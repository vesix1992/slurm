/*****************************************************************************\
 *  setup_nic.c - Library for managing HPE Slingshot networks
 *****************************************************************************
 *  Copyright 2021 Hewlett Packard Enterprise Development LP
 *  Written by Jim Nordby <james.nordby@hpe.com>
 *
 *  This file is part of Slurm, a resource management program.
 *  For details, see <https://slurm.schedmd.com/>.
 *  Please also read the included file: DISCLAIMER.
 *
 *  Slurm is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two. You must obey the GNU
 *  General Public License in all respects for all of the code used other than
 *  OpenSSL. If you modify file(s) with this exception, you may extend this
 *  exception to your version of the file(s), but you are not obligated to do
 *  so. If you do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source files in
 *  the program, then also delete it here.
 *
 *  Slurm is distributed in the hope that it will be useful, but WITHOUT ANY
 *  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with Slurm; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA.
\*****************************************************************************/

#include "config.h"

#include "src/common/slurm_xlator.h"
#include "switch_hpe_slingshot.h"

#include <dlfcn.h>

#include "libcxi/libcxi.h"

// Global variables
bool cxi_avail = false;
struct cxil_dev **cxi_devs;
int cxi_ndevs;
struct cxi_rsrc_limits cxi_limits;

// Function pointers loaded from libcxi
static int (*cxil_get_device_list_p)(struct cxil_device_list **);
static int (*cxil_open_device_p)(uint32_t, struct cxil_dev **);
static int (*cxil_alloc_svc_p)(struct cxil_dev *, struct cxi_svc_desc *);
static int (*cxil_destroy_svc_p)(struct cxil_dev *, unsigned int);

// Static function needed by functions above it
static bool _destroy_profiles(slingshot_jobinfo_t *job);


#define LOOKUP_SYM(_lib, x) \
do { \
	x ## _p = dlsym(_lib, #x); \
	if (x ## _p == NULL) { \
		SSERROR("Error loading symbol %s: %s", #x, dlerror()); \
		return false; \
	} \
} while (0)

static bool _load_cxi_funcs(void *lib)
{
	LOOKUP_SYM(lib, cxil_get_device_list);
	LOOKUP_SYM(lib, cxil_open_device);
	LOOKUP_SYM(lib, cxil_alloc_svc);
	LOOKUP_SYM(lib, cxil_destroy_svc);

	return true;
}

static void _print_devinfo(int idx, struct cxil_devinfo *info)
{
#define PDEVINFO(FMT, ...) debug("devinfo[%d]: " FMT, idx, ##__VA_ARGS__)

	PDEVINFO("device_name='%s' driver_name='%s'",
		info->device_name, info->driver_name);
	PDEVINFO("dev_id=%u nic_addr=%u pid_bits=%u pid_count=%u",
		info->dev_id, info->nic_addr, info->pid_bits, info->pid_count);
	PDEVINFO("pid_granule=%u min_free_shift=%u rdzv_get_idx=%u",
		info->pid_granule, info->min_free_shift, info->rdzv_get_idx);
	PDEVINFO("vendor_id=%u device_id=%u device_rev=%u device_proto=%u"
		 "  device_platform=%u",
		info->vendor_id, info->device_id, info->device_rev,
		info->device_proto, info->device_platform);
	PDEVINFO("num_ptes=%hu num_txqs=%hu num_tgqs=%hu num_eqs=%hu",
		info->num_ptes, info->num_txqs, info->num_tgqs, info->num_eqs);
	PDEVINFO("num_cts=%hu num_acs=%hu num_tles=%hu num_les=%hu",
		info->num_cts, info->num_acs, info->num_tles, info->num_les);
	PDEVINFO("pci_domain=%hu pci_bus=%hu pci_device=%hu pci_function=%hu",
		info->pci_domain, info->pci_bus, info->pci_device,
		info->pci_function);
	PDEVINFO("link_mtu=%zu link_speed=%zu link_state=%hu uc_nic=%d",
		info->link_mtu, info->link_speed, info->link_state,
		info->uc_nic);
	PDEVINFO("pct_eq=%u fru_description='%s' is_vf=%u",
		info->pct_eq, info->fru_description, info->is_vf);
#undef PDEVINFO
}

/*
 * Return array of limits already reserved by system services
 */
static bool _get_reserved_limits(int dev, slingshot_limits_set_t *limits)
{
	int rc;
	struct cxil_svc_list *list = NULL;

	if ((rc = cxil_get_svc_list(cxi_devs[dev], &list))) {
		SSERROR("Could not get service list for CXI device %d:"
			" %d %d", dev, rc, errno);
		return false;
	}
	for (int i = 0; i < list->count; i++) {
		if (!list->descs[i].is_system_svc)
			continue;
#define PLIMIT(DEV, SVC, LIM) { \
	limits->LIM.res += list->descs[SVC].limits.LIM.res; \
	debug("CXI dev[%d]: svc %d: limits.%s.res %hu (tot %d)", \
	 DEV, SVC, #LIM, list->descs[SVC].limits.LIM.res, limits->LIM.res); \
}
		PLIMIT(dev, i, ptes);
		PLIMIT(dev, i, txqs);
		PLIMIT(dev, i, tgqs);
		PLIMIT(dev, i, eqs);
		PLIMIT(dev, i, cts);
		PLIMIT(dev, i, acs);
		PLIMIT(dev, i, tles);
		PLIMIT(dev, i, les);
#undef PLIMIT
	}
	free(list);	// can't use xfree()
	return true;
}

/*
 * Set up basic access to the CXI devices in the daemon
 */
static bool _create_cxi_devs(void)
{
	struct cxil_device_list *list;
	int rc;

	if ((rc = cxil_get_device_list_p(&list))) {
		SSERROR("Could not get a list of the CXI devices: %d %d",
			  rc, errno);
		return false;
	}
	
	// If there are no CXI NICs, just say it's unsupported
	if (!list->count) {
		SSERROR("No CXI devices available");
		return false;
	}

	cxi_devs = xcalloc(list->count, sizeof(struct cxil_dev *));
	cxi_ndevs = list->count;

	// We're OK with only getting access to a subset
	slingshot_limits_set_t reslimits = { 0 };
	for (int d = 0; d < cxi_ndevs; d++) {
		struct cxil_devinfo *info = &list->info[d];
		_print_devinfo(d, info);
		if ((rc = cxil_open_device_p(info->dev_id, &cxi_devs[d]))) {
			SSERROR("Could not open CXI device %d: %d %d",
				d, rc, errno);
			continue;
		}
		_print_devinfo(d, &cxi_devs[d]->info);
		_get_reserved_limits(d, &reslimits);
	}

	return true;
}

/*
 * Open the Slingshot CXI library; set up functions and set cxi_avail
 * if successful (default is 'false')
 */
extern bool slingshot_open_cxi_lib(void)
{
	char *libfile;
	void *lib;

	if (!(libfile = getenv(SLINGSHOT_CXI_LIB_ENV)))
		libfile = SLINGSHOT_CXI_LIB;

	if (!libfile || libfile[0] == '\0') {
		SSERROR("Bad library file specified by %s variable",
			SLINGSHOT_CXI_LIB_ENV);
		goto out;
	}

	if (!(lib = dlopen(libfile, RTLD_LAZY | RTLD_GLOBAL))) {
		SSERROR("Couldn't find CXI library %s: %s", libfile, dlerror());
		goto out;
	}

	if (!_load_cxi_funcs(lib))
		goto out;

	if (!_create_cxi_devs())
		goto out;

	cxi_avail = true;
out:
	return cxi_avail;
}

/*
 * Initialize a cxi_svc_desc with our CXI settings
 */
static void _create_cxi_descriptor(struct cxi_svc_desc *desc,
	const slingshot_jobinfo_t *job, uint32_t uid, uint16_t step_cpus)
{
	memset(desc, 0, sizeof(*desc));

#if CXI_SVC_MEMBER_UID
	desc->restricted_members = true;
	desc->members[0].type = CXI_SVC_MEMBER_UID;
	desc->members[0].svc_member.uid = uid;
#else
	desc->restricted_members = false;
#endif

	// Set up VNI
	if (job->num_vnis > 0) {
		desc->restricted_vnis = true;
		for (int v = 0; v < job->num_vnis; v++)
			desc->vnis[v] = job->vnis[v];
	} else
		desc->restricted_vnis = false;
	

	// Set up traffic classes
	if (job->tcs) {
		desc->restricted_tcs = true;
		if (job->tcs & SLINGSHOT_TC_DEDICATED_ACCESS)
			desc->tcs[CXI_TC_DEDICATED_ACCESS] = true;
		if (job->tcs & SLINGSHOT_TC_LOW_LATENCY)
			desc->tcs[CXI_TC_LOW_LATENCY] = true;
		if (job->tcs & SLINGSHOT_TC_BULK_DATA)
			desc->tcs[CXI_TC_BULK_DATA] = true;
		if (job->tcs & SLINGSHOT_TC_BEST_EFFORT)
			desc->tcs[CXI_TC_BEST_EFFORT] = true;
	} else
		desc->restricted_tcs = false;

	// Set up resource limits
	desc->resource_limits = true;
	if (job->depth)

#define SETLIMIT(LIM) { \
	desc->limits.LIM.max = job->limits.LIM.max; \
	desc->limits.LIM.res = job->limits.LIM.res ? \
		job->limits.LIM.res : job->limits.LIM.def * step_cpus; \
	debug("CXI desc.%s.max/res %hu %hu", #LIM, desc->limits.LIM.max, \
		desc->limits.LIM.res); \
}
	SETLIMIT(txqs);
	SETLIMIT(tgqs);
	SETLIMIT(eqs);
	SETLIMIT(cts);
	SETLIMIT(tles);
	SETLIMIT(ptes);
	SETLIMIT(les);
	SETLIMIT(acs);
#undef SETLIMIT

	// Service persists after the device is closed
	desc->persistent = false;

	// Differentiates system and user services
	desc->is_system_svc = false;
}

/*
 * Create CXI Services for each of the CXI NICs on this host
 */
static bool _create_profiles(
	slingshot_jobinfo_t *job, uint32_t uid, uint16_t step_cpus)
{
	struct cxi_svc_desc desc;

	// Just return true if CXI not available or no VNIs to set up
	if (!cxi_avail || !job->num_vnis) {
		SSDEBUG("cxi_avail=%d num_vnis=%d, ret true",
			cxi_avail, job->num_vnis);
		return true;
	}

	job->num_profiles = cxi_ndevs;
	job->profiles = xcalloc(job->num_profiles, sizeof(*job->profiles));

	// Create a Service for each NIC
	for (int p = 0; p < cxi_ndevs; p++) {
		// Set what we'll need in the CXI Service
		_create_cxi_descriptor(&desc, job, uid, step_cpus);

		struct cxil_dev *dev = cxi_devs[p];
		int svc_id = cxil_alloc_svc_p(dev, &desc);
		if (svc_id < 0) {
			SSERROR("Could not create a CXI Service for"
				" NIC %d (%s) (error %d)",
				p, dev->info.device_name, svc_id);
			goto error;
		}

		pals_comm_profile_t *profile = &job->profiles[p];
		profile->svc_id = svc_id;
		for (int v = 0; v < job->num_vnis; v++)
			profile->vnis[v] = job->vnis[v];
		profile->tcs = job->tcs;
		snprintf(profile->device_name, sizeof(profile->device_name),
			"%s", dev->info.device_name);

		SSDEBUG("[%d]: svc_id=%u vnis=%hu %hu %hu %hu tcs=%u name='%s'",
			p, profile->svc_id, profile->vnis[0],
			profile->vnis[1], profile->vnis[2], profile->vnis[3],
			profile->tcs, profile->device_name);
	}
	return true;

error:
	_destroy_profiles(job);
	return false;
}

/*
 * In the daemon, when the shepherd for an App terminates, free any CXI
 * Services we have allocated for it
 */
static bool _destroy_profiles(slingshot_jobinfo_t *job)
{
	if (!cxi_avail)
		return true;

	for (int p = 0; p < job->num_profiles; p++) {
		int svc_id = job->profiles[p].svc_id;

		// Service ID 0 means not a Service
		if (svc_id <= 0) continue;

		SSDEBUG("Destroying CXI SVC ID %d on NIC %s",
			svc_id, cxi_devs[p]->info.device_name);

		int rc = cxil_destroy_svc_p(cxi_devs[p], svc_id);
		if (rc) {
			SSERROR("Failed to destroy CXI Service ID %d: %d",
				svc_id, errno);
			return false;
		}
	}

	xfree(job->profiles);
	job->profiles = NULL;
	job->num_profiles = 0;
	return true;
}

/*
 * Set up CXI services for each of the CXI NICs on this host
 */
extern bool slingshot_create_services(
	slingshot_jobinfo_t *job, uint32_t uid, uint16_t step_cpus)
{
	xassert(job);
	SSDEBUG("job=%p", job);
	return _create_profiles(job, uid, step_cpus);
}

/*
 * Destroy up CXI services for each of the CXI NICs on this host
 */
extern bool slingshot_destroy_services(slingshot_jobinfo_t *job)
{
	SSDEBUG("job=%p", job);
	xassert(job);
	return _destroy_profiles(job);
}

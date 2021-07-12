/*****************************************************************************\
 *  switch_hpe_slingshot.c - Library for managing HPE Slingshot networks
 *****************************************************************************
 *  Copyright 2021 Hewlett Packard Enterprise Development LP
 *  Written by David Gloe <david.gloe@hpe.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"

#include "src/common/slurm_xlator.h"
#include "switch_hpe_slingshot.h"

/*
 * These variables are required by the generic plugin interface.  If they
 * are not found in the plugin, the plugin loader will ignore it.
 *
 * plugin_name - a string giving a human-readable description of the
 * plugin.  There is no maximum length, but the symbol must refer to
 * a valid string.
 *
 * plugin_type - a string suggesting the type of the plugin or its
 * applicability to a particular form of data or method of data handling.
 * If the low-level plugin API is used, the contents of this string are
 * unimportant and may be anything.  Slurm uses the higher-level plugin
 * interface which requires this string to be of the form
 *
 *      <application>/<method>
 *
 * where <application> is a description of the intended application of
 * the plugin (e.g., "switch" for Slurm switch) and <method> is a description
 * of how this plugin satisfies that application.  Slurm will only load
 * a switch plugin if the plugin_type string has a prefix of "switch/".
 *
 * plugin_version - an unsigned 32-bit integer containing the Slurm version
 * (major.minor.micro combined into a single number).
 */
const char plugin_name[] = "switch HPE Slingshot plugin";
const char plugin_type[] = "switch/hpe_slingshot";
const uint32_t plugin_version = SLURM_VERSION_NUMBER;
const uint32_t plugin_id = SWITCH_PLUGIN_SLINGSHOT;

slingshot_state_t slingshot_state;    // VNI min/max/last/bitmap
slingshot_config_t slingshot_config;  // Configuration defaults


/*
 * init() is called when the plugin is loaded, before any other functions
 * are called.  Put global initialization here.
 */
int init(void)
{
	SSDEBUG("%s loaded", plugin_name);
	return SLURM_SUCCESS;
}

/*
 * Called at slurmctld startup, or when re-reading slurm.conf
 * NOTE: assumed that this runs _after_ switch_p_libstate_restore(),
 * and slingshot_state may or may not already be filled in
 */
extern int switch_p_reconfig(void)
{
	SSDEBUG("entry");

	if (running_in_slurmctld()) {
		if (!slingshot_setup_config(slurm_conf.switch_param))
			return SLURM_ERROR;
	}

	return SLURM_SUCCESS;
}

/*
 * switch functions for global state save/restore
 */
int switch_p_libstate_save(char *dir_name)
{
	SSDEBUG("dir_name=%s", dir_name);

	if (!running_in_slurmctld())
		return SLURM_SUCCESS;

	// Pack state into a buffer
	buf_t *state_buf = init_buf(BUF_SIZE);
	pack32(slingshot_state.version, state_buf);
	pack16(slingshot_state.vni_min, state_buf);
	pack16(slingshot_state.vni_max, state_buf);
	pack16(slingshot_state.vni_last, state_buf);
	pack_bit_str_hex(slingshot_state.vni_table, state_buf);
	pack32(slingshot_state.num_user_vnis, state_buf);
	for (int i = 0; i < slingshot_state.num_user_vnis; i++) {
		pack32(slingshot_state.user_vnis[i].uid, state_buf);
		pack16(slingshot_state.user_vnis[i].vni, state_buf);
	}

	// Get file names for the current and new state files
	char *new_state_file = xstrdup(dir_name);
	xstrcat(new_state_file, "/" SLINGSHOT_STATE_FILE_NEW);
	char *state_file = xstrdup(dir_name);
	xstrcat(state_file, "/" SLINGSHOT_STATE_FILE);

	// Write buffer to new state file
	int state_fd = creat(new_state_file, O_WRONLY);
	if (state_fd == -1) {
		SSERROR("Couldn't create %s for writing: %m", new_state_file);
		goto error;
	}

	size_t buflen = get_buf_offset(state_buf);
	size_t nwrote = write(state_fd, get_buf_data(state_buf), buflen);
	if (nwrote == -1) {
		SSERROR("Couldn't write to %s: %m", new_state_file);
		goto error;
	} else if (nwrote < buflen) {
		SSERROR("Wrote %zu of %zu bytes to %s", nwrote, buflen,
			new_state_file);
		goto error;
	}

	// Overwrite the current state file with rename
	if (rename(new_state_file, state_file) == -1) {
		SSERROR("Couldn't rename %s to %s: %m", new_state_file,
			state_file);
		goto error;
	}

	close(state_fd);
	free_buf(state_buf);
	xfree(new_state_file);
	xfree(state_file);
	return SLURM_SUCCESS;

error:
	close(state_fd);
	free_buf(state_buf);
	unlink(new_state_file);
	xfree(new_state_file);
	xfree(state_file);
	return SLURM_ERROR;
}

/*
 * Set up slingshot_state defaults
 */
static void _state_defaults(void)
{
	memset(&slingshot_state, 0, sizeof(slingshot_state_t));
	slingshot_state.version = SLINGSHOT_STATE_VERSION;
	slingshot_state.vni_min = SLINGSHOT_VNI_MIN_DEF;
	slingshot_state.vni_max = SLINGSHOT_VNI_MAX_DEF;
	slingshot_state.vni_last = slingshot_state.vni_min - 1;
	// Don't set up state->vni_table yet
}

/*
 * Restore slingshot_state from state file
 * NOTE: assumes this runs before loading the slurm.conf config
 */
int switch_p_libstate_restore(char *dir_name, bool recover)
{
	SSDEBUG("dir_name=%s, recover=%d", dir_name, recover);

	// If we're not recovering state, just set up defaults
	if (!recover) {
		_state_defaults();
		return SLURM_SUCCESS;
	}

	// Get state file name
	char *state_file = xstrdup(dir_name);
	xstrcat(state_file, "/" SLINGSHOT_STATE_FILE);

	// Return success if file doesn't exist
	struct stat stat_buf;
	if (stat(state_file, &stat_buf) == -1 && errno == ENOENT) {
		SSDEBUG("State file %s not found", state_file);
		return SLURM_SUCCESS;
	}

	// mmap state file
	buf_t *state_buf = create_mmap_buf(state_file);
	if (state_buf == NULL) {
		SSERROR("Couldn't recover state file %s", state_file);
		goto error;
	}

	// Validate version
	uint32_t version;
	safe_unpack32(&version, state_buf);
	if (version != SLINGSHOT_STATE_VERSION) {
		SSERROR("State file %s version %"PRIu32" != %d", state_file,
			version, SLINGSHOT_STATE_VERSION);
		goto error;
	}

	// Unpack the rest into global state structure
	slingshot_state.version = version;
	safe_unpack16(&slingshot_state.vni_min, state_buf);
	safe_unpack16(&slingshot_state.vni_max, state_buf);
	safe_unpack16(&slingshot_state.vni_last, state_buf);
	unpack_bit_str_hex(&slingshot_state.vni_table, state_buf);
	safe_unpack32(&slingshot_state.num_user_vnis, state_buf);
	slingshot_state.user_vnis = NULL;
	if (slingshot_state.num_user_vnis > 0) {
		slingshot_state.user_vnis = xmalloc(
			slingshot_state.num_user_vnis * sizeof(user_vni_t));
		for (int i = 0; i < slingshot_state.num_user_vnis; i++) {
			safe_unpack32(
				&slingshot_state.user_vnis[i].uid, state_buf);
			safe_unpack16(
				&slingshot_state.user_vnis[i].vni, state_buf);
		}
	}

	free_buf(state_buf);
	xfree(state_file);
	return SLURM_SUCCESS;

error:
unpack_error:
	free_buf(state_buf);
	xfree(state_file);
	if (slingshot_state.vni_table)
		bit_free(slingshot_state.vni_table);
	xfree(slingshot_state.user_vnis);
	
	return SLURM_ERROR;
}

int switch_p_libstate_clear(void)
{
	SSDEBUG("entry");

	if (slingshot_state.vni_table)
		bit_free(slingshot_state.vni_table);
	xfree(slingshot_state.user_vnis);
	return SLURM_SUCCESS;
}

/*
 * switch functions for job step specific credential
 */
int switch_p_alloc_jobinfo(switch_jobinfo_t **switch_job,
			   uint32_t job_id, uint32_t step_id)
{
	slingshot_jobinfo_t *new = NULL;

	SSDEBUG("job_id=%u step_id=%u", job_id, step_id);

	xassert(switch_job);
	new = xcalloc(1, sizeof(slingshot_jobinfo_t));
	new->version = SLINGSHOT_JOBINFO_VERSION;
	*switch_job = (switch_jobinfo_t *)new;
	return SLURM_SUCCESS;
}

int switch_p_build_jobinfo(switch_jobinfo_t *switch_job,
			   slurm_step_layout_t *step_layout,
			   step_record_t *step_ptr)
{
	slingshot_jobinfo_t *job = (slingshot_jobinfo_t *)switch_job;

	if (!step_ptr) {
		fatal("switch_p_build_jobinfo: step_ptr NULL not supported");
	}
	xassert(step_ptr->job_ptr);
	SSDEBUG("job_id=%u step_id=%u uid=%u network='%s'",
		step_ptr->step_id.job_id, step_ptr->step_id.step_id,
		step_ptr->job_ptr->user_id, step_ptr->network);

	if (!job) {
		SSDEBUG("switch_job was NULL");
		return SLURM_SUCCESS;
	}
	xassert(job->version == SLINGSHOT_JOBINFO_VERSION);

	// Do VNI allocation/traffic classes/network limits
	if (slingshot_setup_job(job, step_layout->node_cnt,
				 step_ptr->job_ptr->user_id, step_ptr->network))
		return SLURM_SUCCESS;
	else
		return SLURM_ERROR;
}

int switch_p_duplicate_jobinfo(switch_jobinfo_t *tmp, switch_jobinfo_t **dest)
{
	slingshot_jobinfo_t *old = (slingshot_jobinfo_t *)tmp;
	slingshot_jobinfo_t *new = xmalloc(sizeof(slingshot_jobinfo_t));

	SSDEBUG("old=%p dest=%p new=%p", old, dest, new);

	// Copy static (non-malloced) fields
	memcpy(new, old, sizeof(slingshot_jobinfo_t));

	// Copy malloced fields
	if (old->num_vnis > 0) {
		size_t vnisz = old->num_vnis * sizeof(uint16_t);
		new->vnis = xmalloc(vnisz);
		memcpy(new->vnis, old->vnis, vnisz);
	}

	if (old->num_profiles > 0) {
		size_t profilesz = old->num_profiles *
				   sizeof(pals_comm_profile_t);
		new->profiles = xmalloc(profilesz);
		memcpy(new->profiles, old->profiles, profilesz);
	}

	*dest = (switch_jobinfo_t *)new;
	return SLURM_SUCCESS;
}

void switch_p_free_jobinfo(switch_jobinfo_t *switch_job)
{
	SSDEBUG("switch_job=%p", switch_job);
	slingshot_jobinfo_t *jobinfo = (slingshot_jobinfo_t *)switch_job;
	xassert(jobinfo);
	xfree(jobinfo->vnis);
	xfree(jobinfo->profiles);
	xfree(jobinfo);
	return;
}

void _pack_slingshot_limits(slingshot_limits_t *limits, buf_t *buffer)
{
	pack16(limits->max, buffer);
	pack16(limits->res, buffer);
	pack16(limits->def, buffer);
}

bool _unpack_slingshot_limits(slingshot_limits_t *limits, buf_t *buffer)
{
	safe_unpack16(&limits->max, buffer);
	safe_unpack16(&limits->res, buffer);
	safe_unpack16(&limits->def, buffer);
	return true;

unpack_error:
	return false;
}

void _pack_comm_profile(pals_comm_profile_t *profile, buf_t *buffer)
{
	pack32(profile->svc_id, buffer);
	pack16(profile->vnis[0], buffer);
	pack16(profile->vnis[1], buffer);
	pack16(profile->vnis[2], buffer);
	pack16(profile->vnis[3], buffer);
	pack32(profile->tcs, buffer);
	packstr(profile->device_name, buffer);
}

bool _unpack_comm_profile(pals_comm_profile_t *profile, buf_t *buffer)
{
	safe_unpack32(&profile->svc_id, buffer);
	safe_unpack16(&profile->vnis[0], buffer);
	safe_unpack16(&profile->vnis[1], buffer);
	safe_unpack16(&profile->vnis[2], buffer);
	safe_unpack16(&profile->vnis[3], buffer);
	safe_unpack32(&profile->tcs, buffer);

	char *device_name;
	uint32_t name_len;
	safe_unpackstr_xmalloc(&device_name, &name_len, buffer);
	strncpy(profile->device_name, device_name,
		sizeof(profile->device_name));

	return true;

unpack_error:
	return false;
}

int switch_p_pack_jobinfo(switch_jobinfo_t *switch_job, buf_t *buffer,
			  uint16_t protocol_version)
{
	uint32_t pidx;
	slingshot_jobinfo_t *jobinfo = (slingshot_jobinfo_t *)switch_job;

	SSDEBUG("switch_job=%p buffer=%p protocol_version=%hu",
		switch_job, buffer, protocol_version);

	xassert(jobinfo);
	xassert(buffer);
	pack32(jobinfo->version, buffer);
	pack16_array(jobinfo->vnis, jobinfo->num_vnis, buffer);
	pack32(jobinfo->tcs, buffer);
	_pack_slingshot_limits(&jobinfo->limits.txqs, buffer);
	_pack_slingshot_limits(&jobinfo->limits.tgqs, buffer);
	_pack_slingshot_limits(&jobinfo->limits.eqs, buffer);
	_pack_slingshot_limits(&jobinfo->limits.cts, buffer);
	_pack_slingshot_limits(&jobinfo->limits.tles, buffer);
	_pack_slingshot_limits(&jobinfo->limits.ptes, buffer);
	_pack_slingshot_limits(&jobinfo->limits.les, buffer);
	_pack_slingshot_limits(&jobinfo->limits.acs, buffer);
	pack32(jobinfo->depth, buffer);
	pack32(jobinfo->num_profiles, buffer);
	for (pidx = 0; pidx < jobinfo->num_profiles; pidx++) {
		_pack_comm_profile(&jobinfo->profiles[pidx], buffer);
	}

	return SLURM_SUCCESS;
}

int switch_p_unpack_jobinfo(switch_jobinfo_t **switch_job, buf_t *buffer,
			    uint16_t protocol_version)
{
	uint32_t pidx = 0;
	slingshot_jobinfo_t *jobinfo = xmalloc(sizeof(slingshot_jobinfo_t));

	SSDEBUG("switch_job=%p buffer=%p protocol_version=%hu",
		switch_job, buffer, protocol_version);

	xassert(switch_job);
	xassert(buffer);
	safe_unpack32(&jobinfo->version, buffer);
	if (jobinfo->version != SLINGSHOT_JOBINFO_VERSION) {
		SSERROR("SLINGSHOT jobinfo version %"PRIu32" != %d",
			jobinfo->version, SLINGSHOT_JOBINFO_VERSION);
		goto unpack_error;
	}

	safe_unpack16_array(&jobinfo->vnis, &jobinfo->num_vnis, buffer);
	safe_unpack32(&jobinfo->tcs, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.txqs, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.tgqs, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.eqs, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.cts, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.tles, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.ptes, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.les, buffer);
	_unpack_slingshot_limits(&jobinfo->limits.acs, buffer);

	safe_unpack32(&jobinfo->depth, buffer);
	safe_unpack32(&jobinfo->num_profiles, buffer);
	jobinfo->profiles = xmalloc(jobinfo->num_profiles *
				    sizeof(pals_comm_profile_t));
	for (pidx = 0; pidx < jobinfo->num_profiles; pidx++) {
		_unpack_comm_profile(&jobinfo->profiles[pidx], buffer);
	}

	*switch_job = (switch_jobinfo_t *)jobinfo;
	return SLURM_SUCCESS;

unpack_error:
	xfree(jobinfo);
	return SLURM_ERROR;
}

void switch_p_print_jobinfo(FILE *fp, switch_jobinfo_t *jobinfo)
{
	SSDEBUG("entry");
	return;
}

char *switch_p_sprint_jobinfo(switch_jobinfo_t *switch_jobinfo, char *buf,
		size_t size)
{
	SSDEBUG("entry");

	if ((buf != NULL) && size) {
		buf[0] = '\0';
		return buf;
	}

	return NULL;
}

/*
 * switch functions for job initiation
 */
int switch_p_node_init(void)
{
	SSDEBUG("entry");
	return slingshot_open_cxi_lib();
}

int switch_p_node_fini(void)
{
	SSDEBUG("entry");
	xfree(slingshot_state.user_vnis);
	return SLURM_SUCCESS;
}

/*
 * Set up CXI Services for each of the CXI NICs on this host
 */
int switch_p_job_preinit(stepd_step_rec_t *job)
{
	SSDEBUG("job=%p", job);
	xassert(job);
	slingshot_jobinfo_t *jobinfo = job->switch_job->data;
	xassert(jobinfo);
	int step_cpus = job->node_tasks * job->cpus_per_task;
	return slingshot_create_services(jobinfo, job->uid, step_cpus);
}

/*
 * Privileged, but no jobinfo
 */
extern int switch_p_job_init(stepd_step_rec_t *job)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_job_suspend_test(switch_jobinfo_t *jobinfo)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern void switch_p_job_suspend_info_get(switch_jobinfo_t *jobinfo,
					  void **suspend_info)
{
	SSDEBUG("entry");
	return;
}

extern void switch_p_job_suspend_info_pack(void *suspend_info, buf_t *buffer,
					   uint16_t protocol_version)
{
	SSDEBUG("entry");
	return;
}

extern int switch_p_job_suspend_info_unpack(void **suspend_info, buf_t *buffer,
					    uint16_t protocol_version)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern void switch_p_job_suspend_info_free(void *suspend_info)
{
	SSDEBUG("entry");
	return;
}

extern int switch_p_job_suspend(void *suspend_info, int max_wait)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_job_resume(void *suspend_info, int max_wait)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

/*
 * Non-privileged
 */
int switch_p_job_fini(switch_jobinfo_t *jobinfo)
{
	SSDEBUG("getuid ret %u", getuid());
	return SLURM_SUCCESS;
}

/*
 * Destroy CXI Services for each of the CXI NICs on this host
 */
int switch_p_job_postfini(stepd_step_rec_t *job)
{
	SSDEBUG("job=%p, getuid ret %u", job, getuid());
	xassert(job);

	uid_t pgid = job->jmgr_pid;
	/*
	 *  Kill all processes in the job's session
	 */
	if (pgid) {
		debug2("Sending SIGKILL to pgid %lu", (unsigned long) pgid);
		kill(-pgid, SIGKILL);
	} else
		SSDEBUG("%ps: Bad pid value %lu", &job->step_id,
		      (unsigned long) pgid);

	slingshot_jobinfo_t *jobinfo;
	jobinfo = (slingshot_jobinfo_t *)job->switch_job->data;
	xassert(jobinfo);
	return slingshot_destroy_services(jobinfo);
}

/*
 * Set up environment variables for job step: each environment variable
 * represents data from one or more CXI services, separated by commas.
 * In addition, the SLINGSHOT_VNIS variable has one or more VNIs
 * separated by colons.
 */
int switch_p_job_attach(switch_jobinfo_t *jobinfo, char ***env,
			uint32_t nodeid, uint32_t procid, uint32_t nnodes,
			uint32_t nprocs, uint32_t rank)
{
	slingshot_jobinfo_t *job = (slingshot_jobinfo_t *)jobinfo;
	SSDEBUG("job=%p nodeid=%u procid=%u nnodes=%u, nprocs=%u rank=%u",
		job, nodeid, procid, nnodes, nprocs, rank);

	char *svc_ids = NULL, *vnis = NULL, *devices = NULL, *tcss = NULL;
	for (int i = 0; i < job->num_profiles; i++) {
		char *sep = i ? "," : "";
		pals_comm_profile_t *profile = &job->profiles[i];
		xstrfmtcat(svc_ids, "%s%u", sep, profile->svc_id);
		char *vni = NULL;
		for (int j = 0; j < SLINGSHOT_VNIS; j++) {
			xstrfmtcat(vni, "%s%hu",
				j ? ":" : "", profile->vnis[j]);
		}
		xstrfmtcat(vnis, "%s%s", sep, vni);
		xfree(vni);
		xstrfmtcat(devices, "%s%s", sep, profile->device_name);
		xstrfmtcat(tcss, "%s%u", sep, profile->tcs);
		SSDEBUG("profile %d: svc_ids=%s vnis=%s devices=%s tcss=%s",
			i, svc_ids, vnis, devices, tcss);
	}

	env_array_overwrite(env, "SLINGSHOT_SVC_IDS", svc_ids);
	env_array_overwrite(env, "SLINGSHOT_VNIS", vnis);
	env_array_overwrite(env, "SLINGSHOT_DEVICES", devices);
	env_array_overwrite(env, "SLINGSHOT_TCS", tcss);

	xfree(svc_ids);
	xfree(vnis);
	xfree(devices);
	xfree(tcss);

	return SLURM_SUCCESS;
}

extern int switch_p_get_jobinfo(switch_jobinfo_t *switch_job,
	int key, void *resulting_data)
{
	SSDEBUG("entry");
	slurm_seterrno(EINVAL);
	return SLURM_ERROR;
}

/*
 * node switch state monitoring functions
 * required for IBM Federation switch
 */
extern int switch_p_clear_node_state(void)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_alloc_node_info(switch_node_info_t **switch_node)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_build_node_info(switch_node_info_t *switch_node)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_pack_node_info(switch_node_info_t *switch_node,
				   buf_t *buffer, uint16_t protocol_version)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_unpack_node_info(switch_node_info_t **switch_node,
				     buf_t *buffer, uint16_t protocol_version)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_free_node_info(switch_node_info_t **switch_node)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_job_step_complete(switch_jobinfo_t *jobinfo,
	char *nodelist)
{
	slingshot_jobinfo_t *job = (slingshot_jobinfo_t *)jobinfo;

	SSDEBUG("num_vnis %d", job->num_vnis);

	xassert(job);
	xassert(job->version == SLINGSHOT_JOBINFO_VERSION);

	// Free VNI in job
	slingshot_free_job(job);

	return SLURM_SUCCESS;
}

extern int switch_p_job_step_part_comp(switch_jobinfo_t *jobinfo,
	char *nodelist)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern bool switch_p_part_comp(void)
{
	SSDEBUG("entry");
	return false;
}

extern int switch_p_job_step_allocated(switch_jobinfo_t *jobinfo,
	char *nodelist)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_slurmctld_init(void)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_slurmd_init(void)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_slurmd_step_init(void)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_job_step_pre_suspend(stepd_step_rec_t *job)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_job_step_post_suspend(stepd_step_rec_t *job)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_job_step_pre_resume(stepd_step_rec_t *job)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

extern int switch_p_job_step_post_resume(stepd_step_rec_t *job)
{
	SSDEBUG("entry");
	return SLURM_SUCCESS;
}

/*****************************************************************************\
 *  config.c - Library for managing HPE Slingshot networks
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

// Set this to true if VNI table is re-sized and loses some bits
static bool lost_vnis = false;

/*
 * Set up slingshot_config defaults
 */
static void _config_defaults(void)
{
	memset(&slingshot_config, 0, sizeof(slingshot_config_t));

	slingshot_config.single_node_vni = false;
	slingshot_config.user_vni = false;

	slingshot_config.limits.txqs.max = SLINGSHOT_TXQ_MAX;
	slingshot_config.limits.tgqs.max = SLINGSHOT_TGQ_MAX;
	slingshot_config.limits.eqs.max = SLINGSHOT_EQ_MAX;
	slingshot_config.limits.cts.max = SLINGSHOT_CT_MAX;
	slingshot_config.limits.tles.max = SLINGSHOT_TLE_MAX;
	slingshot_config.limits.ptes.max = SLINGSHOT_PTE_MAX;
	slingshot_config.limits.les.max = SLINGSHOT_LE_MAX;
	slingshot_config.limits.acs.max = SLINGSHOT_AC_MAX;

	slingshot_config.limits.txqs.def = SLINGSHOT_TXQ_DEF;
	slingshot_config.limits.tgqs.def = SLINGSHOT_TGQ_DEF;
	slingshot_config.limits.eqs.def = SLINGSHOT_EQ_DEF;
	slingshot_config.limits.cts.def = SLINGSHOT_CT_DEF;
	slingshot_config.limits.tles.def = SLINGSHOT_TLE_DEF;
	slingshot_config.limits.ptes.def = SLINGSHOT_PTE_DEF;
	slingshot_config.limits.les.def = SLINGSHOT_LE_DEF;
	slingshot_config.limits.acs.def = SLINGSHOT_AC_DEF;
}

/*
 * Parse the VNI min/max token, with format "vni=<min>-<max>";
 * put results in *minp, *maxp
 */
static bool _config_vnis(const char *token, uint16_t *min_ptr,
			 uint16_t *max_ptr)
{
	char *arg, *end_ptr;
	int min, max;

	if (!(arg = strchr(token, '=')))
		goto error;
	arg++;
	end_ptr = NULL;
	min = strtol(arg, &end_ptr, 10);
	if (!end_ptr || end_ptr == arg || *end_ptr != '-')
		goto error;
	if (min < SLINGSHOT_VNI_MIN || min > SLINGSHOT_VNI_MAX)
		goto error;

	arg = end_ptr + 1;
	end_ptr = NULL;
	max = strtol(arg, &end_ptr, 10);
	if (!end_ptr || end_ptr == arg || *end_ptr != '\0')
		goto error;
	if (max <= min || max > SLINGSHOT_VNI_MAX)
		goto error;

	*min_ptr = min;
	*max_ptr = max;
	log_flag(SWITCH, "[token=%s]: min/max %hu %hu", token, min, max);
	return true;

error:
	error("Invalid vni token '%s' (example: 'vnis=10-100', valid range %d-%d)",
	      token, SLINGSHOT_VNI_MIN, SLINGSHOT_VNI_MAX);
	return false;
}

/*
 * Compare old slingshot_state.vni_{min,max} with passed-in min/max;
 * if old table is incompatible with new min/max, return false;
 * otherwise set up slingshot_state with new vni_table values
 */
static bool _setup_vni_table(uint16_t min, uint16_t max)
{
	int32_t oldbits, newbits;
	size_t oldsize = slingshot_state.vni_max - slingshot_state.vni_min + 1;
	size_t newsize = max - min + 1;
	uint16_t oldmin = slingshot_state.vni_min;
	uint16_t oldmax = slingshot_state.vni_max;
	bitstr_t *table = slingshot_state.vni_table;

	log_flag(SWITCH, "oldmin/max/size %hu %hu %zu min/max/size %hu %hu %zu",
		oldmin, oldmax, oldsize, min, max, newsize);

	// If no recovery of vni_table, just set up new one
	if (!slingshot_state.vni_table) {
		table = bit_alloc(newsize);
		goto done;
	}

	xassert(oldmin);
	xassert(oldmax);
	xassert(oldsize > 0);
	xassert(newsize > 0);
	xassert(table);
	xassert(bit_size(table) == oldsize);

	if (oldmin == min && oldmax == max)
		return true;

	// Re-size bitstring if needed
	oldbits = bit_set_count(table);
	if (oldsize != newsize)
		table = bit_realloc(table, newsize);

	// Shift bits if vni_min is changing
	if (oldmin != min)
		bit_rotate(table, min - oldmin);

	newbits = bit_set_count(table);
	// Go on even if we're losing VNIs
	if (newbits != oldbits) {
		error("WARNING: changing vni_min/max %hu %hu -> %hu %hu; %d VNIs will be lost!",
		      oldmin, oldmax, min, max, oldbits - newbits);
		lost_vnis = true;
	}

done:
	slingshot_state.vni_min = min;
	slingshot_state.vni_max = max;
	if (slingshot_state.vni_last < min || slingshot_state.vni_last >= max)
		slingshot_state.vni_last = min - 1;
	slingshot_state.vni_table = table;

	log_flag(SWITCH, "version=%d min/max/last=%hu %hu %hu (%zu)",
		 slingshot_state.version, slingshot_state.vni_min,
		 slingshot_state.vni_max, slingshot_state.vni_last, newsize);
	return true;
}

// Mapping between Slingshot traffic class labels and their bitmasks
static struct {
	const char *label;
	uint32_t bit;
} classes[] = {
	{ "DEDICATED_ACCESS", SLINGSHOT_TC_DEDICATED_ACCESS },
	{ "LOW_LATENCY", SLINGSHOT_TC_LOW_LATENCY },
	{ "BULK_DATA", SLINGSHOT_TC_BULK_DATA },
	{ "BEST_EFFORT", SLINGSHOT_TC_BEST_EFFORT },
};
const int num_classes = sizeof(classes) / sizeof(classes[0]);

/*
 * Parse the Slingshot traffic classes token, with format
 * "tcs=<class1>:<class2>[:...]
 */
static bool _config_tcs(const char *token)
{
	char *arg, *save_ptr = NULL, *tcs, *tc;
	uint32_t tcbits = 0;
	int i;

	if (!(arg = strchr(token, '=')))
		goto err;
	arg++;
	tcs = xstrdup(arg);
	for (tc = strtok_r(tcs, ":", &save_ptr); tc;
		tc = strtok_r(NULL, ":", &save_ptr)) {
		for (i = 0; i < num_classes; i++) {
			if (!strcasecmp(tc, classes[i].label)) {
				tcbits |= classes[i].bit;
				break;
			}
		}
		if (i == num_classes)
			goto err;
	}
	if (tcbits == 0)
		goto err;

	slingshot_config.tcs = tcbits;
	log_flag(SWITCH, "[token=%s]: tcs %#x", token, tcbits);
	xfree(tcs);
	return true;

err:
	xfree(tcs);
	error("Invalid traffic class token '%s' (example 'tcs=DEDICATED_ACCESS:LOW_LATENCY:BULK_DATA:BEST_EFFORT')",
	      token);
	return false;
}

// Mapping between Slingshot limit names, slingshot_limits_set_t offset,
// maximum values
typedef struct limits_table {
	const char *name;
	size_t offset;
	int max;
} limits_table_t;
static limits_table_t limits_table[] = {
	{ "txqs", offsetof(slingshot_limits_set_t, txqs), SLINGSHOT_TXQ_MAX },
	{ "tgqs", offsetof(slingshot_limits_set_t, tgqs), SLINGSHOT_TGQ_MAX },
	{ "eqs",  offsetof(slingshot_limits_set_t, eqs),  SLINGSHOT_EQ_MAX },
	{ "cts",  offsetof(slingshot_limits_set_t, cts),  SLINGSHOT_CT_MAX },
	{ "tles", offsetof(slingshot_limits_set_t, tles), SLINGSHOT_TLE_MAX },
	{ "ptes", offsetof(slingshot_limits_set_t, ptes), SLINGSHOT_PTE_MAX },
	{ "les",  offsetof(slingshot_limits_set_t, les),  SLINGSHOT_LE_MAX },
	{ "acs",  offsetof(slingshot_limits_set_t, acs),  SLINGSHOT_AC_MAX },
};
static const int num_limits = sizeof(limits_table) / sizeof(limits_table[0]);
static const char *all_limits = "txqs,tgqs,eqs,cts,tles,ptes,les,acs";

/*
 * Check whether the token is a Slingshot resource limit token,
 * with format "{def,res,max}_{name}=<limit>"; update slingshot_config
 */
static bool _config_limits(const char *token, slingshot_limits_set_t *limits)
{
	char *tok, *arg, *end_ptr;
	const char *name, *typestr;
	enum { DEF = 1, RES, MAX } type;
	int i, limit;
	const char def_str[] = "def_";
	const size_t def_siz = sizeof(def_str) - 1;
	const char res_str[] = "res_";
	const size_t res_siz = sizeof(res_str) - 1;
	const char max_str[] = "max_";
	const size_t max_siz = sizeof(max_str) - 1;
	limits_table_t *entry;
	slingshot_limits_t *limit_ptr;

	tok = xstrdup(token);
	if (!(arg = strchr(tok, '=')))
		goto err;
	*arg = '\0';	// null-terminate limit name
	arg++;
	// Parse "{def,res,max}_" prefix
	if (!strncmp(tok, def_str, def_siz)) {
		type = DEF;
		typestr = "def";
		name = tok + def_siz;
	} else if (!strncmp(tok, res_str, res_siz)) {
		type = RES;
		typestr = "res";
		name = tok + res_siz;
	} else if (!strncmp(tok, max_str, max_siz)) {
		type = MAX;
		typestr = "max";
		name = tok + max_siz;
	} else {
		goto err;
	}
	// Now find the limit type and point entry at the limit_table slot
	entry = NULL;
	for (i = 0; i < num_limits; i++) {
		if (!strcmp(name, limits_table[i].name)) {
			entry = &limits_table[i];
			break;
		}
	}
	if (!entry)
		goto err;
	end_ptr = NULL;
	limit = strtol(arg, &end_ptr, 10);
	if (!end_ptr || end_ptr == arg || *end_ptr != '\0')
		goto err;
	if (limit < 0 || limit > entry->max) {
		error("Invalid limit token '%s': invalid limit %d"
		      " (valid range 0-%d)", token, limit, entry->max);
		goto out;
	}
	limit_ptr = (slingshot_limits_t *)(((void *) limits) + entry->offset);
	if (type == DEF) {
		limit_ptr->def = limit;
	} else if (type == RES) {
		limit_ptr->res = limit;
	} else if (type == MAX) {
		limit_ptr->max = limit;
	}
	log_flag(SWITCH, "[token=%s]: limits[%d].%s.%s %d",
		token, i, entry->name, typestr, limit);
	xfree(tok);
	return true;
err:
	error("Invalid limit token '%s' (example {max,res,def}_{%s})",
		token, all_limits);
out:
	xfree(tok);
	return false;
}

static void _print_limits(slingshot_limits_set_t *limits)
{
#define DEBUG_LIMIT(SET, LIM) \
	debug("%s: max/res/def %hu %hu %hu", \
		#LIM, SET->LIM.max, SET->LIM.res, SET->LIM.def);
	DEBUG_LIMIT(limits, txqs);
	DEBUG_LIMIT(limits, tgqs);
	DEBUG_LIMIT(limits, eqs);
	DEBUG_LIMIT(limits, cts);
	DEBUG_LIMIT(limits, tles);
	DEBUG_LIMIT(limits, ptes);
	DEBUG_LIMIT(limits, les);
	DEBUG_LIMIT(limits, acs);
#undef DEBUG_LIMIT
}

/*
 * Set up passed-in slingshot_config_t based on values in 'SwitchParameters'
 * slurm.conf setting.  Return true on success, false on bad parameters
 */
extern bool slingshot_setup_config(const char *switch_params)
{
	char *params = NULL, *token, *save_ptr = NULL;

	log_flag(SWITCH, "switch_params=%s", switch_params);
	/*
	 * Handle SwitchParameters values (separated by commas):
	 *
	 *   vnis=<start>-<end> (e.g. vnis=1-16000)
	 *   tcs=<tc_list> (e.g. tcs=BULK_DATA:BEST_EFFORT)
	 *   single_node_vni: allocate VNI for single-node steps
	 *   user_vni: allocate additional VNI per-user
	 *   def_<NIC_resource>: default per-thread value for resource
	 *   res_<NIC_resource>: reserved value for resource
	 *   max_<NIC_resource>: maximum value for resource
	 *
	 * NIC resources are:
	 *   txqs: transmit command queues
	 *   tgqs: target command queues
	 *   eqs:  events queues
	 *   cts:  counters
	 *   tles: trigger list entries
	 *   ptes: portable table entries
	 *   les:  list entries
	 *   acs:  addressing contexts
	 */

	_config_defaults();
	if (switch_params == NULL)
		goto out;

	const char vnis[] = "vnis";
	const size_t size_vnis = sizeof(vnis) - 1;
	const char tcs[] = "tcs";
	const size_t size_tcs = sizeof(tcs) - 1;

	params = xstrdup(switch_params);
	for (token = strtok_r(params, ",", &save_ptr); token;
		token = strtok_r(NULL, ",", &save_ptr)) {
		if (!strncasecmp(token, vnis, size_vnis)) {
			uint16_t min, max;
			if (!_config_vnis(token, &min, &max))
				goto err;
			// See if any incompatible changes in VNI range
			if (!_setup_vni_table(min, max))
				goto err;
		} else if (!strncasecmp(token, tcs, size_tcs)) {
			if (!_config_tcs(token))
				goto err;
		} else if (!strcasecmp(token, "single_node_vni")) {
			slingshot_config.single_node_vni = true;
		} else if (!strcasecmp(token, "user_vni")) {
			slingshot_config.user_vni = true;
		} else {
			if (!_config_limits(token, &slingshot_config.limits))
				goto err;
		}
	}

out:
	debug("single_node_vni=%d user_vni=%d tcs=%#x", \
		slingshot_config.single_node_vni, slingshot_config.user_vni,
		slingshot_config.tcs);
	_print_limits(&slingshot_config.limits);

	xfree(params);
	return true;

err:
	xfree(params);
	return false;
}

/*
 * Allocate a free VNI (range vni_min... vni_max, starting at vni_last + 1)
 * Return (positive integer) VNI on success, 0 on failure
 */
static uint16_t _alloc_vni(void)
{
	bitoff_t start, end, bit;
	uint16_t vni;

	// Search for clear bit from [vni_last + 1...vni_max]
	start = slingshot_state.vni_last - slingshot_state.vni_min + 1;
	end = slingshot_state.vni_max - slingshot_state.vni_min;
	xassert(start >= 0);
	log_flag(SWITCH, "upper bits: start/end %zu %zu", start, end);
	for (bit = start; bit <= end; bit++) {
		if (!bit_test(slingshot_state.vni_table, bit))
			goto gotvni;
	}
	// Search for clear bit from [vni_min...vni_last]
	end = slingshot_state.vni_last - slingshot_state.vni_min;
	log_flag(SWITCH, "lower bits: start/end %zu %zu", start, end);
	for (bit = 0; bit <= end; bit++) {
		if (!bit_test(slingshot_state.vni_table, bit))
			goto gotvni;
	}
	// TODO: developer's mode: check for no bits set?
	error("Cannot allocate VNI (min/max/last %hu %hu %hu)",
		slingshot_state.vni_min, slingshot_state.vni_max,
		slingshot_state.vni_last);
	return 0;

gotvni:
	bit_set(slingshot_state.vni_table, bit);
	xassert(bit + slingshot_state.vni_min <= SLINGSHOT_VNI_MAX);
	vni = bit + slingshot_state.vni_min;
	slingshot_state.vni_last = vni;
	log_flag(SWITCH, "min/max/last %hu %hu %hu vni=%hu",
		slingshot_state.vni_min, slingshot_state.vni_max,
		slingshot_state.vni_last, vni);
	return vni;
}

/*
 * Allocate a per-user VNI - if this is the first allocation for this user,
 * allocate a new VNI and add it to the user_vnis table;
 * otherwise return the VNI from the table for this user
 * Return 0 on error
 */
static uint16_t _alloc_user_vni(uint32_t uid)
{
	int i;
	uint16_t vni;

	// Check if this uid is in the table already
	for (i = 0; i < slingshot_state.num_user_vnis; i++) {
		if (slingshot_state.user_vnis[i].uid == uid) {
			vni = slingshot_state.user_vnis[i].vni;
			log_flag(SWITCH,
				"[uid=%u]: found user_vnis[%d/%d] vni=%hu",
				uid, i, slingshot_state.num_user_vnis, vni);
			return vni;
		}
	}

	// Allocate new slot in user_vnis table
	slingshot_state.num_user_vnis++;
	xrecalloc(slingshot_state.user_vnis, slingshot_state.num_user_vnis,
		  sizeof(user_vni_t));

	if (!(vni = _alloc_vni()))
		return 0;

	i = slingshot_state.num_user_vnis - 1;
	slingshot_state.user_vnis[i].uid = uid;
	slingshot_state.user_vnis[i].vni = vni;
	log_flag(SWITCH, "[uid=%u]: new vni[%d] vni=%hu", uid, i, vni);
	return vni;
}

/*
 * Free an allocated VNI
 */
static void _free_vni(uint16_t vni)
{
	// Range-check VNI, but only if table has been re-sized and VNIs
	// were lost
	if (lost_vnis && (vni < slingshot_state.vni_min ||
				 vni > slingshot_state.vni_max)) {
		info("vni %hu: not in current table min/max %hu-%hu",
			vni, slingshot_state.vni_min, slingshot_state.vni_max);
		return;
	}
	bitoff_t bit = vni - slingshot_state.vni_min;
	xassert(bit_test(slingshot_state.vni_table, bit));
	bit_clear(slingshot_state.vni_table, bit);
	log_flag(SWITCH, "[vni=%hu]: bit %zu", vni, bit);
}

/*
 * Parse --network 'depth=<value>' token: return value, or 0 on error
 */
static uint32_t _setup_depth(const char *token)
{
	uint32_t ret;
	char *arg = strchr(token, '=');
	if (!arg)
		goto err;
	arg++;	// point to argument
	char *end_ptr = NULL;
	ret = strtol(arg, &end_ptr, 10);
	if (*end_ptr || ret < 1 || ret > 1024)
		goto err;
	log_flag(SWITCH, "[token=%s]: depth %u", token, ret);
	return ret;
err:
	error("Invalid depth token '%s' (valid range %d-%d)",
		token, 1, 1024);
	return 0;
}

/*
 * Set up passed-in slingshot_job_t based on values in srun --network
 * parameters.  Return true on successful parsing, false otherwise.
 */
static bool _setup_network_params(
	const char *network_params, slingshot_jobinfo_t *job)
{
	char *params = NULL, *token, *save_ptr = NULL;

	log_flag(SWITCH, "network_params=%s", network_params);

	// First, copy limits from slingshot_config to job
	job->limits = slingshot_config.limits;

	/*
	 * Handle srun --network argument values (separated by commas):
	 *
	 *   depth: value to be used for threads-per-rank
	 *   def_<NIC_resource>: default per-thread value for resource
	 *   res_<NIC_resource>: reserved value for resource
	 *   max_<NIC_resource>: maximum value for resource
	 */
	if (!network_params)
		return true;

	params = xstrdup(network_params);
	char depth_str[] = "depth";
	size_t depth_siz = sizeof(depth_str) - 1;
	for (token = strtok_r(params, ",", &save_ptr); token;
		token = strtok_r(NULL, ",", &save_ptr)) {
		if (!strncmp(token, depth_str, depth_siz)) {
			if ((job->depth = _setup_depth(token)) == 0)
				goto err;
		} else if (!_config_limits(token, &job->limits))
			goto err;
	}

	if (slurm_conf.debug_flags & DEBUG_FLAG_SWITCH)
		_print_limits(&job->limits);
	xfree(params);
	return true;
err:
	xfree(params);
	return false;
}

/*
 * Set up slingshot_jobinfo_t struct with VNIs, and CXI limits,
 * based on configured limits as well as any specified with
 * the --network option
 * Return true on success, false if VNI cannot be allocated,
 * or --network parameters have syntax errors
 */
extern bool slingshot_setup_job(slingshot_jobinfo_t *job,
	int node_cnt, uint32_t uid, const char *network_params)
{
	// VNIs and traffic classes are not allocated for single-node jobs,
	// unless 'single_node_vni' is set in the configuration
	job->num_vnis = 0;
	if (node_cnt > 1 || slingshot_config.single_node_vni) {
		job->num_vnis++;
		job->tcs = slingshot_config.tcs;
	}
	// Add user VNI if configured
	if (slingshot_config.user_vni)
		job->num_vnis++;

	job->vnis = xcalloc(job->num_vnis, sizeof(uint16_t));
	if (job->num_vnis >= 1) {
		if (!(job->vnis[0] = _alloc_vni()))
			goto err;
	}

	// Allocate per-user VNI if configured
	if (job->num_vnis == 2) {
		if (!(job->vnis[1] = _alloc_user_vni(uid)))
			goto err;
	}

	job->limits = slingshot_config.limits;

	// If --network specified, add any depth/limits settings
	// Copy configured Slingshot limits to job, add any --network settings
	if (!_setup_network_params(network_params, job))
		goto err;

	// profiles are allocated in slurmd
	job->num_profiles = 0;
	job->profiles = NULL;

	return true;

err:
	if (job->vnis) {
		for (int i = 0; i < job->num_vnis; i++) {
			if (job->vnis[i])
				_free_vni(job->vnis[i]);
		}
		xfree(job->vnis);
	}

	return false;
}

extern void slingshot_free_job(slingshot_jobinfo_t *job)
{
	// Only free first VNI (second is a user_vni)
	if (job->num_vnis > 0 && job->vnis)
		_free_vni(job->vnis[0]);
}

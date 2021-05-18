/*****************************************************************************\
 *  node_features_helpers.c - Plugin for supporting arbitrary node features
 *  using external helper binaries
 *****************************************************************************
 *  Copyright (C) 2021 NVIDIA CORPORATION. All rights reserved.
 *  Written by NVIDIA CORPORATION.
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

#define _GNU_SOURCE
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>

#include "slurm/slurm_errno.h"
#include "src/common/list.h"
#include "src/common/node_conf.h"
#include "src/common/read_config.h"
#include "src/common/uid.h"
#include "src/common/xmalloc.h"
#include "src/common/xstring.h"

const char plugin_name[] = "node_features helpers plugin";
const char plugin_type[] = "node_features/helpers";
const uint32_t plugin_version = SLURM_VERSION_NUMBER;

static uid_t *allowed_uid = NULL;
static int allowed_uid_cnt = 0;

typedef struct {
	const char *name;
	const char *helper;
} plugin_feature_t;

typedef struct plugin_context {
	List features;
	List exclusives;
	uint32_t boot_time;
	uint32_t node_reboot_weight;
} plugin_context_t;

static plugin_context_t context = {
	.features = NULL,
	.exclusives = NULL,
	.boot_time = (5 * 60),
	.node_reboot_weight = (INFINITE - 1),
};

static int _cmp_str(void *x, void *key)
{
	return strcmp(x, key) == 0;
}

static int cmp_features(void *x, void *key)
{
	plugin_feature_t *feature = x;
	return strcmp(feature->name, key) == 0;
}

static bool is_feature_valid(const char *k)
{
	if (k == NULL || k[0] == '\0')
		return false;

	if (!isalpha(k[0]) && k[0] != '_' && k[0] != '=')
		return false;
	for (int i = 1; k[i] != '\0'; ++i) {
		if (!isalnum(k[i]) && k[i] != '_' && k[i] != '.' && k[i] != '=')
			return false;
	}

	return true;
}

static void _make_uid_array(char *uid_str)
{
	char *save_ptr = NULL, *tmp_str, *tok;
	int i, uid_cnt = 0;

	if (!uid_str)
		return;

	/* Count the number of users */
	for (i = 0; uid_str[i]; i++) {
		if (uid_str[i] == ',')
			uid_cnt++;
	}
	uid_cnt++;

	allowed_uid = xcalloc(uid_cnt, sizeof(uid_t));
	allowed_uid_cnt = 0;
	tmp_str = xstrdup(uid_str);
	tok = strtok_r(tmp_str, ",", &save_ptr);
	while (tok) {
		if (uid_from_string(tok, &allowed_uid[allowed_uid_cnt++]) < 0)
			error("node_features.conf: Invalid AllowUserBoot: %s", tok);
		tok = strtok_r(NULL, ",", &save_ptr);
	}
	xfree(tmp_str);
}

static plugin_feature_t *feature_create(const char *name, const char *helper)
{
	plugin_feature_t *feature = NULL;

	feature = xmalloc(sizeof(*feature));
	feature->name = xstrdup(name);
	feature->helper = xstrdup(helper);

	return feature;
}

static void feature_destroy(plugin_feature_t *feature)
{
	if (feature == NULL)
		return;

	xfree(feature->name);
	xfree(feature->helper);
	xfree(feature);
}

static void feature_destroy_void(void *feature)
{
	feature_destroy((plugin_feature_t *)feature);
}

static void exclusives_destroy(void *exclusives)
{
	list_destroy((List)exclusives);
}

/* FIXME: replace this with run_command() from src/common/run_command.c */
static int run_command(const char *command, char **output)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int status = 0, rc = SLURM_ERROR;

	info("executing \"%s\"", command);

	if (output != NULL)
		*output = NULL;

	if ((fp = popen(command, "re")) == NULL)
		goto fail;

	if (output != NULL) {
		while (getline(&line, &len, fp) > 0)
			xstrncat(*output, line, len);
	}

	if ((status = pclose(fp)) != 0) {
		error("command \"%s\" returned with exit status: %d",
		      command, status);
		goto fail;
	}

	rc = SLURM_SUCCESS;

fail:
	free(line);
	if (rc != SLURM_SUCCESS && output != NULL)
		xfree(*output);

	return rc;
}

static int feature_set_state(const plugin_feature_t *feature)
{
	char *command = NULL;
	int rc = SLURM_ERROR;

	if (feature->helper == NULL)
		goto fail;

	xstrfmtcat(command, "%s %s", feature->helper, feature->name);
	if (run_command(command, NULL) != SLURM_SUCCESS) {
		error("failed to set new value for feature: %s", feature->name);
		goto fail;
	}

	rc = SLURM_SUCCESS;

fail:
	xfree(command);
	return rc;
}

static List feature_get_state(const plugin_feature_t *feature)
{
	char *tmp, *kv;
	char *output = NULL;
	List result = list_create(xfree_ptr);

	if (run_command(feature->helper, &output) != SLURM_SUCCESS)
		return result;

	tmp = output;
	while ((kv = strsep(&tmp, "\n"))) {
		if (kv[0] == '\0')
			break;

		list_append(result, xstrdup(kv));
	}

	xfree(output);

	return result;
}

static int feature_register(const char *name, const char *helper)
{
	const plugin_feature_t *existing;
	plugin_feature_t *feature = NULL;

	existing = list_find_first(context.features, cmp_features, (char*)name);
	if (existing != NULL) {
		error("feature \"%s\" previously registered with helper \"%s\"",
		      name, existing->helper);
		return SLURM_ERROR;
	}

	feature = feature_create(name, helper);

	info("adding new feature \"%s\"", feature->name);
	list_append(context.features, feature);
	feature = NULL;

	feature_destroy(feature);
	return SLURM_SUCCESS;
}

static int exclusive_register(const char *listp)
{
	List data_list = list_create(xfree_ptr);
	char *input = xstrdup(listp);
	char *tmp = input;
	char *entry;

	while ((entry = strsep(&tmp, ","))) {
		if (list_find_first(data_list, _cmp_str, entry)) {
			error("feature \"%s\" already in exclusive list", entry);
			continue;
		}

		list_append(data_list, xstrdup(entry));
	}

	xfree(input);

	list_append(context.exclusives, data_list);

	return SLURM_SUCCESS;
}

static int parse_feature(void **data, slurm_parser_enum_t type,
			 const char *key, const char *name,
			 const char *line, char **leftover)
{
	static s_p_options_t feature_options[] = {
		 {"Helper", S_P_STRING},
		 {NULL},
	};
	s_p_hashtbl_t *tbl = NULL;
	char *path = NULL;
	int rc = -1;

	if (!is_feature_valid(name)) {
		slurm_seterrno(ESLURM_INVALID_FEATURE);
		goto fail;
	}

	tbl = s_p_hashtbl_create(feature_options);
	if (s_p_parse_line(tbl, *leftover, leftover) == 0)
		goto fail;

	s_p_get_string(&path, "Helper", tbl);

	/* In slurmctld context, we can have path == NULL */
	*data = feature_create(name, path);
	xfree(path);

	rc = 1;
fail:
	s_p_hashtbl_destroy(tbl);
	return rc;
}

static int parse_exclusives(void **data, slurm_parser_enum_t type,
			 const char *key, const char *name,
			 const char *line, char **leftover)
{
	*data = xstrdup(name);

	return 1;
}

static s_p_options_t conf_options[] = {
	{"Feature", S_P_ARRAY, parse_feature, feature_destroy_void},
	{"BootTime", S_P_UINT32},
	{"MutuallyExclusive", S_P_ARRAY, parse_exclusives, xfree_ptr},
	{"NodeRebootWeight", S_P_UINT32},
	{"AllowUserBoot", S_P_STRING},
	{NULL},
};

static int read_config_file(void)
{
	s_p_hashtbl_t *tbl = NULL;
	char *confpath = NULL;
	char *tmp_str = NULL;
	void **features = NULL;
	void **exclusives = NULL;
	int count = 0;
	int rc = SLURM_ERROR;

	xfree(allowed_uid);
	allowed_uid_cnt = 0;

	if (context.features != NULL) {
		list_destroy(context.features);
		context.features = NULL;
	}
	context.features = list_create(feature_destroy_void);

	if (context.exclusives != NULL) {
		list_destroy(context.exclusives);
		context.exclusives = NULL;
	}
	context.exclusives = list_create(exclusives_destroy);

	tbl = s_p_hashtbl_create(conf_options);

	confpath = get_extra_conf_path("node_features.conf");
	if (s_p_parse_file(tbl, NULL, confpath, false) == SLURM_ERROR) {
		error("could not parse configuration file: %s", confpath);
		goto fail;
	}
	xfree(confpath);

	if (s_p_get_array(&features, &count, "Feature", tbl) == 0) {
		error("no \"Feature\" entry in configuration file %s",
		      confpath);
		goto fail;
	}

	if (s_p_get_string(&tmp_str, "AllowUserBoot", tbl)) {
		_make_uid_array(tmp_str);
		xfree(tmp_str);
	}

	for (int i = 0; i < count; ++i) {
		const plugin_feature_t *feature = features[i];
		if (feature_register(feature->name, feature->helper) != SLURM_SUCCESS)
			continue;
	}

	if (s_p_get_array(&exclusives, &count, "MutuallyExclusive", tbl) != 0) {
		for (int i = 0; i < count; ++i) {
			if (exclusive_register(exclusives[i]) != SLURM_SUCCESS)
				continue;
		}
	}

	if (s_p_get_uint32(&context.boot_time, "BootTime", tbl) == 0)
		info("BootTime not specified, using default value: %u",
		     context.boot_time);

	if (s_p_get_uint32(&context.node_reboot_weight,
				"NodeRebootWeight", tbl) == 0)
		info("NodeRebootWeight not specified, using default value: %u",
		     context.node_reboot_weight);

	rc = SLURM_SUCCESS;

fail:
	s_p_hashtbl_destroy(tbl);

	return rc;
}

int init(void)
{
	return read_config_file();
}

int fini(void)
{
	if (context.features != NULL) {
		list_destroy(context.features);
		context.features = NULL;
	}

	if (context.exclusives != NULL) {
		list_destroy(context.exclusives);
		context.exclusives = NULL;
	}

	xfree(allowed_uid);
	allowed_uid_cnt = 0;

	return SLURM_SUCCESS;
}

bool node_features_p_changeable_feature(char *input)
{
	plugin_feature_t *feature = NULL;

	feature = list_find_first(context.features, cmp_features, input);
	if (feature == NULL)
		return false;

	return true;
}

static int _count_exclusivity(char *job_features, List exclusive_list)
{
	unsigned int count = 0;
	ListIterator it;
	char *feature = NULL;

	it = list_iterator_create(exclusive_list);
	while ((feature = list_next(it))) {
	char *ptr = strstr(job_features, feature);
	unsigned int len = strlen(feature);

	/* check for every matching pattern */
	while (ptr) {
		/* check word+1 to verify exact match */
		if (isalnum(ptr[len]) || ptr[len] == '-' || ptr[len] == '.' ||
			ptr[len] == '_' || ptr[len] == '=') {
			ptr = strstr(&ptr[len], feature);
			continue;
		}

		/* check word-1 to verify exact match */
		if ((ptr != job_features) && isalnum(ptr[-1])) {
			ptr = strstr(&ptr[len], feature);
			continue;
		}

		count++;
		ptr = strstr(&ptr[len], feature);
		}
	}

	return count;
}

int node_features_p_job_valid(char *job_features)
{
	ListIterator fit = NULL;
	plugin_feature_t *feature = NULL;
	List exclusive_list;
	char *name = NULL;
	int rc = SLURM_ERROR;

	if (job_features == NULL)
		return SLURM_SUCCESS;

	/* Check the mutually exclusive lists */
	fit = list_iterator_create(context.exclusives);
	while ((exclusive_list = list_next(fit))) {
		if (_count_exclusivity(job_features, exclusive_list) > 1) {
			error("job requests mutually exclusive features");
			rc = ESLURM_INVALID_FEATURE;
			goto end;
		}
	}

	/* Check for unsupported constraint operators in constraint expression */
	if (strpbrk(job_features, "[]()|*") == NULL)
		return SLURM_SUCCESS;

	/* If an unsupported operator was used, the constraint is valid only if
	 * the expression doesn't contain a feature handled by this plugin. */
	fit = list_iterator_create(context.features);
	while ((feature = list_next(fit))) {
		if (strstr(job_features, feature->name) != NULL) {
			error("operator(s) \"[]()|*\" not allowed in constraint \"%s\" when using changeable feature \"%s\"",
			      job_features, feature->name);
			rc = ESLURM_INVALID_FEATURE;
			goto end;
		}
	}

	rc = SLURM_SUCCESS;

end:
	if (fit != NULL)
		list_iterator_destroy(fit);
	xfree(name);

	return rc;
}

int node_features_p_node_set(char *active_features)
{
	char *kv, *tmp;
	char *input = NULL;
	const plugin_feature_t *feature = NULL;
	int rc = SLURM_ERROR;

	input = xstrdup(active_features);
	tmp = input;
	while ((kv = strsep(&tmp, "&"))) {

		feature = list_find_first(context.features, cmp_features, kv);
		if (feature == NULL) {
			info("skipping unregistered feature \"%s\"", kv);
			continue;
		}

		if (feature_set_state(feature) != SLURM_SUCCESS)
			goto fail;
	}

	rc = SLURM_SUCCESS;

fail:
	xfree(input);
	active_features[0] = '\0';
	return rc;
}

void node_features_p_node_state(char **avail_modes, char **current_mode)
{
	ListIterator fit = NULL;
	plugin_feature_t *feature = NULL;
	List all_current = NULL;
	char *value;

	if (!avail_modes || !current_mode)
		return;

	verbose("original: avail=%s current=%s",
		*avail_modes, *current_mode);

	if (*avail_modes == NULL)
		*avail_modes = xstrdup("");
	if (*current_mode == NULL)
		*current_mode = xstrdup("");

	all_current = list_create(xfree_ptr);

	/* Call every helper with no args to get list of active features
	 * Account for possible duplicates in output */
	fit = list_iterator_create(context.features);
	while ((feature = list_next(fit))) {
		ListIterator curfit = NULL;
		List current = feature_get_state(feature);

		xstrfmtcat(*avail_modes, "%s%s",
			(*avail_modes[0] ? "," : ""), feature->name);

		if (current == NULL || list_is_empty(current))
			continue;

		curfit = list_iterator_create(current);
		while ((value = list_next(curfit))) {
			/* Verify registered mode, parse out garbage */
			if (!list_find_first(context.features, cmp_features, value))
				continue;

			/* check that this mode is not already in list of current modes */
			if (!list_find_first(all_current, _cmp_str, value))
				list_append(all_current, xstrdup(value));
		}

		list_destroy(current);
	}
	list_iterator_destroy(fit);

	fit = list_iterator_create(all_current);
	while ((value = list_next(fit))) {
		xstrfmtcat(*current_mode, "%s%s", (*current_mode[0] ? "," : ""), value);
	}
	list_destroy(all_current);

	verbose("new: avail=%s current=%s", *avail_modes, *current_mode);
}

char *node_features_p_node_xlate(char *new_features, char *orig_features,
				 char *avail_features, int node_inx)
{
	List features = NULL;
	const char *feature = NULL;
	char *input = NULL;
	char *tmp = NULL;
	ListIterator it;
	char *merged = NULL;

	verbose("new_features: %s", new_features);
	verbose("orig_features: %s", orig_features);
	verbose("avail_features: %s", avail_features);

	if (new_features == NULL || new_features[0] == '\0')
		return xstrdup(orig_features);

	if (orig_features == NULL || orig_features[0] == '\0')
		return xstrdup(new_features);

	/* Compute: merged = new_features U (orig_features - changeable_features) */
	features = list_create(xfree_ptr);

	/* Add all features in "new_features" */
	input = xstrdup(new_features);
	tmp = input;
	while ((feature = strsep(&tmp, ",")))
		list_append(features, xstrdup(feature));
	xfree(input);

	input = xstrdup(orig_features);
	tmp = input;
	while ((feature = strsep(&tmp, ","))) {
		/* orig_features - plugin_changeable_features */
		if (node_features_p_changeable_feature((char *)feature))
			continue;
		/* new_features U (orig_features - plugin_changeable_features) */
		if (list_find_first(features, _cmp_str, (char *)feature) != NULL)
			continue;
		list_append(features, xstrdup(feature));
	}
	xfree(input);

	merged = xstrdup("");
	it = list_iterator_create(features);
	while ((feature = list_next(it))) {
		xstrfmtcat(merged, "%s%s", (merged[0] ? "," : ""), feature);
	}

	if (features != NULL)
		list_destroy(features);
	verbose("merged features: %s", merged);

	return merged;
}

char *node_features_p_job_xlate(char *job_features)
{
	if (strpbrk(job_features, "[]()|*") != NULL) {
		info("an unsupported constraint operator was used in \"%s\", clearing job constraint",
		     job_features);
		return xstrdup("");
	}

	return xstrdup(job_features);
}

/* Return true if the plugin requires PowerSave mode for booting nodes */
bool node_features_p_node_power(void)
{
	return false;
}

static char *_make_helper_str(const plugin_feature_t *feature)
{
	char *str = NULL;
	/* Format: "Name Helper=<path>" */

	str = xstrdup("");
	xstrfmtcat(str, "%s Helper=%s", feature->name, feature->helper);

	return str;
}

static char *_make_exclusive_str(List exclusive)
{
	ListIterator it = NULL;
	char *item = NULL, *str = NULL;

	str = xstrdup("");
	it = list_iterator_create(exclusive);
	while ((item = list_next(it))) {
		xstrfmtcat(str, "%s%s", (str[0] ? "," : ""), item);
	}

	return str;
}

static char *_make_uid_str(uid_t *uid_array, int uid_cnt)
{
	char *sep = "", *tmp_str = NULL, *uid_str = NULL;
	int i;

	if (allowed_uid_cnt == 0) {
		uid_str = xstrdup("ALL");
		return uid_str;
	}

	for (i = 0; i < uid_cnt; i++) {
		tmp_str = uid_to_string(uid_array[i]);
		xstrfmtcat(uid_str, "%s%s(%d)", sep, tmp_str, uid_array[i]);
		xfree(tmp_str);
		sep = ",";
	}

	return uid_str;
}

/* Get node features plugin configuration */
void node_features_p_get_config(config_plugin_params_t *p)
{
	ListIterator fit = NULL;
	plugin_feature_t *feature;
	config_key_pair_t *key_pair;
	List data;
	List exclusive;

	xassert(p);
	xstrcat(p->name, plugin_type);
	data = p->key_pairs;

	fit = list_iterator_create(context.features);
	while ((feature = list_next(fit))) {
		key_pair = xmalloc(sizeof(config_key_pair_t));
		key_pair->name = xstrdup("Feature");
		key_pair->value = _make_helper_str(feature);
		list_append(data, key_pair);
	}

	fit = list_iterator_create(context.exclusives);
	while ((exclusive = list_next(fit))) {
		key_pair = xmalloc(sizeof(config_key_pair_t));
		key_pair->name = xstrdup("MutuallyExclusive");
		key_pair->value = _make_exclusive_str(exclusive);
		list_append(data, key_pair);
	}

	key_pair = xmalloc(sizeof(config_key_pair_t));
	key_pair->name = xstrdup("AllowUserBoot");
	key_pair->value = _make_uid_str(allowed_uid, allowed_uid_cnt);
	list_append(data, key_pair);

	key_pair = xmalloc(sizeof(config_key_pair_t));
	key_pair->name = xstrdup("NodeRebootWeight");
	key_pair->value = xstrdup_printf("%u", context.node_reboot_weight);
	list_append(data, key_pair);

	key_pair = xmalloc(sizeof(config_key_pair_t));
	key_pair->name = xstrdup("BootTime");
	key_pair->value = xstrdup_printf("%u", context.boot_time);
	list_append(data, key_pair);

	return;
}

bitstr_t *node_features_p_get_node_bitmap(void)
{
	bitstr_t *bitmap;
	bitmap = bit_alloc(node_record_count);
	bit_set_all(bitmap);
	return bitmap;
}

char *node_features_p_node_xlate2(char *new_features)
{
	return xstrdup(new_features);
}

uint32_t node_features_p_boot_time(void)
{
	return context.boot_time;
}

uint32_t node_features_p_reboot_weight(void)
{
	return context.node_reboot_weight;
}

int node_features_p_reconfig(void)
{
	return read_config_file();
}

bool node_features_p_user_update(uid_t uid)
{
	if (allowed_uid_cnt == 0)   /* Default is ALL users allowed to update */
		return true;

	for (int i = 0; i < allowed_uid_cnt; i++) {
		if (allowed_uid[i] == uid)
			return true;
	}

	return false;
}

void node_features_p_step_config(bool mem_sort, bitstr_t *numa_bitmap)
{
	return;
}

int node_features_p_overlap(bitstr_t *active_bitmap)
{
	/* Executed on slurmctld and not used by this plugin */
	return bit_set_count(active_bitmap);
}

int node_features_p_get_node(char *node_list)
{
	/* Executed on slurmctld and not used by this plugin */
	return SLURM_SUCCESS;
}

int node_features_p_node_update(char *active_features,
				bitstr_t *node_bitmap)
{
	/* Executed on slurmctld and not used by this plugin */
	return SLURM_SUCCESS;
}

bool node_features_p_node_update_valid(void *node_ptr,
				       update_node_msg_t *update_node_msg)
{
	/* Executed on slurmctld and not used by this plugin */
	return true;
}

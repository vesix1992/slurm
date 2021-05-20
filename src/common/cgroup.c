/*****************************************************************************\
 *  cgroup.c - driver for cgroup plugin
 *****************************************************************************
 *  Copyright (C) 2021 SchedMD LLC
 *  Written by Felip Moll <felip.moll@schedmd.com>
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

#include "src/common/cgroup.h"

/*Symbols provided by the plugin */
typedef struct slurm_ops {
	int     (*initialize)		(cgroup_ctl_type_t sub);
	int     (*system_create)        (cgroup_ctl_type_t sub);
	int     (*system_addto)		(cgroup_ctl_type_t sub, pid_t *pids,
					 int npids);
	int     (*system_destroy)      (cgroup_ctl_type_t sub);
	int     (*step_create)		(cgroup_ctl_type_t sub,
					 stepd_step_rec_t *job);
	int     (*step_addto)		(cgroup_ctl_type_t sub, pid_t *pids,
					 int npids);
	int     (*step_get_pids)	(pid_t **pids, int *npids);
	int     (*step_suspend)		(void);
	int     (*step_resume)		(void);
	int     (*step_destroy)		(cgroup_ctl_type_t sub);
	bool    (*has_pid)              (pid_t pid);
	void    (*free_conf)		(slurm_cgroup_conf_t *cg_conf);
	slurm_cgroup_conf_t *(*get_conf) (void);
	cgroup_limits_t *(*root_constrain_get) (cgroup_ctl_type_t sub);
	int     (*root_constrain_set)   (cgroup_ctl_type_t sub,
					 cgroup_limits_t *limits);
	cgroup_limits_t *(*system_constrain_get) (cgroup_ctl_type_t sub);
	int     (*system_constrain_set) (cgroup_ctl_type_t sub,
					 cgroup_limits_t *limits);
	int     (*user_constrain_set)   (cgroup_ctl_type_t sub,
					 stepd_step_rec_t *job,
					 cgroup_limits_t *limits);
	int     (*job_constrain_set)    (cgroup_ctl_type_t sub,
					 stepd_step_rec_t *job,
					 cgroup_limits_t *limits);
	int     (*step_constrain_set)   (cgroup_ctl_type_t sub,
					 stepd_step_rec_t *job,
					 cgroup_limits_t *limits);
	int     (*step_start_oom_mgr)   (void);
	cgroup_oom_t *(*step_stop_oom_mgr) (stepd_step_rec_t *job);
	int     (*accounting_init)	();
	int     (*accounting_fini)	();
	int     (*task_addto_accounting) (pid_t pid,
					  stepd_step_rec_t *job,
					  uint32_t task_id);
	cgroup_acct_t *(*task_get_acct_data) (uint32_t taskid);
} slurm_ops_t;

/*
 * These strings must be kept in the same order as the fields
 * declared for slurm_ops_t.
 */
static const char *syms[] = {
	"cgroup_p_initialize",
	"cgroup_p_system_create",
	"cgroup_p_system_addto",
	"cgroup_p_system_destroy",
	"cgroup_p_step_create",
	"cgroup_p_step_addto",
	"cgroup_p_step_get_pids",
	"cgroup_p_step_suspend",
	"cgroup_p_step_resume",
	"cgroup_p_step_destroy",
	"cgroup_p_has_pid",
	"cgroup_p_free_conf",
	"cgroup_p_get_conf",
	"cgroup_p_root_constrain_get",
	"cgroup_p_root_constrain_set",
	"cgroup_p_system_constrain_get",
	"cgroup_p_system_constrain_set",
	"cgroup_p_user_constrain_set",
	"cgroup_p_job_constrain_set",
	"cgroup_p_step_constrain_set",
	"cgroup_p_step_start_oom_mgr",
	"cgroup_p_step_stop_oom_mgr",
	"cgroup_p_accounting_init",
	"cgroup_p_accounting_fini",
	"cgroup_p_task_addto_accounting",
	"cgroup_p_task_get_acct_data"
};

/* Local variables */
static slurm_ops_t ops;
static plugin_context_t *g_context = NULL;
static pthread_mutex_t g_context_lock =	PTHREAD_MUTEX_INITIALIZER;
static bool init_run = false;

/*
 * Initialize Cgroup plugins.
 *
 * Returns a Slurm errno.
 */
extern int cgroup_g_init(void)
{
	int rc = SLURM_SUCCESS;
	char *plugin_type = "cgroup";
	char *type = "cgroup";

	if (init_run && g_context)
		return rc;

	slurm_mutex_lock(&g_context_lock);

	if (g_context)
		goto done;

	g_context = plugin_context_create(
		plugin_type, type, (void **)&ops, syms, sizeof(syms));

	if (!g_context) {
		error("cannot create %s context for %s", plugin_type, type);
		rc = SLURM_ERROR;
		goto done;
	}
	init_run = true;

done:
	xfree(type);
	slurm_mutex_unlock(&g_context_lock);

	return rc;
}

extern int cgroup_g_fini(void)
{
	int rc;

	if (!g_context)
		return SLURM_SUCCESS;

	slurm_mutex_lock(&g_context_lock);
	init_run = false;
	rc = plugin_context_destroy(g_context);
	g_context = NULL;
	slurm_mutex_unlock(&g_context_lock);

	return rc;
}

extern int cgroup_g_initialize(cgroup_ctl_type_t sub)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.initialize))(sub);
}

extern int cgroup_g_system_create(cgroup_ctl_type_t sub)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.system_create))(sub);
}

extern int cgroup_g_system_addto(cgroup_ctl_type_t sub, pid_t *pids, int npids)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.system_addto))(sub, pids, npids);
}

extern int cgroup_g_system_destroy(cgroup_ctl_type_t sub)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.system_destroy))(sub);
}

extern int cgroup_g_step_create(cgroup_ctl_type_t sub, stepd_step_rec_t *job)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.step_create))(sub, job);
}

extern int cgroup_g_step_addto(cgroup_ctl_type_t sub, pid_t *pids, int npids)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.step_addto))(sub, pids, npids);
}

extern int cgroup_g_step_get_pids(pid_t **pids, int *npids)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.step_get_pids))(pids, npids);
}

extern int cgroup_g_step_suspend()
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.step_suspend))();
}

extern int cgroup_g_step_resume()
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.step_resume))();
}

extern int cgroup_g_step_destroy(cgroup_ctl_type_t sub)
{
	if (cgroup_g_init() < 0)
		return SLURM_ERROR;

	return (*(ops.step_destroy))(sub);
}

extern bool cgroup_g_has_pid(pid_t pid)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.has_pid))(pid);
}

extern void cgroup_g_free_conf(slurm_cgroup_conf_t *cg_conf)
{
	if (cgroup_g_init() < 0)
		return;

	return (*(ops.free_conf))(cg_conf);
}

extern slurm_cgroup_conf_t *cgroup_g_get_conf()
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.get_conf))();
}

extern cgroup_limits_t *cgroup_g_root_constrain_get(cgroup_ctl_type_t sub)
{
	if (cgroup_g_init() < 0)
		return NULL;

	return (*(ops.root_constrain_get))(sub);
}

extern int cgroup_g_root_constrain_set(cgroup_ctl_type_t sub,
				       cgroup_limits_t *limits)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.root_constrain_set))(sub, limits);
}

extern cgroup_limits_t *cgroup_g_system_constrain_get(cgroup_ctl_type_t sub)
{
	if (cgroup_g_init() < 0)
		return NULL;

	return (*(ops.system_constrain_get))(sub);
}

extern int cgroup_g_system_constrain_set(cgroup_ctl_type_t sub,
				       cgroup_limits_t *limits)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.system_constrain_set))(sub, limits);
}

extern int cgroup_g_user_constrain_set(cgroup_ctl_type_t sub,
				       stepd_step_rec_t *job,
				       cgroup_limits_t *limits)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.user_constrain_set))(sub, job, limits);
}

extern int cgroup_g_job_constrain_set(cgroup_ctl_type_t sub,
				      stepd_step_rec_t *job,
				      cgroup_limits_t *limits)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.job_constrain_set))(sub, job, limits);
}

extern int cgroup_g_step_constrain_set(cgroup_ctl_type_t sub,
				       stepd_step_rec_t *job,
				       cgroup_limits_t *limits)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.step_constrain_set))(sub, job, limits);
}

extern int cgroup_g_step_start_oom_mgr()
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.step_start_oom_mgr))();
}

extern cgroup_oom_t *cgroup_g_step_stop_oom_mgr(stepd_step_rec_t *job)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.step_stop_oom_mgr))(job);
}

extern int cgroup_g_accounting_init()
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.accounting_init))();
}

extern int cgroup_g_accounting_fini()
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.accounting_fini))();
}

extern int cgroup_g_task_addto_accounting(pid_t pid, stepd_step_rec_t *job,
					  uint32_t task_id)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.task_addto_accounting))(pid, job, task_id);
}

extern cgroup_acct_t *cgroup_g_task_get_acct_data(uint32_t taskid)
{
	if (cgroup_g_init() < 0)
		return false;

	return (*(ops.task_get_acct_data))(taskid);
}

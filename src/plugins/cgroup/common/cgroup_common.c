/*****************************************************************************\
 *  cgroup_common.c - Cgroup plugin common functions
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

#include "cgroup_common.h"

extern void cgroup_free_conf(slurm_cgroup_conf_t *cg_conf)
{
	if (!cg_conf)
		return;

	xfree(cg_conf->cgroup_mountpoint);
	xfree(cg_conf->cgroup_prepend);
	xfree(cg_conf->allowed_devices_file);
	xfree(cg_conf);
}

extern slurm_cgroup_conf_t *cgroup_get_conf()
{
	slurm_cgroup_conf_t *conf;
	slurm_cgroup_conf_t *conf_ptr;

	slurm_mutex_lock(&xcgroup_config_read_mutex);

	conf = xcgroup_get_slurm_cgroup_conf();
	conf_ptr = xmalloc(sizeof(*conf_ptr));

	conf_ptr->cgroup_automount = conf->cgroup_automount;
	conf_ptr->cgroup_mountpoint = xstrdup(conf->cgroup_mountpoint);
	conf_ptr->cgroup_prepend = xstrdup(conf->cgroup_prepend);
	conf_ptr->constrain_cores = conf->constrain_cores;
	conf_ptr->task_affinity = conf->task_affinity;
	conf_ptr->constrain_ram_space = conf->constrain_ram_space;
	conf_ptr->allowed_ram_space = conf->allowed_ram_space;
	conf_ptr->max_ram_percent = conf->max_ram_percent;
	conf_ptr->min_ram_space = conf->min_ram_space;
	conf_ptr->constrain_kmem_space = conf->constrain_kmem_space;
	conf_ptr->allowed_kmem_space = conf->allowed_kmem_space;
	conf_ptr->max_kmem_percent = conf->max_kmem_percent;
	conf_ptr->min_kmem_space = conf->min_kmem_space;
	conf_ptr->constrain_swap_space = conf-> constrain_swap_space;
	conf_ptr->allowed_swap_space = conf->allowed_swap_space;
	conf_ptr->max_swap_percent = conf->max_swap_percent;
	conf_ptr->memory_swappiness = conf->memory_swappiness;
	conf_ptr->constrain_devices = conf->constrain_devices;
	conf_ptr->allowed_devices_file = xstrdup(conf->allowed_devices_file);
	conf_ptr->cgroup_plugin = xstrdup(conf->cgroup_plugin);
	slurm_mutex_unlock(&xcgroup_config_read_mutex);

	return conf_ptr;
}

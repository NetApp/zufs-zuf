// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Ioctl operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/delay.h>
#include <linux/pfn_t.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/kref.h>

#include "zuf.h"
#include "relay.h"

enum { INITIAL_ZT_CHANNELS = 3 };

struct zufc_thread {
	struct zuf_special_file hdr;
	struct relay relay;
	struct vm_area_struct *vma;
	int no;
	int chan;

	/* Kernel side allocated IOCTL buffer */
	struct vm_area_struct *opt_buff_vma;
	void *opt_buff;
	ulong max_zt_command;

	/* Next operation*/
	struct zuf_dispatch_op *zdo;
};

struct zuf_threads_pool {
	struct __mount_thread_info {
		struct zuf_special_file zsf;
		spinlock_t lock;
		struct relay relay;
		struct zufs_ioc_mount *zim;
	} mount;

	uint _max_zts;
	uint _max_channels;
	 /* array of pcp_arrays */
	struct zufc_thread *_all_zt[ZUFS_MAX_ZT_CHANNELS];
};

/* ~~~~ some helpers ~~~~ */
const char *zuf_op_name(enum e_zufs_operation op)
{
#define CASE_ENUM_NAME(e) case e: return #e
	switch  (op) {
		CASE_ENUM_NAME(ZUFS_OP_NULL);
		CASE_ENUM_NAME(ZUFS_OP_BREAK);
		CASE_ENUM_NAME(ZUFS_OP_STATFS);
		CASE_ENUM_NAME(ZUFS_OP_SHOW_OPTIONS);
	case ZUFS_OP_MAX_OPT:
	default:
		return "UNKNOWN";
	}
}

static inline ulong _zt_pr_no(struct zufc_thread *zt)
{
	/* So in hex it will be channel as first nibble and cpu as 3rd and on */
	return ((ulong)zt->no << 8) | zt->chan;
}

static struct zufc_thread *_zt_from_cpu(struct zuf_root_info *zri,
					int cpu, uint chan)
{
	return per_cpu_ptr(zri->_ztp->_all_zt[chan], cpu);
}

static struct zufc_thread *_zt_from_f_private(struct file *file)
{
	struct zuf_special_file *zsf = file->private_data;

	WARN_ON(zsf->type != zlfs_e_zt);
	return container_of(zsf, struct zufc_thread, hdr);
}

/* ~~~~ init/ fini ~~~~ */
static int _alloc_zts_channel(struct zuf_root_info *zri, int channel)
{
	zri->_ztp->_all_zt[channel] = alloc_percpu_gfp(struct zufc_thread,
						       GFP_KERNEL | __GFP_ZERO);
	if (unlikely(!zri->_ztp->_all_zt[channel])) {
		zuf_err("!!! alloc_percpu channel=%d failed\n", channel);
		return -ENOMEM;
	}
	return 0;
}

int zufc_zts_init(struct zuf_root_info *zri)
{
	int c;

	zri->_ztp = kcalloc(1, sizeof(struct zuf_threads_pool), GFP_KERNEL);
	if (unlikely(!zri->_ztp))
		return -ENOMEM;

	spin_lock_init(&zri->_ztp->mount.lock);
	relay_init(&zri->_ztp->mount.relay);

	zri->_ztp->_max_zts = num_possible_cpus();
	zri->_ztp->_max_channels = INITIAL_ZT_CHANNELS;

	for (c = 0; c < INITIAL_ZT_CHANNELS; ++c) {
		int err = _alloc_zts_channel(zri, c);

		if (unlikely(err))
			return err;
	}

	return 0;
}

void zufc_zts_fini(struct zuf_root_info *zri)
{
	int c;

	/* Always safe/must call zufc_zts_fini */
	if (!zri->_ztp)
		return;

	for (c = 0; c < zri->_ztp->_max_channels; ++c) {
		if (zri->_ztp->_all_zt[c])
			free_percpu(zri->_ztp->_all_zt[c]);
	}
	kfree(zri->_ztp);
	zri->_ztp = NULL;
}

/* ~~~~ mounting ~~~~*/
int __zufc_dispatch_mount(struct zuf_root_info *zri,
			  enum e_mount_operation operation,
			  struct zufs_ioc_mount *zim)
{
	struct __mount_thread_info *zmt = &zri->_ztp->mount;

	zim->hdr.operation = operation;
	for (;;) {
		bool fss_waiting;

		spin_lock(&zmt->lock);

		if (unlikely(!zmt->zsf.file)) {
			spin_unlock(&zmt->lock);
			zuf_err("Server not up\n");
			zim->hdr.err = -EIO;
			return zim->hdr.err;
		}

		fss_waiting = relay_is_fss_waiting_grab(&zmt->relay);
		if (fss_waiting)
			break;
		/* in case of break above spin_unlock is done inside
		 * relay_fss_wakeup_app_wait
		 */

		spin_unlock(&zmt->lock);

		/* It is OK to wait if user storms mounts */
		zuf_dbg_verbose("waiting\n");
		msleep(100);
	}

	zmt->zim = zim;
	relay_fss_wakeup_app_wait_spin(&zmt->relay, &zmt->lock);

	if (zim->hdr.err > 0) {
		zuf_err("[%s] Bad Server RC not negative => %d\n",
			zuf_op_name(zim->hdr.operation), zim->hdr.err);
		zim->hdr.err = -EBADRQC;
	}
	return zim->hdr.err;
}

int zufc_dispatch_mount(struct zuf_root_info *zri, struct zus_fs_info *zus_zfi,
			enum e_mount_operation operation,
			struct zufs_ioc_mount *zim)
{
	zim->hdr.out_len = sizeof(*zim);
	zim->hdr.in_len = sizeof(*zim);
	if (operation == ZUFS_M_MOUNT || operation == ZUFS_M_REMOUNT)
		zim->hdr.in_len += zim->zmi.po.mount_options_len;
	zim->zmi.zus_zfi = zus_zfi;
	zim->zmi.num_cpu = zri->_ztp->_max_zts;
	zim->zmi.num_channels = zri->_ztp->_max_channels;

	return __zufc_dispatch_mount(zri, operation, zim);
}

static int _zu_mount(struct file *file, void *parg)
{
	struct super_block *sb = file->f_inode->i_sb;
	struct zuf_root_info *zri = ZRI(sb);
	struct __mount_thread_info *zmt = &zri->_ztp->mount;
	bool waiting_for_reply;
	struct zufs_ioc_mount *zim;
	ulong cp_ret;
	int err;

	spin_lock(&zmt->lock);

	if (unlikely(!file->private_data)) {
		/* First time register this file as the mount-thread owner */
		zmt->zsf.type = zlfs_e_mout_thread;
		zmt->zsf.file = file;
		file->private_data = &zmt->zsf;
		zri->state = ZUF_ROOT_MOUNT_READY;
	} else if (unlikely(file->private_data != zmt)) {
		spin_unlock(&zmt->lock);
		zuf_err("Say what?? %p != %p\n",
			file->private_data, zmt);
		return -EIO;
	}

	zim = zmt->zim;
	zmt->zim = NULL;
	waiting_for_reply = zim && relay_is_app_waiting(&zmt->relay);

	spin_unlock(&zmt->lock);

	if (waiting_for_reply) {
		cp_ret = copy_from_user(zim, parg, zim->hdr.out_len);
		if (unlikely(cp_ret)) {
			zuf_err("copy_from_user => %ld\n", cp_ret);
			 zim->hdr.err = -EFAULT;
		}

		relay_app_wakeup(&zmt->relay);
	}

	/* This gets to sleep until a mount comes */
	err = relay_fss_wait(&zmt->relay);
	if (unlikely(err || !zmt->zim)) {
		struct zufs_ioc_hdr *hdr = parg;

		/* Released by _zu_break INTER or crash */
		zuf_dbg_zus("_zu_break? %p => %d\n", zmt->zim, err);
		put_user(ZUFS_OP_BREAK, &hdr->operation);
		put_user(EIO, &hdr->err);
		return err;
	}

	zim = zmt->zim;
	cp_ret = copy_to_user(parg, zim, zim->hdr.in_len);
	if (unlikely(cp_ret)) {
		err = -EFAULT;
		zuf_err("copy_to_user =>%ld\n", cp_ret);
	}
	return err;
}

static void zufc_mounter_release(struct file *file)
{
	struct zuf_root_info *zri = ZRI(file->f_inode->i_sb);
	struct __mount_thread_info *zmt = &zri->_ztp->mount;

	zuf_dbg_zus("closed fu=%d au=%d fw=%d aw=%d\n",
		  zmt->relay.fss_wakeup, zmt->relay.app_wakeup,
		  zmt->relay.fss_waiting, zmt->relay.app_waiting);

	spin_lock(&zmt->lock);
	zmt->zsf.file = NULL;
	if (relay_is_app_waiting(&zmt->relay)) {
		zri->state = ZUF_ROOT_SERVER_FAILED;
		zuf_err("server emergency exit while IO\n");
		if (zmt->zim)
			zmt->zim->hdr.err = -EIO;
		spin_unlock(&zmt->lock);

		relay_app_wakeup(&zmt->relay);
		msleep(1000); /* crap */
	} else {
		if (zmt->zim)
			zmt->zim->hdr.err = 0;
		spin_unlock(&zmt->lock);
	}
}

static int _zu_private_mounter_release(struct file *file)
{
	struct zuf_root_info *zri = ZRI(file->f_inode->i_sb);
	struct zuf_special_file *zsf = file->private_data;
	struct zuf_private_mount_info *zpmi;
	int err;

	zpmi = container_of(zsf, struct zuf_private_mount_info, zsf);

	err = zuf_private_umount(zri, zpmi->sb);

	kfree(zpmi);

	return err;
}

static int _zu_private_mounter(struct file *file, void *parg)
{
	struct super_block *sb = file->f_inode->i_sb;
	struct zufs_ioc_mount_private *zip = NULL;
	struct zuf_private_mount_info *zpmi;
	struct zuf_root_info *zri = ZRI(sb);
	struct zufs_ioc_hdr hdr;
	__u32 is_umount;
	ulong cp_ret;
	int err = 0;

	get_user(is_umount,
		 &((struct zufs_ioc_mount_private *)parg)->is_umount);
	if (is_umount)
		return _zu_private_mounter_release(file);

	if (unlikely(file->private_data)) {
		zuf_err("One mount per runner please..\n");
		return -EINVAL;
	}

	zpmi = kzalloc(sizeof(*zpmi), GFP_KERNEL);
	if (unlikely(!zpmi)) {
		zuf_err("alloc failed\n");
		return -ENOMEM;
	}

	zpmi->zsf.type = zlfs_e_private_mount;
	zpmi->zsf.file = file;

	cp_ret = copy_from_user(&hdr, parg, sizeof(hdr));
	if (unlikely(cp_ret)) {
		zuf_err("copy_from_user(hdr) => %ld\n", cp_ret);
		err = -EFAULT;
		goto fail;
	}

	zip = kmalloc(hdr.in_len, GFP_KERNEL);
	if (unlikely(!zip)) {
		zuf_err("alloc failed\n");
		err = -ENOMEM;
		goto fail;
	}

	cp_ret = copy_from_user(zip, parg, hdr.in_len);
	if (unlikely(cp_ret)) {
		zuf_err("copy_from_user => %ld\n", cp_ret);
		err = -EFAULT;
		goto fail;
	}

	err = zuf_private_mount(zri, &zip->rfi, &zip->zmi, &zpmi->sb);
	if (unlikely(err))
		goto fail;

	cp_ret = copy_to_user(parg, zip, hdr.in_len);
	if (unlikely(cp_ret)) {
		zuf_err("copy_to_user =>%ld\n", cp_ret);
		err = -EFAULT;
		goto fail;
	}

	file->private_data = &zpmi->zsf;

out:
	kfree(zip);
	return err;

fail:
	kfree(zpmi);
	goto out;
}

/* ~~~~ ZU_IOC_NUMA_MAP ~~~~ */
static int _zu_numa_map(struct file *file, void *parg)
{
	struct zufs_ioc_numa_map *numa_map;
	int n_nodes = num_possible_nodes();
	uint *nodes_cpu_count;
	uint max_cpu_per_node = 0;
	uint alloc_size;
	int cpu, i, err;

	alloc_size = sizeof(*numa_map) +
			(n_nodes * sizeof(numa_map->cpu_set_per_node[0]));

	if ((n_nodes > 255) || (alloc_size > PAGE_SIZE)) {
		zuf_warn("!!!unexpected big machine with %d nodes alloc_size=0x%x\n",
			  n_nodes, alloc_size);
		return -ENOTSUPP;
	}

	nodes_cpu_count = kcalloc(n_nodes, sizeof(uint), GFP_KERNEL);
	if (unlikely(!nodes_cpu_count))
		return -ENOMEM;

	numa_map = kzalloc(alloc_size, GFP_KERNEL);
	if (unlikely(!numa_map)) {
		err = -ENOMEM;
		goto out;
	}

	numa_map->possible_nodes	= num_possible_nodes();
	numa_map->possible_cpus		= num_possible_cpus();

	numa_map->online_nodes		= num_online_nodes();
	numa_map->online_cpus		= num_online_cpus();

	for_each_online_cpu(cpu)
		set_bit(cpu, numa_map->cpu_set_per_node[cpu_to_node(cpu)].bits);

	for_each_cpu(cpu, cpu_online_mask) {
		uint ctn  = cpu_to_node(cpu);
		uint ncc = ++nodes_cpu_count[ctn];

		max_cpu_per_node = max(max_cpu_per_node, ncc);
	}

	for (i = 1; i < n_nodes; ++i) {
		if (nodes_cpu_count[i] &&
		    (nodes_cpu_count[i] != nodes_cpu_count[0])) {
			zuf_info("@[%d]=%d Unbalanced CPU sockets @[0]=%d\n",
				  i, nodes_cpu_count[i], nodes_cpu_count[0]);
			numa_map->nodes_not_symmetrical = true;
			break;
		}
	}

	numa_map->max_cpu_per_node = max_cpu_per_node;

	zuf_dbg_verbose(
		"possible_nodes=%d possible_cpus=%d online_nodes=%d online_cpus=%d\n",
		numa_map->possible_nodes, numa_map->possible_cpus,
		numa_map->online_nodes, numa_map->online_cpus);

	err = copy_to_user(parg, numa_map, alloc_size);
	kfree(numa_map);
out:
	kfree(nodes_cpu_count);
	return err;
}

/* ~~~~ PMEM GRAB ~~~~ */
/*FIXME: At pmem the struct md_dev_list for t1(s) is not properly set
 * For now we do not fix it and re-write the mdt. So just fix the one
 * we are about to send to Server
 */
static void _fix_numa_ids(struct multi_devices *md, struct md_dev_list *mdl)
{
	int i;

	for (i = 0; i < md->t1_count; ++i)
		if (md->devs[i].nid != __dev_id_nid(&mdl->dev_ids[i]))
			__dev_id_nid_set(&mdl->dev_ids[i], md->devs[i].nid);
}

static int _zu_grab_pmem(struct file *file, void *parg)
{
	struct zuf_root_info *zri = ZRI(file->f_inode->i_sb);
	struct zufs_ioc_pmem __user *arg_pmem = parg;
	struct zufs_ioc_pmem *zi_pmem = kzalloc(sizeof(*zi_pmem), GFP_KERNEL);
	struct super_block *sb;
	struct zuf_sb_info *sbi;
	size_t pmem_size;
	int err;

	if (unlikely(!zi_pmem))
		return -ENOMEM;

	err = get_user(zi_pmem->sb_id, &arg_pmem->sb_id);
	if (err) {
		zuf_err("\n");
		goto out;
	}

	sb = zuf_sb_from_id(zri, zi_pmem->sb_id, NULL);
	if (unlikely(!sb)) {
		err = -ENODEV;
		zuf_err("!!! pmem_kern_id=%llu not found\n", zi_pmem->sb_id);
		goto out;
	}
	sbi = SBI(sb);

	if (sbi->pmem.hdr.file) {
		zuf_err("[%llu] pmem already taken\n", zi_pmem->sb_id);
		err = -EIO;
		goto out;
	}

	memcpy(&zi_pmem->mdt, md_zdt(sbi->md), sizeof(zi_pmem->mdt));
	zi_pmem->dev_index = sbi->md->dev_index;
	_fix_numa_ids(sbi->md, &zi_pmem->mdt.s_dev_list);

	pmem_size = md_p2o(md_t1_blocks(sbi->md));
	if (mdt_test_option(md_zdt(sbi->md), MDT_F_SHADOW))
		pmem_size += pmem_size;
	i_size_write(file->f_inode, pmem_size);
	sbi->pmem.hdr.type = zlfs_e_pmem;
	sbi->pmem.hdr.file = file;
	sbi->pmem.md = sbi->md; /* FIXME: Use container_of in t1.c */
	file->private_data = &sbi->pmem.hdr;
	zuf_dbg_core("pmem %llu i_size=0x%llx GRABED %s\n",
		     zi_pmem->sb_id, i_size_read(file->f_inode),
		     _bdev_name(md_t1_dev(sbi->md, 0)->bdev));

out:
	zi_pmem->hdr.err = err;
	err = copy_to_user(parg, zi_pmem, sizeof(*zi_pmem));
	if (err)
		zuf_err("=>%d\n", err);
	kfree(zi_pmem);
	return err;
}

static void _prep_header_size_op(struct zufs_ioc_hdr *hdr,
				 enum e_zufs_operation op, int err)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->operation = op;
	hdr->in_len = sizeof(*hdr);
	hdr->err = err;
}

/* ~~~~~ ZT thread operations ~~~~~ */

static int _zu_init(struct file *file, void *parg)
{
	struct zufc_thread *zt;
	int cpu = smp_processor_id();
	struct zufs_ioc_init zi_init;
	int err;

	err = copy_from_user(&zi_init, parg, sizeof(zi_init));
	if (unlikely(err)) {
		zuf_err("=>%d\n", err);
		return err;
	}
	if (unlikely(zi_init.channel_no >= ZUFS_MAX_ZT_CHANNELS)) {
		zuf_err("[%d] channel_no=%d\n", cpu, zi_init.channel_no);
		return -EINVAL;
	}

	zuf_dbg_zus("[%d] channel=%d\n", cpu, zi_init.channel_no);

	zt = _zt_from_cpu(ZRI(file->f_inode->i_sb), cpu, zi_init.channel_no);
	if (unlikely(!zt)) {
		zi_init.hdr.err = -ERANGE;
		zuf_err("_zt_from_cpu(%d, %d) => %d\n",
			cpu, zi_init.channel_no, err);
		goto out;
	}

	if (unlikely(zt->hdr.file)) {
		zi_init.hdr.err = -EINVAL;
		zuf_err("[%d] !!! thread already set\n", cpu);
		goto out;
	}

	relay_init(&zt->relay);
	zt->hdr.type = zlfs_e_zt;
	zt->hdr.file = file;
	zt->no = cpu;
	zt->chan = zi_init.channel_no;

	zt->max_zt_command = zi_init.max_command;
	zt->opt_buff = vmalloc(zi_init.max_command);
	if (unlikely(!zt->opt_buff)) {
		zi_init.hdr.err = -ENOMEM;
		goto out;
	}

	file->private_data = &zt->hdr;
out:
	err = copy_to_user(parg, &zi_init, sizeof(zi_init));
	if (err)
		zuf_err("=>%d\n", err);
	return err;
}

/* Caller checks that file->private_data != NULL */
static void zufc_zt_release(struct file *file)
{
	struct zuf_root_info *zri = ZRI(file->f_inode->i_sb);
	struct zufc_thread *zt = _zt_from_f_private(file);

	if (unlikely(zt->hdr.file != file))
		zuf_err("What happened zt->file(%p) != file(%p)\n",
			zt->hdr.file, file);

	zuf_dbg_zus("[%d] closed fu=%d au=%d fw=%d aw=%d\n",
		  zt->no, zt->relay.fss_wakeup, zt->relay.app_wakeup,
		  zt->relay.fss_waiting, zt->relay.app_waiting);

	if (relay_is_app_waiting(&zt->relay)) {
		zuf_err("server emergency exit while IO\n");

		/* NOTE: Do not call _unmap_pages the vma is gone */
		zt->hdr.file = NULL;

		zri->state = ZUF_ROOT_SERVER_FAILED;

		relay_app_wakeup(&zt->relay);
		msleep(1000); /* crap */
	}

	vfree(zt->opt_buff);
	memset(zt, 0, sizeof(*zt));
}

static int _map_pages(struct zufc_thread *zt, struct page **pages, uint nump,
		      bool map_readonly)
{
	int p, err;

	if (!(zt->vma && pages && nump))
		return 0;

	for (p = 0; p < nump; ++p) {
		ulong zt_addr = zt->vma->vm_start + p * PAGE_SIZE;
		ulong pfn = page_to_pfn(pages[p]);
		pfn_t pfnt = phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV);
		vm_fault_t flt;

		if (map_readonly)
			flt = vmf_insert_mixed(zt->vma, zt_addr, pfnt);
		else
			flt = vmf_insert_mixed_mkwrite(zt->vma, zt_addr, pfnt);
		err = zuf_flt_to_err(flt);
		if (unlikely(err)) {
			zuf_err("zuf: remap_pfn_range => %d p=0x%x start=0x%lx\n",
				 err, p, zt->vma->vm_start);
			return err;
		}
	}
	return 0;
}

static void _unmap_pages(struct zufc_thread *zt, struct page **pages, uint nump)
{
	if (!(zt->vma && zt->zdo && pages && nump))
		return;

	zt->zdo->pages = NULL;
	zt->zdo->nump = 0;

	zap_vma_ptes(zt->vma, zt->vma->vm_start, nump * PAGE_SIZE);
}

static int _copy_outputs(struct zufc_thread *zt, void *arg)
{
	struct zufs_ioc_hdr *hdr = zt->zdo->hdr;
	struct zufs_ioc_hdr *user_hdr = zt->opt_buff;

	if (zt->opt_buff_vma->vm_start != (ulong)arg) {
		zuf_err("malicious Server\n");
		return -EINVAL;
	}

	/* Update on the user out_len and return-code */
	hdr->err = user_hdr->err;
	hdr->out_len = user_hdr->out_len;

	if (!hdr->out_len)
		return 0;

	if ((hdr->err == -EZUFS_RETRY && zt->zdo->oh) ||
	    (hdr->out_max < hdr->out_len)) {
		if (WARN_ON(!zt->zdo->oh)) {
			zuf_err("Trouble op(%s) out_max=%d out_len=%d\n",
				zuf_op_name(hdr->operation),
				hdr->out_max, hdr->out_len);
			return -EFAULT;
		}
		zuf_dbg_zus("[%s] %d %d => %d\n",
			    zuf_op_name(hdr->operation),
			    hdr->out_max, hdr->out_len, hdr->err);
		return zt->zdo->oh(zt->zdo, zt->opt_buff, zt->max_zt_command);
	} else {
		void *rply = (void *)hdr + hdr->out_start;
		void *from = zt->opt_buff + hdr->out_start;

		memcpy(rply, from, hdr->out_len);
		return 0;
	}
}

static int _zu_wait(struct file *file, void *parg)
{
	struct zufc_thread *zt;
	bool __chan_is_locked = false;
	int err;

	zt = _zt_from_f_private(file);
	if (unlikely(!zt)) {
		zuf_err("Unexpected ZT state\n");
		err = -ERANGE;
		goto err;
	}

	if (!zt->hdr.file || file != zt->hdr.file) {
		zuf_err("fatal\n");
		err = -E2BIG;
		goto err;
	}
	if (unlikely((ulong)parg != zt->opt_buff_vma->vm_start)) {
		zuf_err("fatal 2\n");
		err = -EINVAL;
		goto err;
	}

	if (relay_is_app_waiting(&zt->relay)) {
		if (unlikely(!zt->zdo)) {
			zuf_err("User has gone...\n");
			err = -E2BIG;
			goto err;
		}

		/* overflow_handler might decide to execute the parg here at
		 * zus context and return to server.
		 * If it also has an error to report to zus it will set
		 * zdo->hdr->err. EZUS_RETRY_DONE is when that happens.
		 * In this case pages stay mapped in zt->vma.
		 */
		err = _copy_outputs(zt, parg);
		if (err == EZUF_RETRY_DONE) {
			put_user(zt->zdo->hdr->err, (int *)parg);
			return 0;
		}

		_unmap_pages(zt, zt->zdo->pages, zt->zdo->nump);

		zt->zdo = NULL;
		if (unlikely(err)) /* _copy_outputs returned an err */
			goto err;

		relay_app_wakeup(&zt->relay);
	}

	err = __relay_fss_wait(&zt->relay, __chan_is_locked);
	if (err)
		zuf_dbg_err("[%d] relay error: %d\n", zt->no, err);

	if (zt->zdo &&  zt->zdo->hdr &&
	    zt->zdo->hdr->operation != ZUFS_OP_BREAK &&
	    zt->zdo->hdr->operation < ZUFS_OP_MAX_OPT) {
		/* call map here at the zuf thread so we need no locks
		 * TODO: Currently only ZUFS_OP_WRITE protects user-buffers
		 * we should have a bit set in zt->zdo->hdr set per operation.
		 * TODO: Why this does not work?
		 */
		_map_pages(zt, zt->zdo->pages, zt->zdo->nump, 0);
	} else {
		/* This Means we were released by _zu_break */
		zuf_dbg_zus("_zu_break? => %d\n", err);
		_prep_header_size_op(zt->opt_buff, ZUFS_OP_BREAK, err);
	}

	return err;

err:
	put_user(err, (int *)parg);
	return err;
}

static int _try_grab_zt_channel(struct zuf_root_info *zri, int cpu,
				 struct zufc_thread **ztp)
{
	struct zufc_thread *zt;
	int c;

	for (c = 0; ; ++c) {
		zt = _zt_from_cpu(zri, cpu, c);
		if (unlikely(!zt || !zt->hdr.file))
			break;

		if (relay_is_fss_waiting_grab(&zt->relay)) {
			*ztp = zt;
			return true;
		}
	}

	*ztp = _zt_from_cpu(zri, cpu, 0);
	return false;
}

#ifdef CONFIG_ZUF_DEBUG
#define DEBUG_CPU_SWITCH(cpu)		\
	do {					\
		int cpu2 = smp_processor_id();	\
		if (cpu2 != cpu)		\
			zuf_warn("App switched cpu1=%u cpu2=%u\n", \
				 cpu, cpu2);	\
	} while (0)

static
int _r_zufs_dispatch(struct zuf_root_info *zri, struct zuf_dispatch_op *zdo)

#else /* !CONFIG_ZUF_DEBUG */
#define DEBUG_CPU_SWITCH(cpu)

int __zufc_dispatch(struct zuf_root_info *zri, struct zuf_dispatch_op *zdo)
#endif /* CONFIG_ZUF_DEBUG */
{
	struct task_struct *app = get_current();
	struct zufs_ioc_hdr *hdr = zdo->hdr;
	int cpu;
	struct zufc_thread *zt;

	if (unlikely(zri->state == ZUF_ROOT_SERVER_FAILED))
		return -EIO;

	if (unlikely(hdr->out_len && !hdr->out_max)) {
		/* TODO: Complain here and let caller code do this proper */
		hdr->out_max = hdr->out_len;
	}

	if (unlikely(zdo->__locked_zt)) {
		zt = zdo->__locked_zt;
		zdo->__locked_zt = NULL;

		cpu = get_cpu();
		/* FIXME: Very Pedantic need it stay */
		if (unlikely((zt->zdo != zdo) || cpu != zt->no)) {
			zuf_warn("[%ld] __locked_zt but zdo(%p != %p) || cpu(%d != %d)\n",
				 _zt_pr_no(zt), zt->zdo, zdo, cpu, zt->no);
			put_cpu();
			goto channel_busy;
		}
		goto has_channel;
	}
channel_busy:
	cpu = get_cpu();

	if (!_try_grab_zt_channel(zri, cpu, &zt)) {
		put_cpu();

		/* If channel was grabbed then maybe a break_all is in progress
		 * on a different CPU make sure zt->file on this core is
		 * updated
		 */
		mb();
		if (unlikely(!zt->hdr.file)) {
			zuf_err("[%d] !zt->file\n", cpu);
			return -EIO;
		}
		zuf_dbg_err("[%d] can this be\n", cpu);
		/* FIXME: Do something much smarter */
		msleep(10);
		if (signal_pending(get_current())) {
			zuf_dbg_err("[%d] => EINTR\n", cpu);
			return -EINTR;
		}
		goto channel_busy;
	}

	/* lock app to this cpu while waiting */
	cpumask_copy(&zt->relay.cpus_allowed, &app->cpus_mask);
	cpumask_copy(&app->cpus_mask,  cpumask_of(smp_processor_id()));

	zt->zdo = zdo;

has_channel:
	if (zdo->dh)
		zdo->dh(zdo, zt, zt->opt_buff);
	else
		memcpy(zt->opt_buff, zt->zdo->hdr, zt->zdo->hdr->in_len);

	put_cpu();

	if (relay_fss_wakeup_app_wait(&zt->relay) == -ERESTARTSYS) {
		struct zufs_ioc_hdr *opt_hdr = zt->opt_buff;

		opt_hdr->flags |= ZUFS_H_INTR;

		relay_fss_wakeup_app_wait_cont(&zt->relay);
	}

	/* __locked_zt must be kept on same cpu */
	if (!zdo->__locked_zt)
		/* restore cpu affinity after wakeup */
		cpumask_copy(&app->cpus_mask, &zt->relay.cpus_allowed);

	DEBUG_CPU_SWITCH(cpu);

	return zt->hdr.file ? hdr->err : -EIO;
}

#ifdef CONFIG_ZUF_DEBUG
#define MAX_ZT_SEC 7
int __zufc_dispatch(struct zuf_root_info *zri, struct zuf_dispatch_op *zdo)
{
	u64 t1, t2;
	int err;

	t1 = ktime_get_ns();
	err = _r_zufs_dispatch(zri, zdo);
	t2 = ktime_get_ns();

	if ((t2 - t1) > MAX_ZT_SEC * NSEC_PER_SEC)
		zuf_err("zufc_dispatch(%s, [0x%x-0x%x]) took %lld sec\n",
			zuf_op_name(zdo->hdr->operation), zdo->hdr->offset,
			zdo->hdr->len,
			(t2 - t1) / NSEC_PER_SEC);

	return err;
}
#endif /* def CONFIG_ZUF_DEBUG */

/* ~~~ iomap_exec && exec_buffer allocation ~~~ */

struct zu_exec_buff {
	struct zuf_special_file hdr;
	struct vm_area_struct *vma;
	void *opt_buff;
	ulong alloc_size;
};

/* Do some common checks and conversions */
static inline struct zu_exec_buff *_ebuff_from_file(struct file *file)
{
	struct zu_exec_buff *ebuff = file->private_data;

	if (WARN_ON_ONCE(ebuff->hdr.type != zlfs_e_dpp_buff)) {
		zuf_err("Must call ZU_IOC_ALLOC_BUFFER first\n");
		return NULL;
	}

	if (WARN_ON_ONCE(ebuff->hdr.file != file))
		return NULL;

	return ebuff;
}

static int _zu_ebuff_alloc(struct file *file, void *arg)
{
	struct zufs_ioc_alloc_buffer ioc_alloc;
	struct zu_exec_buff *ebuff;
	int err;

	err = copy_from_user(&ioc_alloc, arg, sizeof(ioc_alloc));
	if (unlikely(err)) {
		zuf_err("=>%d\n", err);
		return err;
	}

	if (ioc_alloc.init_size > ioc_alloc.max_size)
		return -EINVAL;

	/* TODO: Easily Support growing */
	/* TODO: Support global pools, also easy */
	if (ioc_alloc.pool_no || ioc_alloc.init_size != ioc_alloc.max_size)
		return -ENOTSUPP;

	ebuff = kzalloc(sizeof(*ebuff), GFP_KERNEL);
	if (unlikely(!ebuff))
		return -ENOMEM;

	ebuff->hdr.type = zlfs_e_dpp_buff;
	ebuff->hdr.file = file;
	i_size_write(file->f_inode, ioc_alloc.max_size);
	ebuff->alloc_size =  ioc_alloc.init_size;
	ebuff->opt_buff = vmalloc(ioc_alloc.init_size);
	if (unlikely(!ebuff->opt_buff)) {
		kfree(ebuff);
		return -ENOMEM;
	}

	file->private_data = &ebuff->hdr;
	return 0;
}

static void zufc_ebuff_release(struct file *file)
{
	struct zu_exec_buff *ebuff = _ebuff_from_file(file);

	if (unlikely(!ebuff))
		return;

	vfree(ebuff->opt_buff);
	ebuff->hdr.type = 0;
	ebuff->hdr.file = NULL; /* for none-dbg Kernels && use-after-free */
	kfree(ebuff);
}

/* ~~~~ ioctl & release handlers ~~~~ */
static int _zu_register_fs(struct file *file, void *parg)
{
	struct zufs_ioc_register_fs rfs;
	int err;

	err = copy_from_user(&rfs, parg, sizeof(rfs));
	if (unlikely(err)) {
		zuf_err("=>%d\n", err);
		return err;
	}

	err = zufr_register_fs(file->f_inode->i_sb, &rfs);
	if (err)
		zuf_err("=>%d\n", err);
	err = put_user(err, (int *)parg);
	return err;
}

static int _zu_break(struct file *filp, void *parg)
{
	struct zuf_root_info *zri = ZRI(filp->f_inode->i_sb);
	int i, c;

	zuf_dbg_core("enter\n");
	mb(); /* TODO how to schedule on all CPU's */

	for (i = 0; i < zri->_ztp->_max_zts; ++i) {
		if (unlikely(!cpu_active(i)))
			continue;
		for (c = 0; c < zri->_ztp->_max_channels; ++c) {
			struct zufc_thread *zt = _zt_from_cpu(zri, i, c);

			if (unlikely(!(zt && zt->hdr.file)))
				continue;
			relay_fss_wakeup(&zt->relay);
		}
	}

	if (zri->_ztp->mount.zsf.file)
		relay_fss_wakeup(&zri->_ztp->mount.relay);

	zuf_dbg_core("exit\n");
	return 0;
}

long zufc_ioctl(struct file *file, unsigned int cmd, ulong arg)
{
	void __user *parg = (void __user *)arg;

	switch (cmd) {
	case ZU_IOC_REGISTER_FS:
		return _zu_register_fs(file, parg);
	case ZU_IOC_MOUNT:
		return _zu_mount(file, parg);
	case ZU_IOC_NUMA_MAP:
		return _zu_numa_map(file, parg);
	case ZU_IOC_GRAB_PMEM:
		return _zu_grab_pmem(file, parg);
	case ZU_IOC_INIT_THREAD:
		return _zu_init(file, parg);
	case ZU_IOC_WAIT_OPT:
		return _zu_wait(file, parg);
	case ZU_IOC_ALLOC_BUFFER:
		return _zu_ebuff_alloc(file, parg);
	case ZU_IOC_PRIVATE_MOUNT:
		return _zu_private_mounter(file, parg);
	case ZU_IOC_BREAK_ALL:
		return _zu_break(file, parg);
	default:
		zuf_err("%d %ld\n", cmd, ZU_IOC_WAIT_OPT);
		return -ENOTTY;
	}
}

int zufc_release(struct inode *inode, struct file *file)
{
	struct zuf_special_file *zsf = file->private_data;

	if (!zsf)
		return 0;

	switch (zsf->type) {
	case zlfs_e_zt:
		zufc_zt_release(file);
		return 0;
	case zlfs_e_mout_thread:
		zufc_mounter_release(file);
		return 0;
	case zlfs_e_private_mount:
		_zu_private_mounter_release(file);
		return 0;
	case zlfs_e_pmem:
		/* NOTHING to clean for pmem file yet */
		/* zuf_pmem_release(file);*/
		return 0;
	case zlfs_e_dpp_buff:
		zufc_ebuff_release(file);
		return 0;
	default:
		return 0;
	}
}

/* ~~~~  mmap area of app buffers into server ~~~~ */

static vm_fault_t zuf_zt_fault(struct vm_fault *vmf)
{
	zuf_err("should not fault pgoff=0x%lx\n", vmf->pgoff);
	return VM_FAULT_SIGBUS;
}

static const struct vm_operations_struct zuf_vm_ops = {
	.fault		= zuf_zt_fault,
};

static int _zufc_zt_mmap(struct file *file, struct vm_area_struct *vma,
			 struct zufc_thread *zt)
{
	/* VM_PFNMAP for zap_vma_ptes() Careful! */
	vma->vm_flags |= VM_PFNMAP;
	vma->vm_ops = &zuf_vm_ops;

	zt->vma = vma;

	zuf_dbg_core(
		"[0x%lx] start=0x%lx end=0x%lx flags=0x%lx file-start=0x%lx\n",
		_zt_pr_no(zt), vma->vm_start, vma->vm_end, vma->vm_flags,
		vma->vm_pgoff);

	return 0;
}

/* ~~~~  mmap the Kernel allocated IOCTL buffer per ZT ~~~~ */
static int _opt_buff_mmap(struct vm_area_struct *vma, void *opt_buff,
			  ulong opt_size)
{
	ulong offset;

	if (!opt_buff)
		return -ENOMEM;

	for (offset = 0; offset < opt_size; offset += PAGE_SIZE) {
		ulong addr = vma->vm_start + offset;
		ulong pfn = vmalloc_to_pfn(opt_buff +  offset);
		pfn_t pfnt = phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV);
		int err;

		zuf_dbg_verbose("[0x%lx] pfn-0x%lx addr=0x%lx buff=0x%lx\n",
				offset, pfn, addr, (ulong)opt_buff + offset);

		err = zuf_flt_to_err(vmf_insert_mixed_mkwrite(vma, addr, pfnt));
		if (unlikely(err)) {
			zuf_err("zuf: zuf_insert_mixed_mkwrite => %d offset=0x%lx addr=0x%lx\n",
				 err, offset, addr);
			return err;
		}
	}

	return 0;
}

static vm_fault_t zuf_obuff_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct zufc_thread *zt = _zt_from_f_private(vma->vm_file);
	long offset = (vmf->pgoff << PAGE_SHIFT) - ZUS_API_MAP_MAX_SIZE;
	int err;

	zuf_dbg_core(
		"[0x%lx] start=0x%lx end=0x%lx file-start=0x%lx offset=0x%lx\n",
		_zt_pr_no(zt), vma->vm_start, vma->vm_end, vma->vm_pgoff,
		offset);

	/* if Server overruns its buffer crash it dead */
	if (unlikely((offset < 0) || (zt->max_zt_command < offset))) {
		zuf_err("[0x%lx] start=0x%lx end=0x%lx file-start=0x%lx offset=0x%lx\n",
			_zt_pr_no(zt), vma->vm_start,
			vma->vm_end, vma->vm_pgoff, offset);
		return VM_FAULT_SIGBUS;
	}

	/* We never released a zus-core.c that does not fault the
	 * first page first. I want to see if this happens
	 */
	if (unlikely(offset))
		zuf_warn("Suspicious server activity\n");

	/* This faults only once at very first access */
	err = _opt_buff_mmap(vma, zt->opt_buff, zt->max_zt_command);
	if (unlikely(err))
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct zuf_obuff_ops = {
	.fault		= zuf_obuff_fault,
};

static int _zufc_obuff_mmap(struct file *file, struct vm_area_struct *vma,
			    struct zufc_thread *zt)
{
	vma->vm_flags |= VM_PFNMAP;
	vma->vm_ops = &zuf_obuff_ops;

	zt->opt_buff_vma = vma;

	zuf_dbg_core(
		"[0x%lx] start=0x%lx end=0x%lx flags=0x%lx file-start=0x%lx\n",
		_zt_pr_no(zt), vma->vm_start, vma->vm_end, vma->vm_flags,
		vma->vm_pgoff);

	return 0;
}

/* ~~~ */

static int zufc_zt_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zufc_thread *zt = _zt_from_f_private(file);

	/* We have two areas of mmap in this special file.
	 * 0 to ZUS_API_MAP_MAX_SIZE:
	 *	The first part where app pages are mapped
	 *	into server per operation.
	 * ZUS_API_MAP_MAX_SIZE of size zuf_root_info->max_zt_command
	 *	Is where we map the per ZT ioctl-buffer, later passed
	 *	to the zus_ioc_wait IOCTL call
	 */
	if (vma->vm_pgoff == ZUS_API_MAP_MAX_SIZE / PAGE_SIZE)
		return _zufc_obuff_mmap(file, vma, zt);

	/* zuf ZT API is very particular about where in its
	 * special file we communicate
	 */
	if (unlikely(vma->vm_pgoff))
		return -EINVAL;

	return _zufc_zt_mmap(file, vma, zt);
}

/* ~~~~ Implementation of the ZU_IOC_ALLOC_BUFFER mmap facility ~~~~ */

static vm_fault_t zuf_ebuff_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct zu_exec_buff *ebuff = _ebuff_from_file(vma->vm_file);
	long offset = (vmf->pgoff << PAGE_SHIFT);
	int err;

	zuf_dbg_core("start=0x%lx end=0x%lx file-start=0x%lx file-off=0x%lx\n",
		     vma->vm_start, vma->vm_end, vma->vm_pgoff, offset);

	if (unlikely(!ebuff))
		return VM_FAULT_SIGBUS;

	/* if Server overruns its buffer crash it dead */
	if (unlikely((offset < 0) || (ebuff->alloc_size < offset))) {
		zuf_err("start=0x%lx end=0x%lx file-start=0x%lx file-off=0x%lx\n",
			vma->vm_start, vma->vm_end, vma->vm_pgoff,
			offset);
		return VM_FAULT_SIGBUS;
	}

	/* We never released a zus-core.c that does not fault the
	 * first page first. I want to see if this happens
	 */
	if (unlikely(offset))
		zuf_warn("Suspicious server activity\n");

	/* This faults only once at very first access */
	err = _opt_buff_mmap(vma, ebuff->opt_buff, ebuff->alloc_size);
	if (unlikely(err))
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct zuf_ebuff_ops = {
	.fault		= zuf_ebuff_fault,
};

static int zufc_ebuff_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zu_exec_buff *ebuff = _ebuff_from_file(vma->vm_file);

	if (unlikely(!ebuff))
		return -EINVAL;

	vma->vm_flags |= VM_PFNMAP;
	vma->vm_ops = &zuf_ebuff_ops;

	ebuff->vma = vma;

	zuf_dbg_core("start=0x%lx end=0x%lx flags=0x%lx file-start=0x%lx\n",
		      vma->vm_start, vma->vm_end, vma->vm_flags, vma->vm_pgoff);

	return 0;
}

int zufc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zuf_special_file *zsf = file->private_data;

	if (unlikely(!zsf)) {
		zuf_err("Which mmap is that !!!!\n");
		return -ENOTTY;
	}

	switch (zsf->type) {
	case zlfs_e_zt:
		return zufc_zt_mmap(file, vma);
	case zlfs_e_pmem:
		return zuf_pmem_mmap(file, vma);
	case zlfs_e_dpp_buff:
		return zufc_ebuff_mmap(file, vma);
	default:
		zuf_err("type=%d\n", zsf->type);
		return -ENOTTY;
	}
}

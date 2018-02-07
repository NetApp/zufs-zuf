/*
 * BRIEF DESCRIPTION
 *
 * Ioctl operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/wait.h>
#include <linux/delay.h>

#include "zuf.h"

static struct page *g_drain_p = NULL;

struct zufs_thread {
	struct zuf_special_file hdr;
	struct relay relay;
	struct file *file;
	struct vm_area_struct *vma;
	int no;

	/* Next operation*/
	struct zufs_ioc_hdr *next_opt;
	struct page **pages;
	uint nump;
} ____cacheline_aligned;

static int _zt_from_f(struct file *filp, int cpu, struct zufs_thread **ztp)
{
	struct zuf_root_info *zri = ZRI(filp->f_inode->i_sb);

	if ((cpu < 0) || (zri->_max_zts <= cpu))  {
		zuf_err("fatal\n");
		return -ERANGE;
	}

	*ztp = &zri->_all_zt[cpu];
	return 0;
}

int zufs_zts_init(struct zuf_root_info *zri)
{
	zri->_max_zts = num_online_cpus();

	zri->_all_zt = kcalloc(zri->_max_zts, sizeof(struct zufs_thread),
			       GFP_KERNEL);
	if (unlikely(!zri->_all_zt))
		return -ENOMEM;

	g_drain_p = alloc_page(GFP_KERNEL);
	if (!g_drain_p) {
		zuf_err("!!! failed to alloc g_drain_p\n");
		return -ENOMEM;
	}

	return 0;
}

void zufs_zts_fini(struct zuf_root_info *zri)
{
	if (g_drain_p) {
		__free_page(g_drain_p);
		g_drain_p = NULL;
	}
	kfree(zri->_all_zt);
	zri->_all_zt = NULL;
}

static int _zu_register_fs(struct file *file, void *parg)
{
	struct zufs_ioc_register_fs rfs;
	int err;

	err = copy_from_user(&rfs, parg, sizeof(rfs));
	if (unlikely(err)) {
		zuf_err("=>%d\n", err);
		return err;
	}

	err = zuf_register_fs(file->f_inode->i_sb, &rfs);
	if (err)
		zuf_err("=>%d\n", err);
	err = put_user(err, (int *)parg);
	return err;
}

/* ~~~~ mounting ~~~~*/
int zufs_dispatch_mount(struct zuf_root_info *zri, struct zus_fs_info *zus_zfi,
			struct zufs_ioc_mount *zim)
{
	zim->zus_zfi = zus_zfi;

	for (;;) {
		bool fss_waiting;
		/* It is OK to wait if user storms mounts */
		spin_lock(&zri->mount.lock);
		fss_waiting = relay_is_fss_waiting(&zri->mount.relay);
		if (fss_waiting)
			break;

		spin_unlock(&zri->mount.lock);
		/* if (unlikely(zri->mount_file)) {
			// Server died
			zim->hdr.err = -EIO;
			goto out;
		}*/
		zuf_dbg_verbose("waiting\n");
		msleep(100);
	}

	zri->mount.zim = zim;

	relay_fss_wakeup_app_wait(&zri->mount.relay, &zri->mount.lock);

	return zim->hdr.err;
}

int zufs_dispatch_umount(struct zuf_root_info *zri, struct zus_sb_info *zus_sbi)
{
	struct zufs_ioc_mount zim = {
		.is_umounting = true,
		.zus_sbi = zus_sbi,
	};

	return zufs_dispatch_mount(zri, NULL, &zim);
}

static int _zu_mount(struct file *file, void *parg)
{
	struct super_block *sb = file->f_inode->i_sb;
	struct zuf_root_info *zri = ZRI(sb);
	bool waiting_for_reply;
	struct zufs_ioc_mount *zim;
	int err;

	spin_lock(&zri->mount.lock);

	if (unlikely(!file->private_data)) {
		/* First time register this file as the mount-thread owner */
		zri->mount.zsf.type = zlfs_e_mout_thread;
		zri->mount.file = file;
		file->private_data = &zri->mount;
	} else if (unlikely(file->private_data != &zri->mount)) {
		zuf_err("Say what?? %p != %p\n",
			file->private_data, &zri->mount);
		return -EIO;
	}

	relay_fss_waiting_grab(&zri->mount.relay);
	zim = zri->mount.zim;
	zri->mount.zim = NULL;
	waiting_for_reply = zim && relay_is_app_waiting(&zri->mount.relay);

	spin_unlock(&zri->mount.lock);

	if (waiting_for_reply) {
		zim->hdr.err = copy_from_user(zim, parg, sizeof(*zim));
		relay_app_wakeup(&zri->mount.relay);
		if (unlikely(zim->hdr.err)) {
			zuf_err("=>%d\n", zim->hdr.err);
			return zim->hdr.err;
		}
	}

	/* This gets to sleep until a mount comes */
	err = relay_fss_wait(&zri->mount.relay);
	if (unlikely(err || !zri->mount.zim)) {
		struct zufs_ioc_hdr *hdr = parg;

		/* Released by _zu_break INTER or crash */
		zuf_warn("_zu_break? %p => %d\n", zri->mount.zim, err);
		put_user(ZUS_OP_BREAK, &hdr->operation);
		put_user(EIO, &hdr->err);
		return err;
	}

	err = copy_to_user(parg, zri->mount.zim, sizeof(*zri->mount.zim));
	if (unlikely(err))
		zuf_err("=>%d\n", err);
	return err;
}

void zufs_mounter_release(struct file *file)
{
	struct zuf_root_info *zri = ZRI(file->f_inode->i_sb);

	zuf_warn("closed fu=%d au=%d fw=%d aw=%d\n",
		  zri->mount.relay.fss_wakeup, zri->mount.relay.app_wakeup,
		  zri->mount.relay.fss_waiting, zri->mount.relay.app_waiting);

	spin_lock(&zri->mount.lock);
	if (relay_is_app_waiting(&zri->mount.relay)) {
		zuf_err("server emergency exit while IO\n");

		zri->mount.zim->hdr.err = -EIO;
		zri->mount.file = NULL;
		spin_unlock(&zri->mount.lock);

		relay_app_wakeup(&zri->mount.relay);
		msleep(1000); /* crap */
	} else {
		spin_unlock(&zri->mount.lock);
	}
}

/* ~~~~ PMEM GRAB ~~~~ */
static int zufr_find_pmem(struct zuf_root_info *zri,
		   uint pmem_kern_id, struct zuf_pmem **pmem_md)
{
	struct zuf_pmem *z_pmem;

	list_for_each_entry(z_pmem, &zri->pmem_list, list) {
		if (z_pmem->pmem_id == pmem_kern_id) {
			*pmem_md = z_pmem;
			return 0;
		}
	}

	return -ENODEV;
}

static int _zu_grab_pmem(struct file *file, void *parg)
{
	struct zuf_root_info *zri = ZRI(file->f_inode->i_sb);
	struct zufs_ioc_pmem __user *arg_pmem = parg;
	struct zufs_ioc_pmem zi_pmem = {};
	struct zuf_pmem *pmem_md;
	int err;

	err = get_user(zi_pmem.pmem_kern_id, &arg_pmem->pmem_kern_id);
	if (err) {
		zuf_err("\n");
		return err;
	}

	err = zufr_find_pmem(zri, zi_pmem.pmem_kern_id, &pmem_md);
	if (err) {
		zuf_err("!!! pmem_kern_id=%d not found\n",
			zi_pmem.pmem_kern_id);
		goto out;
	}

	if (pmem_md->file) {
		zuf_err("[%u] pmem already taken\n", zi_pmem.pmem_kern_id);
		err = -EIO;
		goto out;
	}

	err = md_numa_info(&pmem_md->md, &zi_pmem);
	if (unlikely(err)) {
		zuf_err("md_numa_info => %d\n", err);
		goto out;
	}

	i_size_write(file->f_inode, zuf_p2o(md_t1_blocks(&pmem_md->md)));
	pmem_md->hdr.type = zlfs_e_pmem;
	pmem_md->file = file;
	file->private_data = &pmem_md->hdr;
	zuf_dbg_core("pmem %d GRABED %s\n",
		     zi_pmem.pmem_kern_id,
		     _bdev_name(md_t1_dev(&pmem_md->md, 0)->bdev));

out:
	zi_pmem.hdr.err = err;
	err = copy_to_user(parg, &zi_pmem, sizeof(zi_pmem));
	if (err)
		zuf_err("=>%d\n", err);
	return err;
}

static int _map_pages(struct zufs_thread *zt, struct page **pages, uint nump,
		      bool zap)
{
	int p, err;
	pgprot_t prot;

	if (!(zt->vma && pages && nump))
		return 0;

	prot = pgprot_modify(prot, PAGE_SHARED);
	for (p = 0; p < nump; ++p) {
		ulong zt_addr = zt->vma->vm_start + p * PAGE_SIZE;
		ulong pfn = page_to_pfn(zap ? g_drain_p : pages[p]);

		err = vm_insert_pfn_prot(zt->vma, zt_addr, pfn, prot);
		if (unlikely(err)) {
			zuf_err("zuf: remap_pfn_range => %d p=0x%x start=0x%lx\n",
				 err, p, zt->vma->vm_start);
			return err;
		}
	}
	return 0;
}

static void _unmap_pages(struct zufs_thread *zt, struct page **pages, uint nump)
{
	if (!(zt->vma && pages && nump))
		return;

	zt->pages = NULL;
	zt->nump = 0;

	// Punch in a drain page for this CPU
	_map_pages(zt, pages, nump, true);
}

static int _zu_init(struct file *file, void *parg)
{
	struct zufs_thread *zt;
	int cpu = smp_processor_id();
	struct zufs_ioc_init zi_init;
	int err;

	err = copy_from_user(&zi_init, parg, sizeof(zi_init));
	if (unlikely(err)) {
		zuf_err("=>%d\n", err);
		return err;
	}

	zuf_warn("[%d] aff=0x%lx\n", cpu, zi_init.affinity);

	zi_init.hdr.err = _zt_from_f(file, cpu, &zt);
	if (unlikely(zi_init.hdr.err)) {
		zuf_err("=>%d\n", err);
		goto out;
	}

	if (zt->file) {
		zuf_err("[%d] thread already set\n", cpu);
		memset(zt, 0, sizeof(*zt));
	}

	relay_init(&zt->relay);
	zt->hdr.type = zlfs_e_zt;
	zt->file = file;
	zt->no = cpu;

	file->private_data = &zt->hdr;
out:
	err = copy_to_user(parg, &zi_init, sizeof(zi_init));
	if (err)
		zuf_err("=>%d\n", err);
	return err;
}

struct zufs_thread *_zt_from_f_private(struct file *file)
{
	struct zuf_special_file *zsf = file->private_data;

	WARN_ON(zsf->type != zlfs_e_zt);
	return container_of(zsf, struct zufs_thread, hdr);
}

/* Caller checks that file->private_data != NULL */
void zufs_zt_release(struct file *file)
{
	struct zufs_thread *zt = _zt_from_f_private(file);

	if (unlikely(zt->file != file))
		zuf_err("What happened zt->file(%p) != file(%p)\n",
			zt->file, file);

	zuf_warn("[%d] closed fu=%d au=%d fw=%d aw=%d\n",
		  zt->no, zt->relay.fss_wakeup, zt->relay.app_wakeup,
		  zt->relay.fss_waiting, zt->relay.app_waiting);

	if (relay_is_app_waiting(&zt->relay)) {
		zuf_err("server emergency exit while IO\n");

		/* NOTE: Do not call _unmap_pages the vma is gone */

		zt->next_opt->err = -EIO;
		zt->file = NULL;

		relay_app_wakeup(&zt->relay);
		msleep(1000); /* crap */
	}

	memset(zt, 0, sizeof(*zt));
}

static int _zu_wait(struct file *file, void *parg)
{
	struct zufs_thread *zt;
	int cpu = smp_processor_id();
	int err;

// 	zuf_warn("[%d] enter\n", cpu);

	err = _zt_from_f(file, cpu, &zt);
	if (unlikely(err))
		goto err;

	if (!zt->file || file != zt->file) {
		zuf_err("fatal\n");
		err = -E2BIG;
		goto err;
	}

	relay_fss_waiting_grab(&zt->relay);

	if (relay_is_app_waiting(&zt->relay)) {
		_unmap_pages(zt, zt->pages, zt->nump);

		get_user(zt->next_opt->err, (int *)parg);
		if (zt->next_opt->out_len) {
			void *rply = (void *)zt->next_opt +
							zt->next_opt->out_start;
			void *from = parg + zt->next_opt->out_start;

			err = copy_from_user(rply, from, zt->next_opt->out_len);
		}
		zt->next_opt = NULL;

		relay_app_wakeup(&zt->relay);
	}

	err  = relay_fss_wait(&zt->relay);

	if (zt->next_opt &&  zt->next_opt->operation < ZUS_OP_BREAK) {
		/* call map here at the zuf thread so we need no locks */
		_map_pages(zt, zt->pages, zt->nump, false);
		err = copy_to_user(parg, zt->next_opt, zt->next_opt->in_len);
	} else {
		struct zufs_ioc_hdr *hdr = parg;

		/* This Means we were released by _zu_break */
		zuf_warn("_zu_break? %p => %d\n", zt->next_opt, err);
		put_user(ZUS_OP_BREAK, &hdr->operation);
		put_user(err, &hdr->err);
	}

// 	zuf_warn("[%d] exit\n", cpu);
	return err;

err:
	put_user(err, (int *)parg);
	return err;
}

int zufs_dispatch(struct zuf_root_info *zri, struct zufs_ioc_hdr *hdr,
		  struct page **pages, uint nump)
{
	int cpu = smp_processor_id();
	struct zufs_thread *zt;

	if ((cpu < 0) || (zri->_max_zts <= cpu))
		return -ERANGE;
	zt = &zri->_all_zt[cpu];

	if (unlikely(!zt->file))
		return -EIO;

	while (!relay_is_fss_waiting(&zt->relay)) {
		mb();
		if (unlikely(!zt->file))
			return -EIO;
		zuf_err("[%d] can this be\n", cpu);
		msleep(100);
		mb();
	}

	zt->next_opt = hdr;
	zt->pages = pages;
	zt->nump = nump;

	relay_fss_wakeup_app_wait(&zt->relay, NULL);

	return zt->file ? hdr->err : -EIO;
}

static int _zu_break(struct file *filp, void *parg)
{
	struct zuf_root_info *zri = ZRI(filp->f_inode->i_sb);
	int i;

	zuf_dbg_core("enter\n");
	mb(); /* TODO how to schedule on all CPU's */

	for (i = 0; i < zri->_max_zts; ++i) {
		struct zufs_thread *zt = &zri->_all_zt[i];

		if (unlikely(!(zt && zt->file)))
			continue;
		relay_fss_wakeup(&zt->relay);
	}

	if (zri->mount.file)
		relay_fss_wakeup(&zri->mount.relay);

	zuf_dbg_core("exit\n");
	return 0;
}

long zufs_ioc(struct file *file, unsigned int cmd, ulong arg)
{
	void __user *parg = (void __user *)arg;

	switch (cmd) {
	case ZU_IOC_REGISTER_FS:
		return _zu_register_fs(file, parg);
	case ZU_IOC_MOUNT:
		return _zu_mount(file, parg);
	case ZU_IOC_GRAB_PMEM:
		return _zu_grab_pmem(file, parg);
	case ZU_IOC_INIT_THREAD:
		return _zu_init(file, parg);
	case ZU_IOC_WAIT_OPT:
		return _zu_wait(file, parg);
	case ZU_IOC_BREAK_ALL:
		return _zu_break(file, parg);
	default:
		zuf_err("%d %ld\n", cmd, ZU_IOC_WAIT_OPT);
		return -ENOTTY;
	}
}

static int zuf_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	zuf_err("should not fault\n");
	return VM_FAULT_SIGBUS;
}

static void zuf_mmap_open(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct zufs_thread *zt = _zt_from_f_private(file);

	zuf_dbg_vfs("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));
	zt->vma = vma;
}

static void zuf_mmap_close(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct zufs_thread *zt = _zt_from_f_private(file);

	zuf_dbg_vfs("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));

	zt->vma = NULL;
}

static const struct vm_operations_struct zuf_vm_ops = {
	.fault		= zuf_file_fault,
	.open           = zuf_mmap_open,
	.close		= zuf_mmap_close,
};

int zuf_zt_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zufs_thread *zt = _zt_from_f_private(file);

	vma->vm_flags |= VM_PFNMAP;
	vma->vm_ops = &zuf_vm_ops;

	zt->vma = vma;

	zuf_dbg_vfs("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}

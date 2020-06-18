// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * mmap operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/pfn_t.h>
#include "zuf.h"

/* ~~~ Functions for mmap and page faults ~~~ */

/* MAP_PRIVATE, copy data to user private page (cow_page) */
static int _cow_private_page(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_mapping->host;
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	int err;

	/* Basically a READ into vmf->cow_page */
	err = zuf_rw_read_page(sbi, inode, vmf->cow_page,
			       md_p2o(vmf->pgoff));
	if (unlikely(err && err != -EINTR)) {
		zuf_err("[%ld] read_page failed @x%lx address=0x%lx => %d\n",
			inode->i_ino, vmf->pgoff, vmf->address, err);
		return VM_FAULT_SIGBUS;
	}

	/*HACK: This is an hack since Kernel v4.7 where a VM_FAULT_LOCKED with
	 * vmf->page==NULL is no longer supported. Looks like for now this way
	 * works well. We let mm mess around with unlocking and putting its own
	 * cow_page.
	 */
	vmf->page = vmf->cow_page;
	get_page(vmf->page);
	lock_page(vmf->page);

	return VM_FAULT_LOCKED;
}

static inline ulong _gb_bn(struct zufs_ioc_IO *get_block)
{
	if (unlikely(!get_block->ziom.iom_n))
		return 0;

	return _zufs_iom_t1_bn(get_block->iom_e[0]);
}

static vm_fault_t zuf_write_fault(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_mapping->host;
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	struct zuf_inode_info *zii = ZUII(inode);
	struct zus_inode *zi = zii->zi;
	ulong bn;
	struct _io_gb_multy io_gb;
	vm_fault_t fault = VM_FAULT_SIGBUS;
	ulong addr = vmf->address;
	ulong pmem_bn;
	pgoff_t size;
	pfn_t pfnt;
	ulong pfn;
	int err;

	zuf_dbg_mmap("[%ld] [@x%lx] vm_start=0x%lx VA=0x%lx vmf_flags=0x%x\n",
		    _zi_ino(zi), vmf->pgoff, vma->vm_start, addr, vmf->flags);

	sb_start_pagefault(inode->i_sb);
	zuf_smr_lock_pagefault(zii);

	size = md_o2p_up(i_size_read(inode));
	if (unlikely(vmf->pgoff >= size)) {
		ulong pgoff = vma->vm_pgoff + md_o2p(addr - vma->vm_start);

		zuf_dbg_err("[%ld] pgoff(@x%lx)(@x%lx) >= size(0x%lx) => SIGBUS\n",
			    _zi_ino(zi), vmf->pgoff, pgoff, size);

		fault = VM_FAULT_SIGBUS;
		goto out;
	}

	if (vmf->cow_page) {
		fault = _cow_private_page(vma, vmf);
		goto out;
	}

	zus_inode_cmtime_now(inode, zi);
	/* NOTE: zus needs to flush the zi */

	zuf_pi_unmap(inode, md_p2o(vmf->pgoff), PAGE_SIZE, EZUF_PIU_AT_wmmap);

	err = zuf_rw_cached_get(sbi, inode, WRITE | ZUFS_RW_MMAP_WRITE, NULL,
				 md_p2o(vmf->pgoff), PAGE_SIZE, &bn, &io_gb);
	if (unlikely(err)) {
		zuf_dbg_err("_get_put_block failed => %d\n", err);
		goto out;
	}
	pmem_bn = _gb_bn(&io_gb.IO);
	if (unlikely(pmem_bn == 0)) {
		zuf_err("[%ld] pmem_bn=0  rw=0x%llx ret_flags=0x%x but no error?\n",
			_zi_ino(zi), io_gb.IO.rw, io_gb.IO.ret_flags);
		fault = VM_FAULT_SIGBUS;
		goto out;
	}

	if (io_gb.IO.ret_flags & ZUFS_RET_NEW) {
		/* newly created block */
		inode->i_blocks = le64_to_cpu(zii->zi->i_blocks);
	}

	pfn = md_pfn(sbi->md, pmem_bn);
	pfnt = phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV);
	fault = vmf_insert_mixed_mkwrite(vma, addr, pfnt);
	err = zuf_flt_to_err(fault);
	if (unlikely(err)) {
		zuf_err("[%ld] vm_insert_mixed_mkwrite failed => fault=0x%x err=%d\n",
			_zi_ino(zi), (int)fault, err);
		goto put;
	}

	zuf_dbg_mmap("[%ld] [@x%lx] vm_insert_mixed 0x%lx pfn=0x%lx prot=0x%lx => %d\n",
		    _zi_ino(zi), vmf->pgoff, pmem_bn, pfn, vma->vm_page_prot.pgprot, err);

	zuf_sync_add(inode);
put:
	zuf_rw_cached_put(sbi, inode, &io_gb);
out:
	zuf_smr_unlock(zii);
	sb_end_pagefault(inode->i_sb);
	return fault;
}

static vm_fault_t zuf_pfn_mkwrite(struct vm_fault *vmf)
{
	return zuf_write_fault(vmf->vma, vmf);
}

static vm_fault_t zuf_read_fault(struct vm_area_struct *vma,
				 struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_mapping->host;
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	struct zuf_inode_info *zii = ZUII(inode);
	struct zus_inode *zi = zii->zi;
	ulong bn;
	struct _io_gb_multy io_gb;
	vm_fault_t fault = VM_FAULT_SIGBUS;
	ulong addr = vmf->address;
	ulong pmem_bn;
	pgoff_t size;
	pfn_t pfnt;
	int err;

	zuf_dbg_mmap("[%ld] [@x%lx] vm_start=0x%lx VA=0x%lx vmf_flags=0x%x\n",
		    _zi_ino(zi), vmf->pgoff, vma->vm_start, addr, vmf->flags);

	zuf_smr_lock_pagefault(zii);

	size = md_o2p_up(i_size_read(inode));
	if (unlikely(vmf->pgoff >= size)) {
		ulong pgoff = vma->vm_pgoff + md_o2p(addr - vma->vm_start);

		zuf_dbg_err("[%ld] pgoff(0x%lx)(0x%lx) >= size(0x%lx) => SIGBUS\n",
			    _zi_ino(zi), vmf->pgoff, pgoff, size);
		goto out;
	}

	if (vmf->cow_page) {
		zuf_warn("cow is read\n");
		fault = _cow_private_page(vma, vmf);
		goto out;
	}

	file_accessed(vma->vm_file);
	/* NOTE: zus needs to flush the zi */

	err = zuf_rw_cached_get(sbi, inode, READ | ZUFS_RW_MMAP,
				 &vma->vm_file->f_ra, md_p2o(vmf->pgoff),
				 PAGE_SIZE, &bn, &io_gb);
	if (unlikely(err && err != -EINTR)) {
		zuf_err("_get_put_block failed => %d\n", err);
		goto out;
	}

	pmem_bn = _gb_bn(&io_gb.IO);
	if (pmem_bn == 0) {
		/* Hole in file */
		pfnt = pfn_to_pfn_t(my_zero_pfn(vmf->address));
	} else {
		/* We have a real page */
		pfnt = phys_to_pfn_t(PFN_PHYS(md_pfn(sbi->md, pmem_bn)),
				     PFN_MAP | PFN_DEV);
	}
	fault = vmf_insert_mixed(vma, addr, pfnt);
	err = zuf_flt_to_err(fault);
	if (unlikely(err)) {
		zuf_err("[%ld] vm_insert_mixed => fault=0x%x err=%d\n",
			_zi_ino(zi), (int)fault, err);
		goto put;
	}

	zuf_dbg_mmap("[%ld] [@x%lx] vm_insert_mixed pmem_bn=0x%lx fault=%d\n",
		     _zi_ino(zi), vmf->pgoff, pmem_bn, fault);

put:
	if (pmem_bn)
		zuf_rw_cached_put(sbi, inode, &io_gb);
out:
	zuf_smr_unlock(zii);
	return fault;
}

static vm_fault_t zuf_fault(struct vm_fault *vmf)
{
	bool write_fault = (0 != (vmf->flags & FAULT_FLAG_WRITE));

	if (write_fault)
		return zuf_write_fault(vmf->vma, vmf);
	else
		return zuf_read_fault(vmf->vma, vmf);
}

static void zuf_mmap_open(struct vm_area_struct *vma)
{
	struct zuf_inode_info *zii = ZUII(file_inode(vma->vm_file));

	atomic_inc(&zii->vma_count);
}

static void zuf_mmap_close(struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(vma->vm_file);
	int vma_count = atomic_dec_return(&ZUII(inode)->vma_count);

	zuf_dbg_mmap("[%ld] start=0x%lx end=0x%lx vma_count=%d\n",
		     vma->vm_file->f_inode->i_ino, vma->vm_start, vma->vm_end,
	             vma_count);

	if (unlikely(vma_count < 0))
		zuf_err("[%ld] WHAT??? vma_count=%d\n",
			 inode->i_ino, vma_count);
	else if (unlikely(vma_count == 0)) {
		struct zuf_inode_info *zii = ZUII(inode);
		struct zufs_ioc_mmap_close mmap_close = {};
		int err;

		mmap_close.hdr.operation = ZUFS_OP_MMAP_CLOSE;
		mmap_close.hdr.in_len = sizeof(mmap_close);

		mmap_close.zus_ii = zii->zus_ii;
		mmap_close.rw = 0; /* TODO: Do we need this */

		zuf_smr_lock(zii);

		err = zufc_dispatch(ZUF_ROOT(SBI(inode->i_sb)), &mmap_close.hdr,
				    NULL, 0);
		if (unlikely(err))
			zuf_dbg_err("[%ld] err=%d\n", inode->i_ino, err);

		zuf_smr_unlock(zii);
	}
}

static const struct vm_operations_struct zuf_vm_ops = {
	.fault		= zuf_fault,
	.pfn_mkwrite	= zuf_pfn_mkwrite,
	.open           = zuf_mmap_open,
	.close		= zuf_mmap_close,
};

int zuf_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct zuf_inode_info *zii = ZUII(inode);

	file_accessed(file);

	vma->vm_ops = &zuf_vm_ops;

	atomic_inc(&zii->vma_count);

	zuf_dbg_mmap("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}

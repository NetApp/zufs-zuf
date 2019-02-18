// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Read/Write operations.
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
		zuf_err("[%ld] read_page failed bn=0x%lx address=0x%lx => %d\n",
			inode->i_ino, vmf->pgoff, vmf->address, err);
		/* FIXME: Probably return VM_FAULT_SIGBUS */
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

int _rw_init_zero_page(struct zuf_inode_info *zii)
{
	if (zii->zero_page)
		return 0;

	zii->zero_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (unlikely(!zii->zero_page))
		return -ENOMEM;
	zii->zero_page->mapping = zii->vfs_inode.i_mapping;
	return 0;
}

static int zuf_write_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
			   bool pfn_mkwrite)
{
	struct inode *inode = vma->vm_file->f_mapping->host;
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	struct zuf_inode_info *zii = ZUII(inode);
	struct zus_inode *zi = zii->zi;
	struct zufs_ioc_IO get_block = {};
	int fault = VM_FAULT_SIGBUS;
	ulong addr = vmf->address;
	pgoff_t size;
	pfn_t pfnt;
	ulong pfn;
	int err;

	zuf_dbg_mmap("[%ld] vm_start=0x%lx vm_end=0x%lx VA=0x%lx "
		    "pgoff=0x%lx vmf_flags=0x%x cow_page=%p page=%p\n",
		    _zi_ino(zi), vma->vm_start, vma->vm_end, addr, vmf->pgoff,
		    vmf->flags, vmf->cow_page, vmf->page);

	if (unlikely(vmf->page && vmf->page != zii->zero_page)) {
		zuf_err("[%ld] vm_start=0x%lx vm_end=0x%lx VA=0x%lx "
			"pgoff=0x%lx vmf_flags=0x%x page=%p cow_page=%p\n",
			_zi_ino(zi), vma->vm_start, vma->vm_end, addr,
			vmf->pgoff, vmf->flags, vmf->page, vmf->cow_page);
		return VM_FAULT_SIGBUS;
	}

	sb_start_pagefault(inode->i_sb);
	zuf_smr_lock_pagefault(zii);

	size = md_o2p_up(i_size_read(inode));
	if (unlikely(vmf->pgoff >= size)) {
		ulong pgoff = vma->vm_pgoff + md_o2p(addr - vma->vm_start);

		zuf_err("[%ld] pgoff(0x%lx)(0x%lx) >= size(0x%lx) => SIGBUS\n",
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

	err = _zuf_get_put_block(sbi, zii, ZUFS_OP_GET_BLOCK, WRITE, vmf->pgoff,
			     &get_block);
	if (unlikely(err)) {
		zuf_dbg_err("_get_put_block failed => %d\n", err);
		goto out;
	}

	if ((get_block.gp_block.ret_flags & ZUFS_GBF_NEW) || !pfn_mkwrite) {
		inode->i_blocks = le64_to_cpu(zii->zi->i_blocks);
		/* newly created block */
		unmap_mapping_range(inode->i_mapping, vmf->pgoff << PAGE_SHIFT,
				    PAGE_SIZE, 0);
	} else if (pfn_mkwrite) {
		/* If the block did not change just tell mm to flip
		 * the write bit
		 */
		fault = VM_FAULT_WRITE;
		goto skip_insert;
	}

	if (unlikely(get_block.gp_block.pmem_bn == 0)) {
		zuf_err("[%ld] pmem_bn=0  rw=0x%x ret_flags=0x%x priv=0x%lx but no error?\n",
			_zi_ino(zi), get_block.gp_block.rw,
			get_block.gp_block.ret_flags,
			(ulong)get_block.gp_block.priv);
		fault = VM_FAULT_SIGBUS;
		goto out;
	}

	pfn = md_pfn(sbi->md, get_block.gp_block.pmem_bn);
	pfnt = phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV);
	fault = vmf_insert_mixed_mkwrite(vma, addr, pfnt);
	err = zuf_flt_to_err(fault);
	if (unlikely(err)) {
		zuf_err("vm_insert_mixed_mkwrite failed => %d\n", err);
		goto put;
	}

	zuf_dbg_mmap("[%ld] vm_insert_mixed 0x%lx prot=0x%lx => %d\n",
		    _zi_ino(zi), pfn, vma->vm_page_prot.pgprot, err);

skip_insert:
	zuf_sync_inc(inode);
put:
	_zuf_get_put_block(sbi, zii, ZUFS_OP_PUT_BLOCK, WRITE, vmf->pgoff,
			     &get_block);
out:
	zuf_smr_unlock(zii);
	sb_end_pagefault(inode->i_sb);
	return fault;
}

static int zuf_pfn_mkwrite(struct vm_fault *vmf)
{
	return zuf_write_fault(vmf->vma, vmf, true);
}

static int zuf_read_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_mapping->host;
	struct zuf_sb_info *sbi = SBI(inode->i_sb);
	struct zuf_inode_info *zii = ZUII(inode);
	struct zus_inode *zi = zii->zi;
	struct zufs_ioc_IO get_block = {};
	int fault = VM_FAULT_SIGBUS;
	ulong addr = vmf->address;
	pgoff_t size;
	pfn_t pfnt;
	ulong pfn;
	int err;

	zuf_dbg_mmap("[%ld] vm_start=0x%lx vm_end=0x%lx VA=0x%lx "
		    "pgoff=0x%lx vmf_flags=0x%x cow_page=%p page=%p\n",
		    _zi_ino(zi), vma->vm_start, vma->vm_end, addr, vmf->pgoff,
		    vmf->flags, vmf->cow_page, vmf->page);

	zuf_smr_lock_pagefault(zii);

	size = md_o2p_up(i_size_read(inode));
	if (unlikely(vmf->pgoff >= size)) {
		ulong pgoff = vma->vm_pgoff + md_o2p(addr - vma->vm_start);

		zuf_err("[%ld] pgoff(0x%lx)(0x%lx) >= size(0x%lx) => SIGBUS\n",
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

	err = _zuf_get_put_block(sbi, zii, ZUFS_OP_GET_BLOCK, READ, vmf->pgoff,
			     &get_block);
	if (unlikely(err && err != -EINTR)) {
		zuf_err("_get_put_block failed => %d\n", err);
		goto out;
	}

	if (get_block.gp_block.pmem_bn == 0) {
		/* Hole in file */
		err = _rw_init_zero_page(zii);
		if (unlikely(err))
			goto out;

		err = vm_insert_page(vma, addr, zii->zero_page);
		zuf_dbg_mmap("[%ld] inserted zero\n", _zi_ino(zi));

		/* NOTE: we are fooling mm, we do not need this page
		 * to be locked and get(ed)
		 */
		fault = VM_FAULT_NOPAGE;
		goto out;
	}

	/* We have a real page */
	pfn = md_pfn(sbi->md, get_block.gp_block.pmem_bn);
	pfnt = phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV);
	fault = vmf_insert_mixed(vma, addr, pfnt);
	err = zuf_flt_to_err(fault);
	if (unlikely(err)) {
		zuf_err("[%ld] vm_insert_page/mixed => %d\n", _zi_ino(zi), err);
		goto put;
	}

	zuf_dbg_mmap("[%ld] vm_insert_mixed 0x%lx prot=0x%lx => %d\n",
		    _zi_ino(zi), pfn, vma->vm_page_prot.pgprot, err);

put:
	_zuf_get_put_block(sbi, zii, ZUFS_OP_PUT_BLOCK, READ, vmf->pgoff,
		       &get_block);
out:
	zuf_smr_unlock(zii);
	return fault;
}

static int zuf_fault(struct vm_fault *vmf)
{
	bool write_fault = (0 != (vmf->flags & FAULT_FLAG_WRITE));

	if (write_fault)
		return zuf_write_fault(vmf->vma, vmf, false);
	else
		return zuf_read_fault(vmf->vma, vmf);
}

static int zuf_page_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = vma->vm_file->f_mapping->host;
	ulong addr = vmf->address;

	/* our zero page doesn't really hold the correct offset to the file in
	 * page->index so vmf->pgoff is incorrect, lets fix that
	 */
	vmf->pgoff = vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT);

	zuf_dbg_mmap("[%ld] pgoff=0x%lx\n", inode->i_ino, vmf->pgoff);

	/* call fault handler to get a real page for writing */
	return zuf_write_fault(vma, vmf, false);
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
	.page_mkwrite	= zuf_page_mkwrite,
	.pfn_mkwrite	= zuf_pfn_mkwrite,
	.open           = zuf_mmap_open,
	.close		= zuf_mmap_close,
};

int zuf_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct zuf_inode_info *zii = ZUII(inode);

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP;
	vma->vm_ops = &zuf_vm_ops;

	atomic_inc(&zii->vma_count);

	zuf_dbg_vfs("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}

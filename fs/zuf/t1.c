/*
 * BRIEF DESCRIPTION
 *
 * Just the special mmap of the all t1 array to the ZUS Server
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/pfn_t.h>
#include <asm/pgtable.h>

#include "zuf.h"

/* ~~~ Functions for mmap a t1-array and page faults ~~~ */
struct zuf_pmem *_pmem_from_f_private(struct file *file)
{
	struct zuf_special_file *zsf = file->private_data;

	WARN_ON(zsf->type != zlfs_e_pmem);
	return container_of(zsf, struct zuf_pmem, hdr);
}

static int t1_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_mapping->host;
	struct zuf_pmem *z_pmem;
	pgoff_t size;
	pgprot_t prot = vma->vm_page_prot;
	ulong bn = vmf->pgoff;
	ulong pfn;
	int err, ret;

	zuf_dbg_t1("[%ld] vm_start=0x%lx vm_end=0x%lx VA=%p "
		    "pgoff=0x%lx vmf_flags=0x%x cow_page=%p page=%p\n",
		    inode->i_ino, vma->vm_start, vma->vm_end,
		    vmf->virtual_address, vmf->pgoff, vmf->flags,
		    vmf->cow_page, vmf->page);

	if (unlikely(vmf->page)) {
		zuf_err("[%ld] vm_start=0x%lx vm_end=0x%lx VA=%p "
			"pgoff=0x%lx vmf_flags=0x%x page=%p cow_page=%p\n",
			inode->i_ino, vma->vm_start, vma->vm_end,
			vmf->virtual_address, vmf->pgoff, vmf->flags,
			vmf->page, vmf->cow_page);
		return VM_FAULT_SIGBUS;
	}

	size = zuf_o2p_up(i_size_read(inode));
	if (unlikely(vmf->pgoff >= size)) {
		ulong pgoff = vma->vm_pgoff + zuf_o2p(
			((ulong)vmf->virtual_address - vma->vm_start));

		zuf_err("[%ld] pgoff(0x%lx)(0x%lx) >= size(0x%lx) => SIGBUS\n",
			 inode->i_ino, vmf->pgoff, pgoff, size);

		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	if (vmf->cow_page) {
		/* HOWTO: prevent private mmaps */
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	z_pmem = _pmem_from_f_private(vma->vm_file);
	pfn = md_pfn(&z_pmem->md, bn);

	prot = pgprot_modify(prot, PAGE_SHARED);
	err = vm_insert_mixed_prot(vma, (ulong)vmf->virtual_address,
				phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV),
				prot);
	zuf_dbg_rw("[%ld] vm_insert_mixed 0x%lx prot=0x%lx => %d\n",
		    inode->i_ino, pfn, vma->vm_page_prot.pgprot, err);

	if (err == -ENOMEM){
		zuf_err("[%ld] vm_insert_page/mixed => ENOMEM\n",
			    inode->i_ino);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	/*
	 * err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (err != -EBUSY)
		BUG_ON(err);
	ret = VM_FAULT_NOPAGE;
out:
	return ret;
}

static const struct vm_operations_struct t1_vm_ops = {
	.fault		= t1_file_fault,
};

int zuf_pmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zuf_special_file *zsf = file->private_data;

	if (!zsf || zsf->type != zlfs_e_pmem)
		return -EPERM;


	/* FIXME:  MIXEDMAP for the support of pmem-pages (Why?)
	 */
	vma->vm_flags |= VM_MIXEDMAP;
	vma->vm_ops = &t1_vm_ops;

	zuf_dbg_vfs("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}


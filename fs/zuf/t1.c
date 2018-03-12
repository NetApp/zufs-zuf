// SPDX-License-Identifier: GPL-2.0
/*
 * BRIEF DESCRIPTION
 *
 * Just the special mmap of the all t1 array to the ZUS Server
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/pfn_t.h>
#include <asm/pgtable.h>

#include "_pr.h"
#include "zuf.h"

/* ~~~ Functions for mmap a t1-array and page faults ~~~ */
static struct zuf_pmem_file *_pmem_from_f_private(struct file *file)
{
	struct zuf_special_file *zsf = file->private_data;

	WARN_ON(zsf->type != zlfs_e_pmem);
	return container_of(zsf, struct zuf_pmem_file, hdr);
}

static vm_fault_t t1_fault(struct vm_fault *vmf, enum page_entry_size pe_size)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = vma->vm_file->f_mapping->host;
	ulong addr = vmf->address;
	struct zuf_pmem_file *z_pmem;
	pgoff_t size;
	ulong bn;
	pfn_t pfnt;
	ulong pfn = 0;
	vm_fault_t flt;

	zuf_dbg_t1("[%ld] vm_start=0x%lx vm_end=0x%lx VA=0x%lx "
		    "pgoff=0x%lx vmf_flags=0x%x cow_page=%p page=%p pe_size=%d\n",
		    inode->i_ino, vma->vm_start, vma->vm_end, addr, vmf->pgoff,
		    vmf->flags, vmf->cow_page, vmf->page, pe_size);

	if (unlikely(vmf->page)) {
		zuf_err("[%ld] vm_start=0x%lx vm_end=0x%lx VA=0x%lx "
			"pgoff=0x%lx vmf_flags=0x%x page=%p cow_page=%p\n",
			inode->i_ino, vma->vm_start, vma->vm_end, addr,
			vmf->pgoff, vmf->flags, vmf->page, vmf->cow_page);
		return VM_FAULT_SIGBUS;
	}

	size = md_o2p_up(i_size_read(inode));
	if (unlikely(vmf->pgoff >= size)) {
		ulong pgoff = vma->vm_pgoff + md_o2p(addr - vma->vm_start);

		zuf_err("[%ld] pgoff(0x%lx)(0x%lx) >= size(0x%lx) => SIGBUS\n",
			 inode->i_ino, vmf->pgoff, pgoff, size);

		return VM_FAULT_SIGBUS;
	}

	if (vmf->cow_page)
		/* HOWTO: prevent private mmaps */
		return VM_FAULT_SIGBUS;

	z_pmem = _pmem_from_f_private(vma->vm_file);

	switch (pe_size) {
	case PE_SIZE_PTE:
		zuf_err("[%ld] PTE fault not expected pgoff=0x%lx addr=0x%lx\n",
			inode->i_ino, vmf->pgoff, addr);
		/* Always PMD insert 2M chunks */
		/* fall through */
	case PE_SIZE_PMD:
		bn = linear_page_index(vma, addr & PMD_MASK);
		pfn = md_pfn(z_pmem->md, bn);
		pfnt = phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV);
		flt = vmf_insert_pfn_pmd(vmf, pfnt, true);
		zuf_dbg_t1("[%ld] PMD pfn-0x%lx addr=0x%lx bn=0x%lx pgoff=0x%lx => %d\n",
			inode->i_ino, pfn, addr, bn, vmf->pgoff, flt);
		break;
	default:
		/* FIXME: Easily support PE_SIZE_PUD Just needs to align to
		 * PUD_MASK at zufr_get_unmapped_area(). But this is hard today
		 * because of the 2M nvdimm lib takes for its page flag
		 * information with NFIT. (That need not be there in any which
		 * case.)
		 * Which means zufr_get_unmapped_area needs to return
		 * a align1G+2M address start. and first 1G is map PMD size.
		 * Very ugly, sigh.
		 * One thing I do not understand why when the vma->vm_start is
		 * not PUD aligned and faults requests index zero. Then system
		 * asks for PE_SIZE_PUD anyway. say my 0 index is 1G aligned
		 * vmf_insert_pfn_pud() will always fail because the aligned
		 * vm_addr is outside the vma.
		 */
		flt = VM_FAULT_FALLBACK;
		zuf_dbg_t1("[%ld] default? pgoff=0x%lx addr=0x%lx pe_size=0x%x => %d\n",
			   inode->i_ino, vmf->pgoff, addr, pe_size, flt);
	}

	return flt;
}

static vm_fault_t t1_fault_pte(struct vm_fault *vmf)
{
	return t1_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct t1_vm_ops = {
	.huge_fault	= t1_fault,
	.fault		= t1_fault_pte,
};

int zuf_pmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zuf_special_file *zsf = file->private_data;

	if (!zsf || zsf->type != zlfs_e_pmem)
		return -EPERM;

	vma->vm_flags |= VM_HUGEPAGE;
	vma->vm_ops = &t1_vm_ops;

	zuf_dbg_vfs("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}


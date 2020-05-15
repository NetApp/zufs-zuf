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
#include <linux/vmalloc.h>
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

/* Num pages including Shadow */
static inline ulong  _pmem_blocks(struct file *file)
{
	return md_o2p_up(i_size_read(file->f_inode));
}

static inline ulong _zpages_bytes(struct zuf_pmem_file *z_pmem)
{
	return ALIGN(md_t1_blocks(z_pmem->md) * sizeof(struct zus_page),
		     PAGE_SIZE);
}

static inline ulong _zpages_pgstart(struct zuf_pmem_file *z_pmem)
{
	return _pmem_blocks(z_pmem->hdr.file) + PAGES_IN_2M;
}

static vm_fault_t t1_fault(struct vm_fault *vmf, enum page_entry_size pe_size)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = vma->vm_file->f_mapping->host;
	ulong addr = vmf->address;
	struct zuf_pmem_file *z_pmem;
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

	if (unlikely(vmf->pgoff >= _pmem_blocks(vma->vm_file))) {
		ulong pgoff = vma->vm_pgoff + md_o2p(addr - vma->vm_start);

		zuf_err("[%ld] pgoff(0x%lx)(0x%lx) >= size(0x%lx) => SIGBUS\n",
			 inode->i_ino, vmf->pgoff, pgoff,
			 _pmem_blocks(vma->vm_file));

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

static vm_fault_t _zpages_fault (struct vm_fault *vmf)
{
	struct zuf_pmem_file *z_pmem = _pmem_from_f_private(vmf->vma->vm_file);
	ulong offset, zpages_size;

	if (vmf->cow_page) {
		/* No private mmaps crash the user */
		zuf_err("No Private mmaps of zpages_mmap\n");
		return VM_FAULT_SIGBUS;
	}

	/* NOTE: Server must map a 2M aligned mmap-space
	 * But only the exact amount of pages are allocated.
	 * On an overrun we crash the Server
	 */
	zpages_size = _zpages_bytes(z_pmem);
	if (unlikely(md_o2p(zpages_size) <
		     (vmf->vma->vm_pgoff - _zpages_pgstart(z_pmem)))) {
		zuf_err("Overrun of zpages array 0x%lx < 0x%lx\n",
			zpages_size, vmf->vma->vm_pgoff);
		return VM_FAULT_SIGBUS;
	}
	
	/* This faults only once at very first access
	 * TODO: Fault only 2M at a time
	 */
	for (offset = 0; offset < zpages_size; offset += PAGE_SIZE) {
		ulong addr = vmf->vma->vm_start + offset;
		ulong pfn = vmalloc_to_pfn((void *)z_pmem->zpages +  offset);
		pfn_t pfnt = phys_to_pfn_t(PFN_PHYS(pfn), PFN_MAP | PFN_DEV);
		vm_fault_t flt;

		zuf_dbg_verbose("[0x%lx] pfn-0x%lx addr=0x%lx\n",
				offset, pfn, addr);

		flt = vmf_insert_mixed_mkwrite(vmf->vma, addr, pfnt);
		if (unlikely(flt != VM_FAULT_NOPAGE)) {
			zuf_err("zuf: zuf_insert_mixed_mkwrite => %d offset=0x%lx addr=0x%lx\n",
				 flt, offset, addr);
			return flt;
		}
	}

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct t1_zpages_ops = {
	.fault	= _zpages_fault
};

int _zpages_mmap (struct zuf_pmem_file *z_pmem, struct vm_area_struct *vma)
{
	ulong zpages_size = _zpages_bytes(z_pmem);
	BUILD_BUG_ON(sizeof(struct zus_page) != 64);

	/* TODO: Allocate each pmem's zpages from the node-id the pmem belongs
	 * to.
	 */
	z_pmem->zpages = vzalloc(zpages_size);
	if (unlikely(!z_pmem->zpages)) {
		zuf_err("pas=0x%lx t1_blocks=0x%lx\n",
			zpages_size, md_t1_blocks(z_pmem->md));
		return -ENOMEM;
	}

	vma->vm_flags |= VM_PFNMAP;
	vma->vm_ops = &t1_zpages_ops;

	zuf_dbg_vfs("[%ld] pgoff=0x%lx len=0x%lx zpages_size=0x%lx\n",
		    vma->vm_file->f_inode->i_ino, vma->vm_pgoff,
		    vma->vm_end - vma->vm_start, zpages_size);

	return 0;
}

int zuf_pmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zuf_pmem_file *z_pmem = file->private_data;

	if (!z_pmem || z_pmem->hdr.type != zlfs_e_pmem)
		return -EPERM;

	/* Valgrined may interfere with our 2M mmap aligned vma start
	 * (See zufr_get_unmapped_area). Tell the guys to back off
	 * Also the zpages_mmap must be 2M aligned. See _zpages_fault note.
	 */
	if (unlikely(vma->vm_start & ~PMD_MASK)) {
		zuf_err("mmap is not 2M aligned vm_start=0x%lx\n",
				vma->vm_start);
		return -EINVAL;
	}

	/* We have two areas of mmap in this special file.
	 * From 0 to t1_size (including shadow):
	 *	This part gives access to the full t1 range.
	 * From t1_size + 2M of size md_t1_blocks * sizeof(zus_page)
	 *	This gives access to the shared zus_page structs per
	 *	T1 page that coordinate access to data between Server
	 *	and Kernel.
	 * NOTE: The inaccessible 2M hole between the two ranges, it is
	 *	so rogue users of pmem do not overwrite the zus_pages, and
	 * 	should just crash.
	 */
	if (vma->vm_pgoff == _zpages_pgstart(z_pmem))
		return _zpages_mmap(z_pmem, vma);

	/* map the t1 range to user-mode Server */

	/* User must map the all range from 0 to i_size_read() */
	if (unlikely(vma->vm_pgoff))
		return -EINVAL;

	vma->vm_flags |= VM_HUGEPAGE;
	vma->vm_ops = &t1_vm_ops;

	zuf_dbg_vfs("[%ld] start=0x%lx end=0x%lx flags=0x%lx page_prot=0x%lx\n",
		     file->f_mapping->host->i_ino, vma->vm_start, vma->vm_end,
		     vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}

void zuf_pmem_release(struct file *file)
{
	struct zuf_pmem_file *z_pmem = file->private_data;

	if (!z_pmem || z_pmem->hdr.type != zlfs_e_pmem)
		return;

	vfree(z_pmem->zpages);
	z_pmem->zpages = NULL;
}

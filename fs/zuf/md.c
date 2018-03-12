// SPDX-License-Identifier: GPL-2.0
/*
 * Multi-Device operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#include <linux/blkdev.h>
#include <linux/pfn_t.h>
#include <linux/crc16.h>
#include <linux/uuid.h>

#include <linux/gcd.h>

#include "_pr.h"
#include "md.h"
#include "t2.h"

const fmode_t _g_mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

static int _bdev_get_by_path(const char *path, struct block_device **bdev,
			     void *holder)
{
	*bdev = blkdev_get_by_path(path, _g_mode, holder);
	if (IS_ERR(*bdev)) {
		int err = PTR_ERR(*bdev);
		*bdev = NULL;
		return err;
	}
	return 0;
}

static void _bdev_put(struct block_device **bdev)
{
	if (*bdev) {
		blkdev_put(*bdev, _g_mode);
		*bdev = NULL;
	}
}

/* convert uuid to a /dev/ path */
static char *_uuid_path(uuid_le *uuid, char path[PATH_UUID])
{
	sprintf(path, "/dev/disk/by-uuid/%pUb", uuid);
	return path;
}

static int _bdev_get_by_uuid(struct block_device **bdev, uuid_le *uuid,
			       void *holder, bool silent)
{
	char path[PATH_UUID];
	int err;

	_uuid_path(uuid, path);
	err = _bdev_get_by_path(path, bdev, holder);
	if (unlikely(err))
		md_err_cnd(silent, "failed to get device path=%s =>%d\n",
			   path, err);

	return err;
}

short md_calc_csum(struct md_dev_table *mdt)
{
	uint n = MDT_STATIC_SIZE(mdt) - sizeof(mdt->s_sum);

	return crc16(~0, (__u8 *)&mdt->s_version, n);
}

/* ~~~~~~~ mdt related functions ~~~~~~~ */

int md_t2_mdt_read(struct multi_devices *md, int index,
		   struct md_dev_table *mdt)
{
	int err = t2_readpage(md, index, virt_to_page(mdt));

	if (err)
		md_dbg_verbose("!!! t2_readpage err=%d\n", err);

	return err;
}

static int _t2_mdt_read(struct block_device *bdev, struct md_dev_table *mdt)
{
	int err;
	/* t2 interface works for all block devices */
	struct multi_devices *md;
	struct md_dev_info *mdi;

	md = kzalloc(sizeof(*md), GFP_KERNEL);
	if (unlikely(!md))
		return -ENOMEM;

	md->t2_count = 1;
	md->devs[0].bdev = bdev;
	mdi = &md->devs[0];
	md->t2a.map = &mdi;
	md->t2a.bn_gcd = 1; /*Does not matter only must not be zero */

	err = md_t2_mdt_read(md, 0, mdt);

	kfree(md);
	return err;
}

int md_t2_mdt_write(struct multi_devices *md, struct md_dev_table *mdt)
{
	int i, err = 0;

	for (i = 0; i < md->t2_count; ++i) {
		ulong bn = md_o2p(md_t2_dev(md, i)->offset);

		mdt->s_dev_list.id_index = mdt->s_dev_list.t1_count + i;
		mdt->s_sum = cpu_to_le16(md_calc_csum(mdt));

		err = t2_writepage(md, bn, virt_to_page(mdt));
		if (err)
			md_dbg_verbose("!!! t2_writepage err=%d\n", err);
	}

	return err;
}

static bool _csum_mismatch(struct md_dev_table *mdt, int silent)
{
	ushort crc = md_calc_csum(mdt);

	if (mdt->s_sum == cpu_to_le16(crc))
		return false;

	md_warn_cnd(silent, "expected(0x%x) != s_sum(0x%x)\n",
		      cpu_to_le16(crc), mdt->s_sum);
	return true;
}

static bool _uuid_le_equal(uuid_le *uuid1, uuid_le *uuid2)
{
	return (memcmp(uuid1, uuid2, sizeof(uuid_le)) == 0);
}

static bool _mdt_compare_uuids(struct md_dev_table *mdt,
			       struct md_dev_table *main_mdt, int silent)
{
	int i, dev_count;

	if (!_uuid_le_equal(&mdt->s_uuid, &main_mdt->s_uuid)) {
		md_warn_cnd(silent, "mdt uuid (%pUb != %pUb) mismatch\n",
			      &mdt->s_uuid, &main_mdt->s_uuid);
		return false;
	}

	dev_count = mdt->s_dev_list.t1_count + mdt->s_dev_list.t2_count +
		    mdt->s_dev_list.rmem_count;
	for (i = 0; i < dev_count; ++i) {
		struct md_dev_id *dev_id1 = &mdt->s_dev_list.dev_ids[i];
		struct md_dev_id *dev_id2 = &main_mdt->s_dev_list.dev_ids[i];

		if (!_uuid_le_equal(&dev_id1->uuid, &dev_id2->uuid)) {
			md_warn_cnd(silent,
				    "mdt dev %d uuid (%pUb != %pUb) mismatch\n",
				    i, &dev_id1->uuid, &dev_id2->uuid);
			return false;
		}

		if (dev_id1->blocks != dev_id2->blocks) {
			md_warn_cnd(silent,
				    "mdt dev %d blocks (0x%llx != 0x%llx) mismatch\n",
				    i, le64_to_cpu(dev_id1->blocks),
				    le64_to_cpu(dev_id2->blocks));
			return false;
		}
	}

	return true;
}

bool md_mdt_check(struct md_dev_table *mdt,
		  struct md_dev_table *main_mdt, struct block_device *bdev,
		  struct mdt_check *mc)
{
	struct md_dev_id *dev_id;
	ulong bdev_size, super_size;

	BUILD_BUG_ON(MDT_STATIC_SIZE(mdt) & (SMP_CACHE_BYTES - 1));

	/* Do sanity checks on the superblock */
	if (le32_to_cpu(mdt->s_magic) != mc->magic) {
		md_warn_cnd(mc->silent,
			     "Magic error in super block: please run fsck\n");
		return false;
	}

	if ((mc->major_ver != mdt_major_version(mdt)) ||
	    (mc->minor_ver < mdt_minor_version(mdt))) {
		md_warn_cnd(mc->silent,
			     "mkfs-mount versions mismatch! %d.%d != %d.%d\n",
			     mdt_major_version(mdt), mdt_minor_version(mdt),
			     mc->major_ver, mc->minor_ver);
		return false;
	}

	if (_csum_mismatch(mdt, mc->silent)) {
		md_warn_cnd(mc->silent,
			    "crc16 error in super block: please run fsck\n");
		return false;
	}

	if (main_mdt) {
		if (mdt->s_dev_list.t1_count != main_mdt->s_dev_list.t1_count) {
			md_warn_cnd(mc->silent, "mdt t1 count mismatch\n");
			return false;
		}

		if (mdt->s_dev_list.t2_count != main_mdt->s_dev_list.t2_count) {
			md_warn_cnd(mc->silent, "mdt t2 count mismatch\n");
			return false;
		}

		if (mdt->s_dev_list.rmem_count !=
		    main_mdt->s_dev_list.rmem_count) {
			md_warn_cnd(mc->silent,
				    "mdt rmem dev count mismatch\n");
			return false;
		}

		if (!_mdt_compare_uuids(mdt, main_mdt, mc->silent))
			return false;
	}

	/* check alignment */
	dev_id = &mdt->s_dev_list.dev_ids[mdt->s_dev_list.id_index];
	super_size = md_p2o(__dev_id_blocks(dev_id));
	if (unlikely(!super_size || super_size & mc->alloc_mask)) {
		md_warn_cnd(mc->silent, "super_size(0x%lx) ! 2_M aligned\n",
			      super_size);
		return false;
	}

	if (!bdev)
		return true;

	/* check t1 device size */
	bdev_size = i_size_read(bdev->bd_inode);
	if (unlikely(super_size > bdev_size)) {
		md_warn_cnd(mc->silent,
			    "bdev_size(0x%lx) too small expected 0x%lx\n",
			    bdev_size, super_size);
		return false;
	} else if (unlikely(super_size < bdev_size)) {
		md_dbg_err("Note mdt->size=(0x%lx) < bdev_size(0x%lx)\n",
			      super_size, bdev_size);
	}

	return true;
}

int md_set_sb(struct multi_devices *md, struct block_device *s_bdev,
	      void *sb, int silent)
{
	struct md_dev_info *main_mdi = md_dev_info(md, md->dev_index);
	int i;

	main_mdi->bdev = s_bdev;

	for (i = 0; i < md->t1_count + md->t2_count; ++i) {
		struct md_dev_info *mdi;

		if (i == md->dev_index)
			continue;

		mdi = md_dev_info(md, i);
		if (mdi->bdev->bd_super && (mdi->bdev->bd_super != sb)) {
			md_warn_cnd(silent,
				"!!! %s already mounted on a different FS => -EBUSY\n",
				_bdev_name(mdi->bdev));
			return -EBUSY;
		}

		mdi->bdev->bd_super = sb;
	}

	return 0;
}

void md_fini(struct multi_devices *md, bool put_all)
{
	struct md_dev_info *main_mdi;
	int i;

	if (unlikely(!md))
		return;

	main_mdi = md_dev_info(md, md->dev_index);
	kfree(md->t2a.map);
	kfree(md->t1a.map);

	for (i = 0; i < md->t1_count + md->t2_count; ++i) {
		struct md_dev_info *mdi = md_dev_info(md, i);

		if (i < md->t1_count)
			md_t1_info_fini(mdi);
		if (!mdi->bdev || i == md->dev_index)
			continue;
		mdi->bdev->bd_super = NULL;
		_bdev_put(&mdi->bdev);
	}

	if (put_all)
		_bdev_put(&main_mdi->bdev);
	else
		/* Main dev is GET && PUT by VFS. Only stop pointing to it */
		main_mdi->bdev = NULL;

	kfree(md);
}


/* ~~~~~~~ Pre-mount operations ~~~~~~~ */

static int _get_device(struct block_device **bdev, const char *dev_name,
		       uuid_le *uuid, void *holder, int silent,
		       bool *bind_mount)
{
	int err;

	if (dev_name)
		err = _bdev_get_by_path(dev_name, bdev, holder);
	else
		err = _bdev_get_by_uuid(bdev, uuid, holder, silent);

	if (unlikely(err)) {
		md_err_cnd(silent,
			"failed to get device dev_name=%s uuid=%pUb err=%d\n",
			dev_name, uuid, err);
		return err;
	}

	if (bind_mount &&  (*bdev)->bd_super &&
			   (*bdev)->bd_super->s_bdev == *bdev)
		*bind_mount = true;

	return 0;
}

static int _init_dev_info(struct md_dev_info *mdi, struct md_dev_id *id,
			  int index, u64 offset,
			  struct md_dev_table *main_mdt,
			  struct mdt_check *mc, bool t1_dev,
			  int silent)
{
	struct md_dev_table *mdt = NULL;
	bool mdt_alloc = false;
	int err = 0;

	if (mdi->bdev == NULL) {
		err = _get_device(&mdi->bdev, NULL, &id->uuid, mc->holder,
				  silent, NULL);
		if (unlikely(err))
			return err;
	}

	mdi->offset = offset;
	mdi->size = md_p2o(__dev_id_blocks(id));
	mdi->index = index;

	if (t1_dev) {
		struct page *dev_page;
		int end_of_dev_nid;

		err = md_t1_info_init(mdi, silent);
		if (unlikely(err))
			return err;

		if ((ulong)mdi->t1i.virt_addr & mc->alloc_mask) {
			md_warn_cnd(silent, "!!! unaligned device %s\n",
				      _bdev_name(mdi->bdev));
			return -EINVAL;
		}

		if (!__pfn_to_section(mdi->t1i.phys_pfn)) {
			md_err_cnd(silent, "Intel does not like pages...\n");
			return -EINVAL;
		}

		mdt = mdi->t1i.virt_addr;

		mdi->t1i.pgmap = virt_to_page(mdt)->pgmap;
		dev_page = pfn_to_page(mdi->t1i.phys_pfn);
		mdi->nid = page_to_nid(dev_page);
		end_of_dev_nid = page_to_nid(dev_page + md_o2p(mdi->size - 1));

		if (mdi->nid != end_of_dev_nid)
			md_warn("pmem crosses NUMA boundaries");
	} else {
		mdt = (void *)__get_free_page(GFP_KERNEL);
		if (unlikely(!mdt)) {
			md_dbg_err("!!! failed to alloc page\n");
			return -ENOMEM;
		}

		mdt_alloc = true;
		err = _t2_mdt_read(mdi->bdev, mdt);
		if (unlikely(err)) {
			md_err_cnd(silent, "failed to read mdt from t2 => %d\n",
				   err);
			goto out;
		}
		mdi->nid = __dev_id_nid(id);
	}

	if (!md_mdt_check(mdt, main_mdt, mdi->bdev, mc)) {
		md_err_cnd(silent, "device %s failed integrity check\n",
			     _bdev_name(mdi->bdev));
		err = -EINVAL;
		goto out;
	}

	return 0;

out:
	if (mdt_alloc)
		free_page((ulong)mdt);
	return err;
}

static int _map_setup(struct multi_devices *md, ulong blocks, int dev_start,
		      struct md_dev_larray *larray)
{
	ulong map_size, bn_end;
	int i, dev_index = dev_start;

	map_size = blocks / larray->bn_gcd;
	larray->map = kcalloc(map_size, sizeof(*larray->map), GFP_KERNEL);
	if (!larray->map) {
		md_dbg_err("failed to allocate dev map\n");
		return -ENOMEM;
	}

	bn_end = md_o2p(md->devs[dev_index].size);
	for (i = 0; i < map_size; ++i) {
		if ((i * larray->bn_gcd) >= bn_end)
			bn_end += md_o2p(md->devs[++dev_index].size);
		larray->map[i] = &md->devs[dev_index];
	}

	return 0;
}

static int _md_init(struct multi_devices *md, struct mdt_check *mc,
		    struct md_dev_list *dev_list, int silent)
{
	struct md_dev_table *main_mdt = NULL;
	u64 total_size = 0;
	int i, err;

	for (i = 0; i < md->t1_count; ++i) {
		struct md_dev_info *mdi = md_t1_dev(md, i);
		struct md_dev_table *dev_mdt;

		err = _init_dev_info(mdi, &dev_list->dev_ids[i], i, total_size,
				     main_mdt, mc, true, silent);
		if (unlikely(err))
			return err;

		/* apparently gcd(0,X)=X which is nice */
		md->t1a.bn_gcd = gcd(md->t1a.bn_gcd, md_o2p(mdi->size));
		total_size += mdi->size;

		dev_mdt = md_t1_addr(md, i);
		if (!main_mdt)
			main_mdt = dev_mdt;

		if (mdt_test_option(dev_mdt, MDT_F_SHADOW))
			memcpy(mdi->t1i.virt_addr,
			       mdi->t1i.virt_addr + mdi->size, mdi->size);

		md_dbg_verbose("dev=%d %pUb %s v=%p pfn=%lu off=%lu size=%lu\n",
				 i, &dev_list->dev_ids[i].uuid,
				 _bdev_name(mdi->bdev), dev_mdt,
				 mdi->t1i.phys_pfn, mdi->offset, mdi->size);
	}

	md->t1_blocks = le64_to_cpu(main_mdt->s_t1_blocks);
	if (unlikely(md->t1_blocks != md_o2p(total_size))) {
		md_err_cnd(silent,
			"FS corrupted md->t1_blocks(0x%lx) != total_size(0x%llx)\n",
			md->t1_blocks, total_size);
		return -EIO;
	}

	err = _map_setup(md, le64_to_cpu(main_mdt->s_t1_blocks), 0, &md->t1a);
	if (unlikely(err))
		return err;

	md_dbg_verbose("t1 devices=%d total_size=0x%llx segment_map=0x%lx\n",
			 md->t1_count, total_size,
			 md_o2p(total_size) / md->t1a.bn_gcd);

	if (md->t2_count == 0)
		return 0;

	/* Done with t1. Counting t2s */
	total_size = 0;
	for (i = 0; i < md->t2_count; ++i) {
		struct md_dev_info *mdi = md_t2_dev(md, i);

		err = _init_dev_info(mdi, &dev_list->dev_ids[md->t1_count + i],
				     md->t1_count + i, total_size, main_mdt,
				     mc, false, silent);
		if (unlikely(err))
			return err;

		/* apparently gcd(0,X)=X which is nice */
		md->t2a.bn_gcd = gcd(md->t2a.bn_gcd, md_o2p(mdi->size));
		total_size += mdi->size;

		md_dbg_verbose("dev=%d %s off=%lu size=%lu\n", i,
				 _bdev_name(mdi->bdev), mdi->offset, mdi->size);
	}

	md->t2_blocks = le64_to_cpu(main_mdt->s_t2_blocks);
	if (unlikely(md->t2_blocks != md_o2p(total_size))) {
		md_err_cnd(silent,
			"FS corrupted md->t2_blocks(0x%lx) != total_size(0x%llx)\n",
			md->t2_blocks, total_size);
		return -EIO;
	}

	err = _map_setup(md, le64_to_cpu(main_mdt->s_t2_blocks), md->t1_count,
			 &md->t2a);
	if (unlikely(err))
		return err;

	md_dbg_verbose("t2 devices=%d total_size=%llu segment_map=%lu\n",
			 md->t2_count, total_size,
			 md_o2p(total_size) / md->t2a.bn_gcd);

	return 0;
}

static int _load_dev_list(struct md_dev_list *dev_list, struct mdt_check *mc,
			  struct block_device *bdev, const char *dev_name,
			  int silent)
{
	struct md_dev_table *mdt;
	int err;

	mdt = (void *)__get_free_page(GFP_KERNEL);
	if (unlikely(!mdt)) {
		md_dbg_err("!!! failed to alloc page\n");
		return -ENOMEM;
	}

	err = _t2_mdt_read(bdev, mdt);
	if (unlikely(err)) {
		md_err_cnd(silent, "failed to read super block from %s => %d\n",
			     dev_name, err);
		goto out;
	}

	if (!md_mdt_check(mdt, NULL, bdev, mc)) {
		md_err_cnd(silent, "bad mdt in %s\n", dev_name);
		err = -EINVAL;
		goto out;
	}

	*dev_list = mdt->s_dev_list;

out:
	free_page((ulong)mdt);
	return err;
}

/* md_init - allocates and initializes ready to go multi_devices object
 *
 * The rule is that if md_init returns error caller must call md_fini always
 */
int md_init(struct multi_devices **ret_md, const char *dev_name,
	    struct mdt_check *mc, char path[PATH_UUID],	const char **dev_path)
{
	struct md_dev_list *dev_list;
	struct block_device *bdev;
	struct multi_devices *md;
	short id_index;
	bool bind_mount = false;
	int err;

	md = kzalloc(sizeof(*md), GFP_KERNEL);
	*ret_md = md;
	if (unlikely(!md))
		return -ENOMEM;

	dev_list = kmalloc(sizeof(*dev_list), GFP_KERNEL);
	if (unlikely(!dev_list))
		return -ENOMEM;

	err = _get_device(&bdev, dev_name, NULL, mc->holder, mc->silent,
			  &bind_mount);
	if (unlikely(err))
		goto out2;

	err = _load_dev_list(dev_list, mc, bdev, dev_name, mc->silent);
	if (unlikely(err)) {
		_bdev_put(&bdev);
		goto out2;
	}

	id_index = le16_to_cpu(dev_list->id_index);
	if (bind_mount) {
		_bdev_put(&bdev);
		md->dev_index = id_index;
		goto out;
	}

	md->t1_count = le16_to_cpu(dev_list->t1_count);
	md->t2_count = le16_to_cpu(dev_list->t2_count);
	md->devs[id_index].bdev = bdev;

	if ((id_index != 0)) {
		err = _get_device(&md_t1_dev(md, 0)->bdev, NULL,
				  &dev_list->dev_ids[0].uuid, mc->holder,
				  mc->silent, &bind_mount);
		if (unlikely(err))
			goto out2;

		if (bind_mount)
			goto out;
	}

	if (md->t2_count) {
		int t2_index = md->t1_count;

		/* t2 is the primary device if given in mount, or the first
		 * mount specified it as primary device
		 */
		if (id_index != md->t1_count) {
			err = _get_device(&md_t2_dev(md, 0)->bdev, NULL,
					  &dev_list->dev_ids[t2_index].uuid,
					  mc->holder, mc->silent, &bind_mount);
			if (unlikely(err))
				goto out2;

			if (bind_mount)
				md->dev_index = t2_index;
		}

		if (t2_index <= id_index)
			md->dev_index = t2_index;
	}

out:
	if (md->dev_index != id_index)
		*dev_path = _uuid_path(&dev_list->dev_ids[md->dev_index].uuid,
				       path);
	else
		*dev_path = dev_name;

	if (!bind_mount) {
		err = _md_init(md, mc, dev_list, mc->silent);
		if (unlikely(err))
			goto out2;
		if (!(mc->private_mnt))
			_bdev_put(&md_dev_info(md, md->dev_index)->bdev);
	} else {
		md_fini(md, true);
	}

out2:
	kfree(dev_list);

	return err;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * PORTING SECTION:
 * Below are members that are done differently in different Linux versions.
 * So keep separate from code
 */
static int _check_da_ret(struct md_dev_info *mdi, long avail, bool silent)
{
	if (unlikely(avail < (long)mdi->size)) {
		if (0 < avail) {
			md_warn_cnd(silent,
				"Unsupported DAX device %s (range mismatch) => 0x%lx < 0x%lx\n",
				_bdev_name(mdi->bdev), avail, mdi->size);
			return -ERANGE;
		}
		md_warn_cnd(silent, "!!! %s direct_access return => %ld\n",
			    _bdev_name(mdi->bdev), avail);
		return avail;
	}
	return 0;
}

#include <linux/dax.h>

int md_t1_info_init(struct md_dev_info *mdi, bool silent)
{
	pfn_t a_pfn_t;
	void *addr;
	long nrpages, avail, pgoff;
	int id;

	mdi->t1i.dax_dev = fs_dax_get_by_bdev(mdi->bdev);
	if (unlikely(!mdi->t1i.dax_dev))
		return -EOPNOTSUPP;

	id = dax_read_lock();

	bdev_dax_pgoff(mdi->bdev, 0, PAGE_SIZE, &pgoff);
	nrpages = dax_direct_access(mdi->t1i.dax_dev, pgoff, md_o2p(mdi->size),
				    &addr, &a_pfn_t);
	dax_read_unlock(id);
	if (unlikely(nrpages <= 0)) {
		if (!nrpages)
			nrpages = -ERANGE;
		avail = nrpages;
	} else {
		avail = md_p2o(nrpages);
	}

	mdi->t1i.virt_addr = addr;
	mdi->t1i.phys_pfn = pfn_t_to_pfn(a_pfn_t);

	md_dbg_verbose("0x%lx 0x%lx pgoff=0x%lx\n",
			 (ulong)mdi->t1i.virt_addr, mdi->t1i.phys_pfn, pgoff);

	return _check_da_ret(mdi, avail, silent);
}

void md_t1_info_fini(struct md_dev_info *mdi)
{
	fs_put_dax(mdi->t1i.dax_dev);
	mdi->t1i.dax_dev = NULL;
	mdi->t1i.virt_addr = NULL;
}

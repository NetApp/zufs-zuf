/*
 * Multi-Device operations.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 *	Sagi Manole <sagim@netapp.com>"
 */

#include <linux/blkdev.h>
#include <linux/pfn_t.h>
#include <linux/gcd.h>

#include "zuf.h"

/* length of uuid dev path /dev/disk/by-uuid/<uuid> */
#define PATH_UUID	64

const fmode_t _g_mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

/* allocate space for and copy an existing uuid */
static char *_uuid_path(uuid_le *uuid)
{
	char path[PATH_UUID];

	sprintf(path, "/dev/disk/by-uuid/%pUb", uuid);
	return kstrdup(path, GFP_KERNEL);
}

static int _bdev_get_by_path(const char *path, struct block_device **bdev,
			     void *holder)
{
	/* The owner of the device is the pointer that will hold it. This
	 * protects from same device mounting on two super-blocks as well
	 * as same device being repeated twice.
	 */
	*bdev = blkdev_get_by_path(path, _g_mode, holder);
	if (IS_ERR(*bdev)) {
		int err = PTR_ERR(*bdev);
		*bdev = NULL;
		return err;
	}
	return 0;
}

static void _bdev_put(struct block_device **bdev, struct block_device *s_bdev)
{
	if (*bdev) {
		if (!s_bdev || *bdev != s_bdev)
			blkdev_put(*bdev, _g_mode);
		*bdev = NULL;
	}
}

static int ___bdev_get_by_uuid(struct block_device **bdev, uuid_le *uuid,
			       void *holder, bool silent, const char *msg,
			       const char *f, int l)
{
	char *path = NULL;
	int err;

	path = _uuid_path(uuid);
	err = _bdev_get_by_path(path, bdev, holder);
	if (unlikely(err))
		zuf_err_cnd(silent, "[%s:%d] %s path=%s =>%d\n",
			     f, l, msg, path, err);

	kfree(path);
	return err;
}

#define _bdev_get_by_uuid(bdev, uuid, holder, msg) \
	___bdev_get_by_uuid(bdev, uuid, holder, silent, msg, __func__, __LINE__)

static bool _main_bdev(struct block_device *bdev)
{
	if (bdev->bd_super && bdev->bd_super->s_bdev == bdev)
		return true;
	return false;
}

/* ~~~~~~~ mdt related functions ~~~~~~~ */

struct zufs_dev_table *md_t2_mdt_read(struct block_device *bdev)
{
	int err;
	struct page *page;
	/* t2 interface works for all block devices */
	struct md_dev_info mdi = {
		.bdev = bdev,
	};

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		zuf_dbg_err("!!! failed to alloc page\n");
		return ERR_PTR(-ENOMEM);
	}

	err = t2_readpage(&mdi, 0, page);
	if (err) {
		zuf_dbg_err("!!! t2_readpage err=%d\n", err);
		__free_page(page);
		return ERR_PTR(err);
	}
	return page_address(page);
}

int md_t2_mdt_write(struct multi_devices *md, ulong flags)
{
	struct zufs_dev_table *t2_zdt, *zdt = md_t1_addr(md, 0);
	int err;

	t2_zdt = (typeof(t2_zdt))get_zeroed_page(GFP_KERNEL);
	if (unlikely(!t2_zdt)) {
		zuf_dbg_err("!!! failed to alloc page\n");
		return -ENOMEM;
	}

	memcpy(t2_zdt, zdt, sizeof(*zdt));
	t2_zdt->s_flags |= flags;
	t2_zdt->s_dev_list.id_index = t2_zdt->s_dev_list.t1_count;
	t2_zdt->s_sum = cpu_to_le16(_calc_csum(t2_zdt));

	err = t2_writepage(md_t2_dev(md, 0), 0, virt_to_page(t2_zdt));
	if (err)
		zuf_dbg_err("!!! t2_writepage err=%d\n", err);

	free_page((ulong)t2_zdt);
	return err;
}

static bool _csum_mismatch(struct zufs_dev_table *zdt, int silent)
{
	ushort crc = _calc_csum(zdt);

	if (zdt->s_sum == cpu_to_le16(crc))
		return false;

	zuf_warn_cnd(silent, "expected(0x%x) != s_sum(0x%x)\n",
		      cpu_to_le16(crc), zdt->s_sum);
	return true;
}

bool md_mdt_check(struct zufs_dev_table *zdt, struct block_device *bdev,
		  int silent)
{
	struct zufs_dev_table *zdt2 = (void *)zdt + ZUFS_SB_SIZE;
	struct zufs_dev_id *dev_id;
	ulong bdev_size, super_size;

	BUILD_BUG_ON(ZUFS_SB_STATIC_SIZE(zdt) & (CACHELINE_SIZE - 1));

	/* Do sanity checks on the superblock */
	if (le32_to_cpu(zdt->s_magic) != ZUFS_SUPER_MAGIC) {
		if (le32_to_cpu(zdt2->s_magic) != ZUFS_SUPER_MAGIC) {
			zuf_warn_cnd(silent, "Can't find a valid zufs partition\n");
			return false;
		} else {
			zuf_warn_cnd(silent, "Magic error in super block: using copy\n");
			/* Try to auto-recover the super block */
			memcpy_to_pmem(zdt, zdt2, sizeof(*zdt));
			/* TODO(sagi): copy fixed zdt to shadow */
		}
	}

	if ((ZUFS_MAJOR_VERSION != md_major_version(zdt)) ||
	    (ZUFS_MINOR_VERSION < md_minor_version(zdt))) {
		zuf_warn_cnd(silent, "mkfs-mount versions mismatch! %d.%d != %d.%d\n",
			      md_major_version(zdt), md_minor_version(zdt),
			      ZUFS_MAJOR_VERSION, ZUFS_MINOR_VERSION);
		return false;
	}

	if (_csum_mismatch(zdt, silent)) {
		if (_csum_mismatch(zdt2, silent)) {
			zuf_warn_cnd(silent, "checksum error in super block\n");
			return false;
		} else {
			zuf_warn_cnd(silent, "crc16 error in super block: using copy\n");
			/* Try to auto-recover the super block */
			memcpy_to_pmem(zdt, zdt2, sizeof(*zdt));
			/* TODO(sagi): copy fixed zdt to shadow */
		}
	}

	/* check t1 device size */
	bdev_size = i_size_read(bdev->bd_inode);
	dev_id = &zdt->s_dev_list.dev_ids[zdt->s_dev_list.id_index];
	super_size = zuf_p2o(le64_to_cpu(dev_id->blocks));
	if (unlikely(!super_size /*|| (super_size & ZUFS_ALLOC_MASK)*/)) {
		zuf_warn_cnd(silent, "super_size(0x%lx) ! 2_M aligned\n",
			      super_size);
		return false;
	}

	if (unlikely(super_size > bdev_size)) {
		zuf_warn_cnd(silent, "bdev_size(0x%lx) too small expected 0x%lx\n",
			      bdev_size, super_size);
		return false;
	} else if (unlikely(super_size < bdev_size)) {
		zuf_dbg_err("Note zdt->size=(0x%lx) < bdev_size(0x%lx)\n",
			      super_size, bdev_size);
	}

	return true;
}


int md_set_sb(struct multi_devices *md, struct block_device *s_bdev,
	      void *sb, int silent)
{
	struct md_dev_info *mdi = md_dev_info(md, md->dev_index);
	struct zufs_dev_table *zdt = md_t1_addr(md, 0);
	int i;

	mdi->bdev = s_bdev;

	for (i = 0; i < md->t1_count; ++i) {
		struct md_dev_info *mdi = md_t1_dev(md, i);

		if (mdi->bdev->bd_super && (mdi->bdev->bd_super != sb)) {
			zuf_warn_cnd(silent, "!!! %s already mounted on a "
				      "different FS => -EBUSY\n",
				      _bdev_name(mdi->bdev));
			return -EBUSY;
		}

		mdi->bdev->bd_super = sb;
	}

	if (md->t2_count &&
	    md_t2_dev(md, 0)->size != zuf_p2o(zdt->s_t2_blocks))
		zuf_err("t2-blocks mismatch! dev-list-size=0x%lx zdt-size=0x%llx\n",
			 mdi->size, zuf_p2o(zdt->s_t2_blocks));

	return 0;
}

void md_fini(struct multi_devices *md, struct block_device *s_bdev)
{
	int i;

	if (md->t2_count)
		_bdev_put(&md_t2_dev(md, 0)->bdev, s_bdev);

	kfree(md->t1a.map);

	for (i = 0; i < md->t1_count; ++i) {
		struct md_dev_info *mdi = md_t1_dev(md, i);

		if (mdi->bdev && !_main_bdev(mdi->bdev))
			mdi->bdev->bd_super = NULL;
		_bdev_put(&mdi->bdev, s_bdev);
	}

	kfree(md);
}


/* ~~~~~~~ Pre-mount operations ~~~~~~~ */

static int _get_device(struct block_device **bdev, const char *dev_name,
		       uuid_le *uuid, struct file_system_type *fs_type,
		       int silent, bool *bind_mount)
{
	int err;

	if (dev_name)
		err = _bdev_get_by_path(dev_name, bdev, fs_type);
	else
		err = _bdev_get_by_uuid(bdev, uuid, fs_type,
					"failed to get device");

	if (unlikely(err)) {
		zuf_err_cnd(silent, "failed to get device dev_name=%s "
			     "uuid=%pUb err=%d\n", dev_name, uuid, err);
		return err;
	}

	if (bind_mount && _main_bdev(*bdev))
		*bind_mount = true;

	return 0;
}

static int _init_dev_info(struct md_dev_info *mdi, struct zufs_dev_id *id,
			  int index, u64 offset,
			  struct file_system_type *fs_type, bool t1_dev,
			  int silent)
{
	struct zufs_dev_table *zdt = NULL;
	int err = 0;

	if (mdi->bdev == NULL) {
		err = _get_device(&mdi->bdev, NULL, &id->uuid, fs_type,
				  silent, NULL);
		if (unlikely(err))
			return err;
	}

	mdi->offset = offset;
	mdi->size = zuf_p2o(le64_to_cpu(id->blocks));
	mdi->index = index;

	if (t1_dev) {
		/* FIXME: shadow */
		struct blk_dax_ctl dax = { .size = mdi->size, };
		long avail;

		avail = bdev_direct_access(mdi->bdev, &dax);
		if (unlikely(avail < (long)mdi->size)) {
			if (0 < avail) {
				zuf_warn_cnd(silent, "Unsupported DAX device "
					      "%s (range mismatch)\n",
					      _bdev_name(mdi->bdev));
				return -ERANGE;
			}
			zuf_warn_cnd(silent, "!!! %s direct_access return => "
				      "%ld\n", _bdev_name(mdi->bdev), avail);
			return avail;
		}

		mdi->t1i.virt_addr = dax.addr;
		mdi->t1i.phys_pfn = pfn_t_to_pfn(dax.pfn);

		zdt = mdi->t1i.virt_addr;
	} else {
		zdt = md_t2_mdt_read(mdi->bdev);
		if (IS_ERR(zdt)) {
			zuf_err_cnd(silent, "failed to read zdt from t2 => "
				     "%ld\n", PTR_ERR(zdt));
			return PTR_ERR(zdt);
		}
	}

	if (!md_mdt_check(zdt, mdi->bdev, silent)) {
		zuf_err_cnd(silent, "device %s failed integrity check\n",
			     _bdev_name(mdi->bdev));
		err = -EINVAL;
		goto out;
	}

	return 0;

out:
	if (!(t1_dev || IS_ERR_OR_NULL(zdt)))
		free_page((ulong)zdt);
	return err;
}

static int _t1_map_setup(struct multi_devices *md)
{
	struct zufs_dev_table *zdt = md_t1_addr(md, 0);
	struct md_dev_larray *t1a = &md->t1a;
	ulong map_size, bn_end;
	int i, dev_index = 0;

	map_size = le64_to_cpu(zdt->s_t1_blocks) / t1a->bn_gcd;
	t1a->map = kcalloc(map_size, sizeof(*t1a->map), GFP_KERNEL);
	if (!t1a->map) {
		zuf_dbg_err("failed to allocate t1 dev map\n");
		return -ENOMEM;
	}

	bn_end = zuf_o2p(md->devs[dev_index].size);
	for (i = 0; i < map_size; ++i) {
		if ((i * t1a->bn_gcd) >= bn_end)
			bn_end += zuf_o2p(md->devs[++dev_index].size);
		t1a->map[i] = &md->devs[dev_index];
	}

	return 0;
}

static int _md_init(struct multi_devices *md, struct file_system_type *fs_type,
		    struct zufs_dev_list *dev_list, int silent)
{
	struct zufs_dev_table *main_zdt = NULL;
	u64 total_size = 0;
	int i, err;

	for (i = 0; i < md->t1_count; ++i) {
		struct md_dev_info *mdi = md_t1_dev(md, i);
		struct zufs_dev_table *dev_zdt;

		err = _init_dev_info(mdi, &dev_list->dev_ids[i], i,
				     total_size, fs_type, true, silent);
		if (unlikely(err))
			return err;

		/* apparently gcd(0,X)=X which is nice */
		md->t1a.bn_gcd = gcd(md->t1a.bn_gcd, zuf_o2p(mdi->size));
		total_size += mdi->size;

		dev_zdt = md_t1_addr(md, i);
		if (!main_zdt) {
			main_zdt = dev_zdt;
		} else if (!uuid_equal(&main_zdt->s_uuid, &dev_zdt->s_uuid)) {
			zuf_err_cnd(silent, "[%d] device %s uuid doesn't match\n",
				     i, _bdev_name(mdi->bdev));
			return -EINVAL;
		}

		if (test_zdt_opt(dev_zdt, ZUFS_SHADOW))
			memcpy(dev_zdt, dev_zdt + mdi->size, mdi->size);

		zuf_dbg_verbose("dev=%d %pUb %s v=%p pfn=%lu off=%lu size=%lu\n",
				 i, &dev_list->dev_ids[i].uuid,
				 _bdev_name(mdi->bdev), dev_zdt,
				 mdi->t1i.phys_pfn, mdi->offset, mdi->size);
	}

	if(unlikely(le64_to_cpu(main_zdt->s_t1_blocks) != zuf_o2p(total_size))) {
		zuf_err_cnd(silent, "FS corrupted zdt->t1_blocks(0x%llx) != "
			     "total_size(0x%llx)\n", main_zdt->s_t1_blocks,
			     total_size);
		return -EIO;
	}

	err = _t1_map_setup(md);
	if (unlikely(err))
		return err;

	zuf_dbg_verbose("t1 devices=%d total_size=%llu segment_map=%lu\n",
			 md->t1_count, total_size,
			 zuf_o2p(total_size) / md->t1a.bn_gcd);

	if (md->t2_count) {
		struct md_dev_info *mdi = md_t2_dev(md, 0);

		err = _init_dev_info(mdi, &dev_list->dev_ids[i], 0, 0,
				     fs_type, false, silent);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int _load_dev_list(struct zufs_dev_list *dev_list,
			  struct block_device *bdev, const char *dev_name,
			  int silent)
{
	struct zufs_dev_table *zdt;
	int err = 0;

	zdt = md_t2_mdt_read(bdev);
	if (IS_ERR(zdt)) {
		zuf_err_cnd(silent, "failed to read super block from %s; err=%ld\n",
			     dev_name, PTR_ERR(zdt));
		err = PTR_ERR(zdt);
		goto out;
	}

	if (!md_mdt_check(zdt, bdev, silent)) {
		zuf_err_cnd(silent, "bad zdt in %s\n", dev_name);
		err = -EINVAL;
		goto out;
	}

	*dev_list = zdt->s_dev_list;

out:
	if (!IS_ERR_OR_NULL(zdt))
		free_page((ulong)zdt);

	return err;
}

int md_init(struct multi_devices *md, const char *dev_name,
	    struct file_system_type *fs_type, int silent, const char **dev_path)
{
	struct zufs_dev_list *dev_list;
	struct block_device *bdev;
	short id_index;
	bool bind_mount = false;
	int err;

	dev_list = kmalloc(sizeof(*dev_list), GFP_KERNEL);
	if (unlikely(!dev_list))
		return -ENOMEM;

	err = _get_device(&bdev, dev_name, NULL, fs_type, silent, &bind_mount);
	if (unlikely(err))
		goto out2;

	err = _load_dev_list(dev_list, bdev, dev_name, silent);
	if (unlikely(err)) {
		_bdev_put(&bdev, NULL);
		goto out2;
	}

	id_index = le16_to_cpu(dev_list->id_index);
	if (bind_mount) {
		_bdev_put(&bdev, NULL);
		md->dev_index = id_index;
		goto out;
	}

	md->t1_count = le16_to_cpu(dev_list->t1_count);
	md->t2_count = le16_to_cpu(dev_list->t2_count);
	md->devs[id_index].bdev = bdev;

	if ((id_index != 0)) {
		err = _get_device(&md_t1_dev(md, 0)->bdev, NULL,
				  &dev_list->dev_ids[0].uuid, fs_type,
				  silent, &bind_mount);
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
					  fs_type, silent, &bind_mount);
			if (unlikely(err))
				goto out2;

			if (bind_mount)
				md->dev_index = t2_index;
		} else {
			md->dev_index = t2_index;
		}
	}

out:
	if (md->dev_index != id_index)
		*dev_path = _uuid_path(&dev_list->dev_ids[md->dev_index].uuid);
	else
		*dev_path = kstrdup(dev_name, GFP_KERNEL);

	if (!bind_mount) {
		err = _md_init(md, fs_type, dev_list, silent);
		if (unlikely(err))
			goto out2;
		_bdev_put(&md_dev_info(md, md->dev_index)->bdev, NULL);
	} else {
		md_fini(md, NULL);
	}

out2:
	kfree(dev_list);

	return err;
}

struct multi_devices *md_alloc(size_t size)
{
	uint s = max(sizeof(struct multi_devices), size);
	struct multi_devices *md = kzalloc(s, GFP_KERNEL);

	if (unlikely(!md))
		return ERR_PTR(-ENOMEM);
	return md;
}

int md_numa_info(struct multi_devices *md, struct zufs_ioc_pmem *zi_pmem)
{
	zi_pmem->pmem_total_blocks = md_t1_blocks(md);
	/*
	if (max_cpu_id < sys_num_active_cpus) {
		max_cpu_id = sys_num_active_cpus;
		return -ETOSMALL;
	}

	max_cpu_id = sys_num_active_cpus;
	__u32 max_nodes;
	__u32 active_pmem_nodes;
	struct zufs_pmem_info {
		int sections;
		struct zufs_pmem_sec {
			__u32 length;
			__u16 numa_id;
			__u16 numa_index;
		} secs[ZUFS_DEV_MAX];
	} pmem;

	struct zufs_numa_info {
		__u32 max_cpu_id; // The below array size
		struct zufs_cpu_info {
			__u32 numa_id;
			__u32 numa_index;
		} numa_id_map[];
	} *numa_info;
	k_nf = kcalloc(max_cpu_id, sizeof(struct zufs_cpu_info), GFP_KERNEL);
	....
	copy_to_user(->numa_info, kn_f, max_cpu_id * sizeof(struct zufs_cpu_info));
	*/
	return 0;
}

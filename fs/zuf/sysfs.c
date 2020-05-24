// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/* sysfs - ZUF sysfs internals.
 *
 * Copyright (c) 2020 NetAppNetApp Inc. All rights reserved.
 *
 * ZUS-ZUF interaction is done via a small specialized FS that
  provides the communication with the mount-thread, ZTs, pmem devices,
 * and so on ...
 * Subsequently all FS super_blocks are children of this root, and point
 * to it. All sharing the same zuf communication channels.
 *
 * Authors:
 *	Omer Caspi <omer.caspi@netapp.com>
 */

#include "zuf.h"

/* Common definitions */
struct zuf_attr {
	struct attribute attr;
	ssize_t (*show)(struct zuf_attr *attr, struct zuf_sb_info *sbi,
			char *buf);
	ssize_t (*store)(struct zuf_attr *attr, struct zuf_sb_info *sbi,
			 const char *buf, size_t len);
	enum pcpu num;
};

#define ZUF_ATTR(name, mode, show, store) \
static struct zuf_attr zuf_attr_##name = __ATTR(name, mode, show, store)

#define ZUF_RO_ATTR(name) ZUF_ATTR(name, 0444, _##name##_show, NULL)
#define ZUF_RW_ATTR(name) ZUF_ATTR(name, 0644, _##name##_show, _##name##_store)


/* mmap counters */
static ssize_t _us_mmap_show(struct zuf_attr *attr, struct zuf_sb_info *sbi,
				char *buf)
{
	int mmap_counters[] = {
		zu_pcpu_us_mmap_shared,
		zu_pcpu_us_mmap_private,
		zu_pcpu_us_mmap_shrd_rd_flt,
		zu_pcpu_us_mmap_shrd_wr_flt,
		zu_pcpu_us_mmap_prvt_rd_flt,
		zu_pcpu_us_mmap_prvt_wr_flt,
		zu_pcpu_us_mmap_rd_2_wr_flt,
		0 };
	int i;
	int ret;

	buf[0] = 0;
	for (i = 0; mmap_counters[i] != 0; ++i) {
		s64 counter = percpu_counter_sum(&sbi->pcpu[mmap_counters[i]]);

		ret = snprintf(buf, PAGE_SIZE, "%s 0x%llx", buf, counter);
	}
	return ret;
}

ZUF_RO_ATTR(us_mmap);


/* IO counters */

#define ZUFS_IO_HISTOGRAM_SIZE (zu_pcpu_lt_4k_wr - zu_pcpu_lt_4k_rd)

static ssize_t _rw_hgram_show(struct zuf_attr *attr, struct zuf_sb_info *sbi,
			      char *buf)
{
	s64 sum = 0;
	int i;

	buf[0] = 0;
	for (i = 0; i < ZUFS_IO_HISTOGRAM_SIZE; ++i) {
		s64 counter = percpu_counter_sum(&sbi->pcpu[attr->num + i]);

		snprintf(buf, PAGE_SIZE, "%s 0x%llx", buf, counter);
		sum += counter;
	}
	return snprintf(buf, PAGE_SIZE, "%s :t=0x%llx\n", buf, sum);
}

static ssize_t _pcpu_show(struct zuf_attr *attr, struct zuf_sb_info *sbi,
			  char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n",
			percpu_counter_sum(&sbi->pcpu[attr->num]));
}


#define ZUF_DEFINE_RW_HGRAM(_name)					\
static struct zuf_attr zuf_attr_##_name = {				\
	.attr = {.name = __stringify(_name),				\
		 .mode = VERIFY_OCTAL_PERMISSIONS(0444) },		\
	.show	= _rw_hgram_show,					\
	.store	= NULL,							\
	.num = zu_pcpu_lt_4k_##_name,					\
}

ZUF_DEFINE_RW_HGRAM(rd);
ZUF_DEFINE_RW_HGRAM(wr);
ZUF_DEFINE_RW_HGRAM(sync_wr);
ZUF_DEFINE_RW_HGRAM(direct_wr);


/* Simple counters */

#define ZUF_DEFINE_PCPU(_name)						\
static struct zuf_attr zuf_attr_##_name = {				\
	.attr = {.name = __stringify(_name),				\
		 .mode = VERIFY_OCTAL_PERMISSIONS(0444) },		\
	.show	= _pcpu_show,						\
	.store	= NULL,							\
	.num = zu_pcpu_##_name,						\
}

ZUF_DEFINE_PCPU(us_seek);
ZUF_DEFINE_PCPU(us_fsync);
ZUF_DEFINE_PCPU(us_fallocate);
ZUF_DEFINE_PCPU(us_lookup);
ZUF_DEFINE_PCPU(us_create);
ZUF_DEFINE_PCPU(us_link);
ZUF_DEFINE_PCPU(us_unlink);
ZUF_DEFINE_PCPU(us_symlink);
ZUF_DEFINE_PCPU(us_mkdir);
ZUF_DEFINE_PCPU(us_rmdir);
ZUF_DEFINE_PCPU(us_mknod);
ZUF_DEFINE_PCPU(us_rename);
ZUF_DEFINE_PCPU(us_setattr);
ZUF_DEFINE_PCPU(us_setsize);
ZUF_DEFINE_PCPU(us_getxattr);
ZUF_DEFINE_PCPU(us_setxattr);
ZUF_DEFINE_PCPU(us_fadvise_willneed);
ZUF_DEFINE_PCPU(us_fadvise_dontneed);
ZUF_DEFINE_PCPU(us_clone);
ZUF_DEFINE_PCPU(wr_bw);
ZUF_DEFINE_PCPU(rd_bw);

#define ATTR_LIST(name) (&zuf_attr_##name.attr)

static struct attribute *zuf_attributes_list[] = {
	ATTR_LIST(us_seek),
	ATTR_LIST(us_fsync),
	ATTR_LIST(us_fallocate),
	ATTR_LIST(us_lookup),
	ATTR_LIST(us_create),
	ATTR_LIST(us_link),
	ATTR_LIST(us_unlink),
	ATTR_LIST(us_symlink),
	ATTR_LIST(us_mkdir),
	ATTR_LIST(us_rmdir),
	ATTR_LIST(us_mknod),
	ATTR_LIST(us_rename),
	ATTR_LIST(us_setattr),
	ATTR_LIST(us_setsize),
	ATTR_LIST(us_getxattr),
	ATTR_LIST(us_setxattr),
	ATTR_LIST(us_fadvise_willneed),
	ATTR_LIST(us_fadvise_dontneed),
	ATTR_LIST(us_mmap),
	ATTR_LIST(us_clone),
	ATTR_LIST(wr_bw),
	ATTR_LIST(rd_bw),
	ATTR_LIST(rd),
	ATTR_LIST(wr),
	ATTR_LIST(sync_wr),
	ATTR_LIST(direct_wr),
	NULL,
};

static ssize_t zuf_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct zuf_attr *mattr = container_of(attr, typeof(*mattr), attr);
	struct zuf_sb_info *sbi = container_of(kobj, typeof(*sbi), s_kobj);

	return mattr->show ? mattr->show(mattr, sbi, buf) : 0;
}

static ssize_t zuf_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t len)
{
	struct zuf_attr *zattr = container_of(attr, typeof(*zattr), attr);
	struct zuf_sb_info *sbi = container_of(kobj, typeof(*sbi), s_kobj);

	return zattr->store ? zattr->store(zattr, sbi, buf, len) : 0;
}

static void zuf_sysfs_release(struct kobject *kobj)
{
	struct zuf_sb_info *sbi = container_of(kobj, typeof(*sbi), s_kobj);

	complete(&sbi->s_kobj_unregister);
}

static const struct sysfs_ops zuf_attr_ops = {
	.show   = zuf_attr_show,
	.store  = zuf_attr_store,
};

static struct kobj_type zuf_ktype = {
	.default_attrs  = zuf_attributes_list,
	.sysfs_ops      = &zuf_attr_ops,
	.release        = zuf_sysfs_release,
};


void zuf_sysfs_entry_init(struct super_block *sb, struct zuf_fs_type *fst,
			 struct block_device *blockdev)
{
	struct zuf_sb_info *sbi = SBI(sb);
	char b[BDEVNAME_SIZE];
	int err;

	if (!fst->sysfs_kset)
		return;
	bdevname(blockdev, b);

	sbi->s_kobj.kset = fst->sysfs_kset;
	init_completion(&sbi->s_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_kobj, &zuf_ktype, NULL, "%s", b);
	if (unlikely(err))
		zuf_warn("error initializing sysfs entries for %s\n", b);
}

void zuf_sysfs_entry_fini(struct super_block *sb)
{
	struct zuf_sb_info *sbi = SBI(sb);

	if (!sbi->s_kobj.state_initialized)
		return;

	kobject_del(&sbi->s_kobj);
	kobject_put(&sbi->s_kobj);
}

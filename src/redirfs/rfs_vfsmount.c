/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * History:
 * 2017 - changing for the latest kernels by Slava Imameev
 *
 * Copyright 2008 - 2010 Frantisek Hrbata
 * All rights reserved.
 *
 * This file is part of RedirFS.
 *
 * RedirFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RedirFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with RedirFS. If not, see <http://www.gnu.org/licenses/>.
 */

#include "rfs.h"
#include "rfs_dbg.h"

#ifdef RFS_PATH_WITH_MNT

static struct rfs_vfsmount rfs_vfsmount_list = {
    .list = LIST_HEAD_INIT(rfs_vfsmount_list.list),
};

static spinlock_t rfs_vfsmount_list_lock = __SPIN_LOCK_INITIALIZER(rfs_vfsmount_list_lock);

static void rfs_vfsmount_umount_begin(struct super_block *sb);

static struct rfs_vfsmount *rfs_vfsmount_alloc(struct vfsmount *mnt)
{
    struct rfs_vfsmount *rmnt;

    DBG_BUG_ON(!rfs_preemptible());

    rmnt = kzalloc(sizeof(struct rfs_vfsmount), GFP_KERNEL);
    if (!rmnt)
        return ERR_PTR(-ENOMEM);

    INIT_LIST_HEAD(&rmnt->list);
    rmnt->mnt = mntget(mnt);
    rmnt->s_ops_old = mnt->mnt_sb->s_op;
    if (mnt->mnt_sb->s_op)
        rmnt->s_ops_new = *mnt->mnt_sb->s_op;
    rmnt->s_ops_new.umount_begin = rfs_vfsmount_umount_begin;
    mnt->mnt_sb->s_op = &rmnt->s_ops_new;
    atomic_set(&rmnt->count, 1);

    return rmnt;
}

struct rfs_vfsmount *rfs_vfsmount_get(struct rfs_vfsmount *rmnt)
{
    if (!rmnt || IS_ERR(rmnt))
        return NULL;

    BUG_ON(!atomic_read(&rmnt->count));
    atomic_inc(&rmnt->count);

    return rmnt;
}

void rfs_vfsmount_put(struct rfs_vfsmount *rmnt)
{
    if (!rmnt || IS_ERR(rmnt))
        return;

    BUG_ON(!atomic_read(&rmnt->count));
    if (!atomic_dec_and_test(&rmnt->count))
        return;

    rfs_pr_debug("mnt=%p, mnt->mnt_sb=%p", rmnt->mnt, rmnt->mnt->mnt_sb);
    rmnt->mnt->mnt_sb->s_op = rmnt->s_ops_old;
    mntput(rmnt->mnt);
    kfree(rmnt);
}

static struct rfs_vfsmount *rfs_vfsmount_find(struct vfsmount *mnt)
{
    struct rfs_vfsmount *rmnt = NULL;
    struct rfs_vfsmount *found = NULL;

    list_for_each_entry(rmnt, &rfs_vfsmount_list.list, list) {
        if (rmnt->mnt != mnt)
            continue;

        found = rfs_vfsmount_get(rmnt);
        break;
    }

    return found;
}

static struct rfs_vfsmount *rfs_vfsmount_find_by_sb(struct super_block *sb)
{
    struct rfs_vfsmount *rmnt = NULL;
    struct rfs_vfsmount *found = NULL;

    list_for_each_entry(rmnt, &rfs_vfsmount_list.list, list) {
        if (rmnt->mnt->mnt_sb != sb)
            continue;

        found = rfs_vfsmount_get(rmnt);
        break;
    }

    return found;
}

static void rfs_vfsmount_list_add(struct rfs_vfsmount *rmnt)
{
    list_add_tail(&rmnt->list, &rfs_vfsmount_list.list);
    rfs_vfsmount_get(rmnt);
}

static void rfs_vfsmount_list_rem(struct rfs_vfsmount *rmnt)
{
    list_del_init(&rmnt->list);
    rfs_vfsmount_put(rmnt);
}


static void rfs_vfsmount_umount_begin(struct super_block *sb)
{
    struct rfs_vfsmount *rmnt;
    rfs_pr_debug("mnt_sb=%p", sb);

    spin_lock(&rfs_vfsmount_list_lock);
    rmnt = rfs_vfsmount_find_by_sb(sb);
    if (rmnt) {
        rfs_path_remove_all_under_mnt(rmnt);
        rfs_vfsmount_list_rem(rmnt);
        spin_unlock(&rfs_vfsmount_list_lock);

        //it must be hold only by rmnt
        DBG_BUG_ON(atomic_read(&rmnt->count) != 1);
        rfs_vfsmount_put(rmnt);
        if (sb->s_op->umount_begin)
            sb->s_op->umount_begin(sb);
    } else {
        spin_unlock(&rfs_vfsmount_list_lock);
    }
}

struct rfs_vfsmount *rfs_vfsmount_add(struct vfsmount *mnt)
{
    struct rfs_vfsmount *rmnt;

    spin_lock(&rfs_vfsmount_list_lock);
    rmnt = rfs_vfsmount_find(mnt);
    if (rmnt) {
        spin_unlock(&rfs_vfsmount_list_lock);
        return rmnt;
    }

    rmnt = rfs_vfsmount_alloc(mnt);
    if (IS_ERR(rmnt)) {
        spin_unlock(&rfs_vfsmount_list_lock);
        return rmnt;
    }

    rfs_vfsmount_list_add(rmnt);
    spin_unlock(&rfs_vfsmount_list_lock);
    
    rfs_pr_debug("mnt=%p, mnt->mnt_sb=%p", mnt, mnt->mnt_sb);

    return rmnt;
}

void rfs_vfsmount_remove(struct rfs_vfsmount *rmnt)
{
    long int v;

    spin_lock(&rfs_vfsmount_list_lock);
    //remove only when it is hold by cache and rmnt
    v = atomic_read(&rmnt->count);
    if (v == 2)
        rfs_vfsmount_list_rem(rmnt);
    spin_unlock(&rfs_vfsmount_list_lock);

    rfs_pr_debug("mnt=%p, v=%ld", rmnt->mnt, v);
}

#endif
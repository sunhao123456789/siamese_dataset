static void shmem_delete_inode(struct inode *inode)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	struct shmem_inode_info *info = SHMEM_I(inode);

	if (inode->i_op->truncate == shmem_truncate) {
		truncate_inode_pages(inode->i_mapping, 0);
		shmem_unacct_size(info->flags, inode->i_size);
		inode->i_size = 0;
		shmem_truncate(inode);
		if (!list_empty(&info->swaplist)) {
			spin_lock(&shmem_swaplist_lock);
			list_del_init(&info->swaplist);
			spin_unlock(&shmem_swaplist_lock);
		}
	}
	BUG_ON(inode->i_blocks);
	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		sbinfo->free_inodes++;
		spin_unlock(&sbinfo->stat_lock);
	}
	clear_inode(inode);
}

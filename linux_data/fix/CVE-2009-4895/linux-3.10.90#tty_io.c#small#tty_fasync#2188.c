static int tty_fasync(int fd, struct file *filp, int on)
{
	struct tty_struct *tty = file_tty(filp);
	int retval;

	tty_lock(tty);
	retval = __tty_fasync(fd, filp, on);
	tty_unlock(tty);

	return retval;
}

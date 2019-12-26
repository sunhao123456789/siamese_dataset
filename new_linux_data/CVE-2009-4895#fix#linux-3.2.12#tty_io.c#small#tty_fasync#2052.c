static int tty_fasync(int fd, struct file *filp, int on)
{
	int retval;
	tty_lock();
	retval = __tty_fasync(fd, filp, on);
	tty_unlock();
	return retval;
}

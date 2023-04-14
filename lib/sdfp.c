#include <linux/types.h>
#include <linux/bitmap.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/export.h>
#include <linux/debugfs.h>

static bool sdfp_no_check = 1;
static bool sdfp_kill_doublefetch = 0;
static DECLARE_BITMAP(sdfp_ignored_calls, NR_syscalls) = { 0 };
static DECLARE_BITMAP(sdfp_multiread_reported, NR_syscalls) = { 0 };
static atomic_t num_multis[NR_syscalls];
static atomic64_t num_bytes[NR_syscalls];
struct dentry *sdfp_dir;

/**
   For stats, all writes will reset the stats data.

   For read:

   4\t2\t8\t12\n = 30
   nr   enabled   num_multis   num_bytes

   30 bytes per line

   1. syscall number
   2. enabled or not (bool)
   3. number of multi reads
   4. Number of bytes read.

*/
static ssize_t stats_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	memset(num_multis, 0, sizeof(num_multis));
	memset(num_bytes, 0, sizeof(num_bytes));
	bitmap_zero(sdfp_multiread_reported, NR_syscalls);
	return count;
}
#define STATS_LEN 30
static ssize_t stats_read(struct file *file, char __user *ubuf, size_t count,
			  loff_t *ppos)
{
	char buf[STATS_LEN + 1];
	int nr = *ppos / STATS_LEN;
	ssize_t res = 0;
	while (nr < NR_syscalls && count > STATS_LEN) {
		bool enabled = test_bit(nr, sdfp_ignored_calls);
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%4u\t%2u\t%8u\t%12llu\n", nr,
			 enabled, atomic_read(&num_multis[nr]),
			 atomic64_read(&num_bytes[nr]));
		if (copy_to_user(ubuf, buf, STATS_LEN)) {
			break;
		}
		ubuf += STATS_LEN;
		*ppos += STATS_LEN;
		nr = *ppos / STATS_LEN;
		res += STATS_LEN;
		count -= STATS_LEN;
	}
	return res;
}
const static struct file_operations stat_fops = {
	.read = stats_read,
	.write = stats_write,
};

static ssize_t disable_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	unsigned nr = 0;
	int res = kstrtouint_from_user(ubuf, count, 10, &nr);
	if (res) {
		return res;
	}
	if (nr >= NR_syscalls) {
		return -ERANGE;
	}
	set_bit(nr, sdfp_ignored_calls);
	*ppos += count;
	return count;
}
const static struct file_operations disable_fops = {
	.write = disable_write,
};
static ssize_t enable_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	unsigned nr = 0;
	int res = kstrtouint_from_user(ubuf, count, 10, &nr);
	if (res) {
		return res;
	}
	if (nr >= NR_syscalls) {
		return -ERANGE;
	}
	clear_bit(nr, sdfp_ignored_calls);
	*ppos += count;
	return count;
}
const static struct file_operations enable_fops = {
	.write = enable_write,
};
/**
 * Set up the bitfields or other data for sdfp.
 */
static int __init sdfp_init(void)
{
	set_bit(__NR_write, sdfp_ignored_calls);
	set_bit(__NR_execve, sdfp_ignored_calls);
	set_bit(__NR_futex, sdfp_ignored_calls);
	sdfp_dir = debugfs_create_dir("sdfp", 0);
	if (sdfp_dir == (struct dentry *)ERR_PTR) {
		return 1;
	}
	debugfs_create_bool("df_kill", 0600, sdfp_dir, &sdfp_kill_doublefetch);
	debugfs_create_bool("no_check", 0600, sdfp_dir, &sdfp_no_check);
	debugfs_create_file("stats", 0600, sdfp_dir, 0, &stat_fops);
	debugfs_create_file("enable", 0200, sdfp_dir, 0, &enable_fops);
	debugfs_create_file("disable", 0200, sdfp_dir, 0, &disable_fops);
	return 0;
}
module_init(sdfp_init);

/**
   Create a new node, or use the static node.

   Static node is unused if it's start is 0. 
 */
static struct sdfp_node *new_node(void *buf, uintptr_t start, uintptr_t end)
{
	struct sdfp_node *nn = current->sdfp_list;
	if (nn->start) {
		// Static node is in use, create a new node.
		nn = kmalloc(sizeof(struct sdfp_node), GFP_KERNEL);
		if (!nn) {
			return 0;
		}
		nn->buf = kmalloc(end - start, GFP_KERNEL);
		if (!nn->buf) {
			kfree(nn);
			return 0;
		}
	}
	nn->start = start;
	nn->end = end;
	memcpy(&nn->buf[0], buf, end - start);
	return nn;
}
/**
   data_check() - Check a new sdfp_node for multi-reads
   @nn: the node to check

   See if there are any overlaps with something on
   &current->sdfp_list. If so, overwrite @nn->buf with original data.

   nn may be in static node, don't trip on that.
   
   RETURNS:
   %true if there was a mult-read.
 */
static bool data_check(struct sdfp_node *nn)
{
	const int nr = current->sdfp_nr;
	struct sdfp_node *cn = current->sdfp_list;
	bool ret = false;
	while (cn) {
		if ((cn != nn) && (cn->start < nn->end) &&
		    (cn->end > nn->start)) {
			// There is an overlap.
			uintptr_t ostart = max(cn->start, nn->start);
			uintptr_t oend = min(cn->end, nn->end);
			atomic_inc(&num_multis[nr]);
			if (!test_and_set_bit(nr, sdfp_multiread_reported))
				printk(KERN_ALERT
				       "SDFP: Multi-read detected in pid %d syscall %d",
				       current->pid, nr);
			if (memcmp(&cn->buf[ostart - cn->start],
				   &nn->buf[ostart - nn->start],
				   oend - ostart)) {
				memcpy(&nn->buf[ostart - nn->start],
				       &cn->buf[ostart - cn->start],
				       oend - ostart);
				ret = true;
			}
		}
		cn = cn->next;
	}
	return ret;
}

/**
   Add a new node to the `current->sdfp_list` after the static node. 
 */
static void add_node(struct sdfp_node *nn)
{
	struct sdfp_node *cn = current->sdfp_list;
	if (nn != cn) {
		nn->next = cn->next;
		cn->next = nn;
	}
}

/**
 * sdfp_check - Check for double fetch attacks.
 * @to: Result location
 * @from: Source address, in user space
 * @n: Amount to check.
 *
 * Context: user context only.
 *
 *
 * At this point, n bytes have already been copied to `to`.  This
 * ensures that we can check and fix `n` bytes without a fault. The
 * `from` is only used to get the `start` and `end` addresses.
 *
 * If data has been seen before (in this syscall), make sure it hasn't
 * changed.
 *
 * If data has changed and the syscall isn't in `sdfp_ignored_calls`,
 * overwrite with saved data. Send a SIGKILL if `sdfp_kill` is set.
 *
 */
void sdfp_check(volatile void *to, const void __user *from, unsigned long n)
{
	int nr = current->sdfp_nr;
	uintptr_t start = (uintptr_t)from;
	uintptr_t end = start + n;
	struct sdfp_node *nn = 0;
	struct mutex *lock = &current->sdfp_lock;
	if (!n || sdfp_no_check || pagefault_disabled())
		return;
	if (nr < 0 || nr >= NR_syscalls) {
		printk(KERN_ALERT "SDFP: bad syscall number: %d, state %d", nr,
		       get_current_state());

		return;
	} else if (test_bit(nr, sdfp_ignored_calls))
		return;
	atomic64_add(n, &num_bytes[nr]);
	mutex_lock(&lock);
	nn = new_node((void *)to, start, end);
	if (!nn) {
		printk(KERN_ALERT "SDFP: Malloc failure in new node\n");
		mutex_unlock(&lock);
		sdfp_clear(current, nr);
		return;
	}
	if (data_check(nn)) {
		printk(KERN_ALERT
		       "SDFP: Modifed multi detected in pid %d syscall %d bytes %ld",
		       current->pid, nr, n);
		memcpy((void *)to, nn->buf, n);
		if (sdfp_kill_doublefetch) {
			printk(KERN_ALERT "SDFP: Killing pid %d", current->pid);
			force_sig(SIGKILL);
		}
	}
	add_node(nn);
	mutex_unlock(&lock);
}
EXPORT_SYMBOL(sdfp_check);

/**
   Clear the sdfp_list from task `tsk`. Called at the beginning of a
   syscall (on current) or when a task_struct is being cleaned up.
 */
void sdfp_clear(struct task_struct *tsk, int nr)
{
	struct mutex *lock = &tsk->sdfp_lock;
	struct sdfp_node *cn = 0;
	mutex_lock(lock);
	cn = tsk->sdfp_list;
	cn->start = 0;
	cn->end = 0;
	cn = cn->next;
	tsk->sdfp_list->next = 0;
	mutex_unlock(lock);
	while (cn) {
		struct sdfp_node *nn = cn->next;
		kfree(cn->buf);
		kfree(cn);
		cn = nn;
	}
	tsk->sdfp_nr = nr;
}
EXPORT_SYMBOL(sdfp_clear);

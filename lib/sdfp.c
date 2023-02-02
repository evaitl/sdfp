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
static unsigned num_multis[NR_syscalls];
static unsigned long num_bytes[NR_syscalls];
struct dentry *sdfp_dir;

#ifdef SDFP_DBG
static const uint32_t SDFP_M1 = 0xa5a5a5a5c5c5c5c5;
static const uint32_t SDFP_M2 = 0x5f5f5f5f8a8a8a8a;
static inline void *sdfp_malloc(size_t size)
{
	size = (((size + 3) & ~0x03) + 12) >> 2; // size in words
	uint32_t *m = kmalloc(size << 2, GPF_KERNEL);
	m[0] = SDFP_M1;
	m[1] = size;
	m[size - 1] = SDFP_M2;
	return &m[2];
}
static inline void sdfp_free(const void *ptr)
{
	const uint32_t *p = ptr;
	BUG_ON(p[-2] != SDFP_M1);
	BUG_ON(p[p[-1] - 1] != SDFP_M2);
	kfree(&p[-2]);
}
static void sdfp_memcheck(void)
{
	struct sdfp_node *cn = current->sdfp_list;
	while (cn) {
		const uint32_t *p = cn->buf;
		BUG_ON(p[-2] != SDFP_M1);
		BUG_ON(p[p[-1] - 1] != SDFP_M2);
		cn = cn->next;
	}
}
#else
static inline void *sdfp_malloc(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}
static inline void sdfp_free(const void *ptr)
{
	kfree(ptr);
}
static inline void sdfp_memcheck(void)
{
}
#endif

/**
   For stats, all writes will reset the stats data.

   For read:

   4\t2\t8\t12\n = 30
   nr   enabled   num_multis   num_bytes

   30 bytes per line
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
		snprintf(buf, sizeof(buf), "%4u\t%2u\t%8u\t%12lu\n", nr,
			 enabled, num_multis[nr], num_bytes[nr]);
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
 * Overlap found. Need to merge the `to` buf with the buf in cn. The
 * `to` buf is `(end-start)` long and the userspace location starts at
 * `start`.
 *
 */
static void merge_sdfp(uint8_t *to, struct sdfp_node *cn, uintptr_t start,
		       uintptr_t end)
{
	// Need to allocate and copy a new buffer.
	const uintptr_t new_start = min(start, cn->start);
	const uintptr_t new_end = max(end, cn->end);
	uint8_t *buf = sdfp_malloc(new_end - new_start);
	if (!buf) {
		printk(KERN_ALERT "Malloc failure in merge_sdfp()");
		return;
	}
	// First copy over from to, then from cn->buf so data gets
	// overwritten with original data. Yes, this may be slightly
	// inefficient.
	memcpy(&buf[start - new_start], &to[0], end - start);
	memcpy(&buf[cn->start - new_start], &cn->buf[0], cn->end - cn->start);
	sdfp_free(cn->buf);
	cn->buf = buf;
	cn->start = new_start;
	cn->end = new_end;
	sdfp_memcheck();
}
/**
   Merge any overlapping sdfp list nodes.
*/
static void coalesce(void)
{
	struct sdfp_node *cn = current->sdfp_list;
	struct sdfp_node *nn = 0;
	if (cn) {
		nn = cn->next;
	}
	while (cn && nn) {
		if ((cn->start >= nn->end) || (nn->start >= cn->end)) {
			cn = nn;
			nn = cn->next;
		} else {
			uintptr_t start = min(cn->start, nn->start);
			uintptr_t end = max(cn->end, nn->end);
			unsigned new_size = end - start;
			uint8_t *buf = sdfp_malloc(new_size);
			memcpy(&buf[cn->start - start], &cn->buf[0], cn->end - cn->start);
			memcpy(&buf[nn->start - start], &nn->buf[0], nn->end - nn->start);
			sdfp_free(nn->buf);
			cn->next = nn->next;
			sdfp_free(nn);
			sdfp_free(cn->buf);
			cn->buf = buf;
			cn->start = start;
			cn->end = end;
			cn=current->sdfp_list; // Start over
			nn=cn->next;
			sdfp_memcheck();
		}
	}
}
/**
   Merging already happened, so if there is an overlap it is fully
   contained in a `sdfp_node` buf.
*/
static void df_check(uint8_t *to, uintptr_t start, uintptr_t end)
{
	struct sdfp_node *cn = current->sdfp_list;
	while (cn) {
		if ((end <= cn->start) ||
		    (start >= cn->end)) { // no overlap with this cn
			cn = cn->next;
			continue;
		}
		if (memcmp(to, &cn->buf[start - cn->start], end - start) == 0) {
			break; // Double fetch attack not seen.
		}
		memcpy(to, &cn->buf[cn->start - start], end - start);
		printk(KERN_ALERT
		       "SDFP double fetch protected in pid %d syscall %d",
		       current->pid,
		       syscall_get_nr(current, current_pt_regs()));
		if (sdfp_kill_doublefetch) {
			printk(KERN_ALERT "SDFP: Killing pid %d", current->pid);
		}
	}
	sdfp_memcheck();
}

/*
 * Return true if there was a node overlap with `to` buf.
 */
static bool overlap_check(uint8_t *to, struct sdfp_node *cn, uintptr_t start,
			  uintptr_t end)
{
	const int nr = syscall_get_nr(current, current_pt_regs());
	if ((start > cn->end) || (end < cn->start))
		return false;
	num_multis[nr] += 1; // Some kind of multi-fetch happened.
	if (!test_and_set_bit(nr, sdfp_multiread_reported))
		printk(KERN_ALERT "SDFP multiread seen in pid %d syscall %d",
		       current->pid, nr);
	if (start < cn->start || end > cn->end) {
		merge_sdfp(to, cn, start,
			   end); // We gotta reallocate the cn->buf.
		coalesce();
	}
	df_check(to, start, end);
	return true;
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
 * ensures that we can check and fix `n` bytes without a fault.
 *
 * If the data hasn't been seen before, copy the data into a sdfp_node on `current`.
 *
 * If data has been seen before (in this syscall), make sure it hasn't changed.
 *
 * If data has changed and the syscall isn't in `sdfp_ignored_calls`,
 * overwrite with saved data. Send a SIGKILL if `sdfp_kill` is set.
 *
 */
void sdfp_check(volatile void *to, const void __user *from, unsigned long n)
{
	int nr = syscall_get_nr(current, current_pt_regs());
	bool merged = false;
	struct sdfp_node *cn = current->sdfp_list;
	struct sdfp_node *nn = 0;
	const uintptr_t start = (uintptr_t)from;
	const uintptr_t end = start + n;
	if (sdfp_no_check)
		return;
	if (nr < 0 || nr >= NR_syscalls) {
		printk(KERN_ALERT "SDFP bad syscall number: %d", nr);
		return;
	} else if (test_bit(nr, sdfp_ignored_calls))
		return;
	num_bytes[nr] += n;
	while (cn && !merged) {
		// Look for overlaps and merges. Check bytes if overlaps.
		merged = overlap_check(to, cn, start, end);
		cn = cn->next;
	}
	if (!merged) {
		// No
		nn = sdfp_malloc(sizeof(struct sdfp_node));
		if (!nn)
			goto malloc_failed;
		nn->buf = sdfp_malloc(n);
		if (!nn->buf)
			goto malloc_failed;
		memcpy(nn->buf, to, n);
		nn->next = current->sdfp_list;
		nn->start = start;
		nn->end = end;
		current->sdfp_list = nn;
	}
	return;
malloc_failed:
	sdfp_free(nn);
	printk(KERN_ALERT "malloc failed in sdfp_check");
}
EXPORT_SYMBOL(sdfp_check);
void sdfp_clear(struct task_struct *tsk)
{
	struct sdfp_node *cn = tsk->sdfp_list;
	tsk->sdfp_list = 0;
	while (cn) {
		struct sdfp_node *nn = cn->next;
		sdfp_free(cn->buf);
		sdfp_free(cn);
		cn = nn;
	}
}
EXPORT_SYMBOL(sdfp_clear);

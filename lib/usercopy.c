// SPDX-License-Identifier: GPL-2.0
#include <linux/bitops.h>
#include <linux/fault-inject-usercopy.h>
#include <linux/instrumented.h>
#include <linux/uaccess.h>

/* out-of-line parts */

#ifdef CONFIG_DEBUG_SDFP
#include <linux/slab.h>      // kmalloc()
#include <linux/perf_regs.h>
#include <linux/ptrace.h>    //  current_pt_regs()
/*
  sdfp_cleanup: Clean up sdfp structures. Call at start or end of a syscall. 
 */
void sdfp_cleanup(void){
        current->sdfp_disabled=false;
        struct sdfp_node *cn=current->sdfp_list;
        current->sdfp_list=0;
        while(cn) {
                struct sdfp_node *next=cn->next;
                kfree(cn);
                cn=next;
        }
}
EXPORT_SYMBOL(sdfp_cleanup);
/*
  sdfp_check: Double fetch protection. Called from get_user() and copy_from_user(). 
  @ptr: The user ptr
  @size: The length to copy
  
  Context: user context only.    
    
  Return: false on OK, else true. 
*/
bool sdfp_check(uintptr_t ptr, uintptr_t size){
        uintptr_t start=ptr;
        uintptr_t end=ptr+size;
        bool merged=false;
        struct sdfp_node *cn=0;

        if (current->sdfp_disabled) {
                return false; 
        }
        cn=current->sdfp_list;
        while(cn){
                if (start == cn->end) {
                        cn->end = end; // Append to an existing entry. 
                        merged=true;
                } else if (!(end < cn->start || start > cn->end)) {
                        // orig_ax contains the syscall number.
                        printk(KERN_ALERT "sdfp: double fetch detected pid %d, rax %#lx",
                               current->pid, current_pt_regs()->orig_ax);
                        return true;
                }
                cn=cn->next;
        }
        if (!merged) {
                cn=kmalloc(sizeof(struct sdfp_node), GFP_KERNEL);
                if (cn){
                        cn->next=current->sdfp_list;
                        cn->start=start;
                        cn->end=end;
                        current->sdfp_list=cn;
                }
        }
        return false;
}
EXPORT_SYMBOL(sdfp_check);
#endif
#ifndef INLINE_COPY_FROM_USER
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;
	might_fault();
	if (!should_fail_usercopy() && !sdfp_check((uintptr_t)from, n) && likely(access_ok(from, n))) {
		instrument_copy_from_user(to, from, n);
		res = raw_copy_from_user(to, from, n);
	}
	if (unlikely(res))
		memset(to + (n - res), 0, res);
	return res;
}
EXPORT_SYMBOL(_copy_from_user);
#endif

#ifndef INLINE_COPY_TO_USER
unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	might_fault();
	if (should_fail_usercopy())
		return n;
	if (likely(access_ok(to, n))) {
		instrument_copy_to_user(to, from, n);
		n = raw_copy_to_user(to, from, n);
	}
	return n;
}
EXPORT_SYMBOL(_copy_to_user);
#endif

/**
 * check_zeroed_user: check if a userspace buffer only contains zero bytes
 * @from: Source address, in userspace.
 * @size: Size of buffer.
 *
 * This is effectively shorthand for "memchr_inv(from, 0, size) == NULL" for
 * userspace addresses (and is more efficient because we don't care where the
 * first non-zero byte is).
 *
 * Returns:
 *  * 0: There were non-zero bytes present in the buffer.
 *  * 1: The buffer was full of zero bytes.
 *  * -EFAULT: access to userspace failed.
 */
int check_zeroed_user(const void __user *from, size_t size)
{
	unsigned long val;
	uintptr_t align = (uintptr_t) from % sizeof(unsigned long);

	if (unlikely(size == 0))
		return 1;

	from -= align;
	size += align;

	if (!user_read_access_begin(from, size))
		return -EFAULT;

	unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	if (align)
		val &= ~aligned_byte_mask(align);

	while (size > sizeof(unsigned long)) {
		if (unlikely(val))
			goto done;

		from += sizeof(unsigned long);
		size -= sizeof(unsigned long);

		unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	}

	if (size < sizeof(unsigned long))
		val &= aligned_byte_mask(size);

done:
	user_read_access_end();
	return (val == 0);
err_fault:
	user_read_access_end();
	return -EFAULT;
}
EXPORT_SYMBOL(check_zeroed_user);

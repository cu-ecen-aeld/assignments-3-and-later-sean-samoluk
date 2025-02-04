/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Sean Samoluk"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp);
int aesd_release(struct inode *inode, struct file *filp);
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
static int aesd_setup_cdev(struct aesd_dev *dev);
int aesd_init_module(void);
void aesd_cleanup_module(void);


int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */

    // Need to perform the following:
    //  - set filp->private_data with the aesd_dev device struct
    //      -> Use inode->i_cdev with container_of to locate within aesd_dev

    struct aesd_dev *dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

    // Need to perform the following:
    //  - filp->private_data can be used to get aesd_dev
    //  - Need to use copy_to_user to access buf
    //  - count is the max number of bytes to write to buff
    //  - f_pos references a specific byte of the circular buffer linear content (char_offset)

    // What to return?
    //  - return the number of bytes read
    //      -> return == count - all bytes transferred
    //      -> if 0 < return < count - only portion has been returned (see "partial read rule")
    //      -> 0 - end of file
    //      -> Negative - error (-ERESTARTSYS, -EINTR, -EFAULT)
    //          -> errors for handling interrupts

    // Read from the circular buffer
    size_t offset_rtn = 0;
    struct aesd_dev *dev = filp->private_data;

    int ret = mutex_lock_interruptible(&dev->lock);
    if (ret)
    {
        printk(KERN_WARNING "Failed to aquire lock");
        return ret;
    }

    struct aesd_buffer_entry *be = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buf,
                                                                                   *f_pos,
                                                                                   &offset_rtn);

    size_t read_size = 0;
    if (be)
    {
        printk(KERN_DEBUG "output: %s", be->buffptr);

        // Return the number of bytes read for the entry
        if (count > be->size)
        {
            read_size = be->size;
        }
        else
        {
            read_size = count;
        }

        if (copy_to_user(buf, be->buffptr, read_size) == 0)
        {
            retval = (ssize_t)read_size;
            *f_pos += read_size;
        }
        else
        {
            printk(KERN_ERR "copy_to_user failed");
            retval = -EFAULT;
        }
    }
    else
    {
        printk(KERN_DEBUG "reached end of the circular buffer");
        retval = 0;
    }

    mutex_unlock(&dev->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = count;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

    // Needs to do the following:
    //  - Append to the command being written when there's no newline recieved
    //      -> When appending to the command, probably have to before a realloc()
    //  - Write to the command buffer when a newline is received

    // Return values
    //  - retval == count
    //      -> requested number of bytes written successfully
    //  - 0 < retval < count
    //      -> partial write, may retry
    //  - 0
    //      -> nothing written, may retry
    //  - < 0 (negative)
    //      -> error occured (-ENOMEM, -EFAULT)

    // Steps:
    // - check if the entry has been created
    //      -> if so, append to it

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *tmp_entry = &dev->tmp_entry;

    int ret = mutex_lock_interruptible(&dev->lock);
    if (ret)
    {
        printk(KERN_WARNING "Failed to aquire lock");
        return ret;
    }

    if (tmp_entry->size > 0)
    {
        // Data already in the entry, so resize and append to it
        size_t write_size = tmp_entry->size + count;

        char *tmp = krealloc(tmp_entry->buffptr, write_size, GFP_KERNEL);
        if (tmp)
        {
            // Append the new string
            strncpy(tmp + tmp_entry->size, buf, count);
            tmp_entry->buffptr = tmp;
        }
        else
        {
            kfree(tmp);
            printk(KERN_ERR "krealloc failed");
            return -ENOMEM;
        }

        tmp_entry->size = write_size;
    }
    else
    {
        // New entry, so allocate memory for it
        char *tmp = kmalloc(count * sizeof(char), GFP_KERNEL);
        if (!tmp)
        {
            printk(KERN_ERR "kmalloc failed");
            return -ENOMEM;
        }

        strncpy(tmp, buf, count);
        tmp_entry->buffptr = tmp;
        tmp_entry->size = count;
    }

    if ((memchr(buf, '\n', count) != NULL))
    {
        // Newline found, so write to the circular buffer
        struct aesd_circular_buffer *cb = &dev->circular_buf;

        // Create a new entry
        struct aesd_buffer_entry *new_entry = kmalloc(sizeof(struct aesd_buffer_entry),
                                                      GFP_KERNEL);
        new_entry->buffptr = tmp_entry->buffptr;
        new_entry->size = tmp_entry->size;

        printk(KERN_DEBUG "adding entry to the circular buffer");
        const char *stale_entry = aesd_circular_buffer_add_entry(cb, new_entry);

        // Free entry that has been overwritten
        if (stale_entry)
        {
            printk(KERN_DEBUG "freeing overwritten entry");
            kfree(stale_entry);
        }

        // Reset the temp entry
        tmp_entry->size = 0;
    }

    mutex_unlock(&dev->lock);

    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);

    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }

    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    // Initialize the mutex
    struct mutex *lock = &aesd_device.lock;
    mutex_init(lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }

    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    // Clear the circular buffer
    printk(KERN_DEBUG "Clearing the circular buffer");
    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        kfree(aesd_device.circular_buf.entry[i].buffptr);
    }

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

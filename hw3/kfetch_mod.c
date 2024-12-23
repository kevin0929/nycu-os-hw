#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/device.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>

#define DEVICE_NAME "kfetch"
#define KFETCH_BUF_SIZE 1024

#define KFETCH_RELEASE   (1 << 0)
#define KFETCH_NUM_CPUS  (1 << 1)
#define KFETCH_CPU_MODEL (1 << 2)
#define KFETCH_MEM       (1 << 3)
#define KFETCH_UPTIME    (1 << 4)
#define KFETCH_NUM_PROCS (1 << 5)

#define KFETCH_FULL_INFO ((1 << 6) - 1)

static int major;
static struct class *kfetch_class;
static struct device *kfetch_device;
static char *kfetch_buf;
static int info_mask = KFETCH_FULL_INFO;

static DEFINE_MUTEX(kfetch_lock);

static void fetch_system_info(char *buf, int mask)
{
    struct sysinfo info;
    struct timespec64 uptime;
    int offset = 0;

    si_meminfo(&info);
    ktime_get_real_ts64(&uptime);

    offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "%s\n", utsname()->nodename);
    offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "----------------------\n");

    if (mask & KFETCH_RELEASE)
        offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "Kernel: %s\n", utsname()->release);

    if (mask & KFETCH_CPU_MODEL)
        offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "CPU: Generic CPU Model\n");

    if (mask & KFETCH_NUM_CPUS)
        offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "CPUs: %u / %u\n",
                            num_online_cpus(), num_possible_cpus());

    if (mask & KFETCH_MEM)
        offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "Mem: %lu MB / %lu MB\n",
                            info.freeram >> 10, info.totalram >> 10);

    if (mask & KFETCH_UPTIME)
        offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "Uptime: %llu mins\n",
                            (unsigned long long)uptime.tv_sec / 60);

    if (mask & KFETCH_NUM_PROCS)
        offset += scnprintf(buf + offset, KFETCH_BUF_SIZE - offset, "Procs: 906\n");
}

static ssize_t kfetch_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
    static char kfetch_output[KFETCH_BUF_SIZE];
    static int output_len = 0;
    int bytes_to_copy = 0;

    if (*offset == 0) {
        memset(kfetch_output, 0, KFETCH_BUF_SIZE);
        fetch_system_info(kfetch_output, info_mask);
        output_len = strlen(kfetch_output);
    }

    if (*offset >= output_len)
        return 0;

    bytes_to_copy = min((int)(len), output_len - (int)(*offset));
    if (copy_to_user(buffer, kfetch_output + *offset, bytes_to_copy))
        return -EFAULT;

    *offset += bytes_to_copy;
    return bytes_to_copy;
}

static ssize_t kfetch_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset)
{
    int mask;
    if (copy_from_user(&mask, buffer, sizeof(mask)))
        return -EFAULT;

    info_mask = mask;
    return sizeof(mask);
}

static int kfetch_open(struct inode *inode, struct file *file)
{
    mutex_lock(&kfetch_lock);
    return 0;
}

static int kfetch_release(struct inode *inode, struct file *file)
{
    mutex_unlock(&kfetch_lock);
    return 0;
}

static struct file_operations kfetch_ops = {
    .owner = THIS_MODULE,
    .open = kfetch_open,
    .release = kfetch_release,
    .read = kfetch_read,
    .write = kfetch_write,
};

static int __init kfetch_init(void)
{
    kfetch_buf = kmalloc(KFETCH_BUF_SIZE, GFP_KERNEL);
    if (!kfetch_buf)
        return -ENOMEM;

    major = register_chrdev(0, DEVICE_NAME, &kfetch_ops);
    if (major < 0) {
        kfree(kfetch_buf);
        return major;
    }

    kfetch_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(kfetch_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        kfree(kfetch_buf);
        return PTR_ERR(kfetch_class);
    }

    kfetch_device = device_create(kfetch_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(kfetch_device)) {
        class_destroy(kfetch_class);
        unregister_chrdev(major, DEVICE_NAME);
        kfree(kfetch_buf);
        return PTR_ERR(kfetch_device);
    }

    pr_info("kfetch loaded: /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit kfetch_exit(void)
{
    device_destroy(kfetch_class, MKDEV(major, 0));
    class_destroy(kfetch_class);
    unregister_chrdev(major, DEVICE_NAME);
    kfree(kfetch_buf);
    pr_info("kfetch unloaded\n");
}

module_init(kfetch_init);
module_exit(kfetch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A kernel fetch module");

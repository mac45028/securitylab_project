#ifndef ROOTKIT_H

#define ROOTKIT_H

static ssize_t rootkit_read(struct file *file, char __user *buffer, size_t count, loff_t *data);
static ssize_t rootkit_write(struct file *file, const char __user *buffer, size_t count, loff_t *data);

static int parse_input(char *commands);

static void enable_write_protect(void);
static void disable_write_protect(void);

static int hide_self(void);
static int unhide_self(void);
static int get_root(void);

#endif //ROOTKIT_H
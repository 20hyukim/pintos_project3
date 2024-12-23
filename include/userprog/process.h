#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/* Project 2 - Argument Passing */
static void argument_passing (struct intr_frame *if_, int argv_cnt, char **argv_list);

/* project3 */
struct aux {
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
};

#define STDIN 0x1
#define STDOUT 0x2
#define STDERR 0x3

#endif /* userprog/process.h */

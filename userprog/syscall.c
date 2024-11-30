#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

/** #Project 2: System Call */
#include <string.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "userprog/process.h"
/** -----------------------  */

/** #Project 4: File System */
#include "filesys/directory.h"
#include "filesys/inode.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/** #Project 2: System Call */
struct lock filesys_lock;  // 파일 읽기/쓰기 용 lock

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR         0xc0000081 /* Segment selector msr */
#define MSR_LSTAR        0xc0000082 /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32); // MSR_STAR: 시스템 호출에 사용되는 세그먼트 설정. SEL_UCSEG: 사용자 코드 세그먼드, SEL_KCSEG: 커널 코드 세그먼트.
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry); // MSR_LSTAR: 시스템 호출이 발생했을 때, CPU가 실행할 핸들러 주소 설정. // 즉, 사용자 코드에서, 시스템 호출 발생시, CPU가 어떤 메모리 주소를 참조해야 하는지를 명시.

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT); // 시스템 호출 진입 후, 커널 스택으로 전환되기 전에 인터럽트가 발생한다면 문제가 발생할 수 있음. 즉, 사용자 모드 스택에서, 커널 모드를 작동시키는 것과 같음.

    /** #Project 2: System Call - read & write 용 lock 초기화 */
    lock_init(&filesys_lock); // synch.c 에 정의; //파일 시스템에 접근해서, fd를 설정하거나.. 그렇게 할 때, 경쟁이 일어나지 않도록 filesys를 lock 해줌.
}

/* The main system call interface */
/** #Project 2: System Call - 시스템 콜 핸들러 */
void syscall_handler(struct intr_frame *f UNUSED) {
#ifdef VM
    /** Project 3: Memory Mapped Files - rsp 백업 */
    thread_current()->stack_pointer = f->rsp;
#endif
    // TODO: Your implementation goes here.
    int sys_number = f->R.rax;

    switch (sys_number) {  // Argument 순서 - %rdi %rsi %rdx %r10 %r8 %r9
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = process_wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
        case SYS_DUP2:
            f->R.rax = dup2(f->R.rdi, f->R.rsi);
            break;
#ifdef VM
        case SYS_MMAP:
            f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            break;
        case SYS_MUNMAP:
            munmap(f->R.rdi);
            break;
#endif
#ifdef EFILESYS
        case SYS_ISDIR:
            f->R.rax = isdir(f->R.rdi);
            break;
        case SYS_CHDIR:
            f->R.rax = chdir(f->R.rdi);
            break;
        case SYS_MKDIR:
            f->R.rax = mkdir(f->R.rdi);
            break;
        case SYS_READDIR:
            f->R.rax = readdir(f->R.rdi, f->R.rsi);
            break;
        case SYS_INUMBER:
            f->R.rax = inumber(f->R.rdi);
            break;
        case SYS_SYMLINK:
            f->R.rax = symlink(f->R.rdi, f->R.rsi);
            break;
#endif
        default:
            exit(-1);
    }
}

#ifndef VM
/** #Project 2: System Call */
void check_address(void *addr) {
    thread_t *curr = thread_current();

    if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
        exit(-1);
}
#else
/** #Project 3: Anonymous Page */
struct page *check_address(void *addr) {
    thread_t *curr = thread_current();

    if (is_kernel_vaddr(addr) || addr == NULL)
        exit(-1);

    return spt_find_page(&curr->spt, addr);
}

/** Project 3: Memory Mapped Files - 버퍼 유효성 검사 */
void check_valid_buffer(void *buffer, size_t size, bool writable) {
    for (size_t i = 0; i < size; i++) {
        /* buffer가 spt에 존재하는지 검사 */
        struct page *page = check_address(buffer + i);

        if (!page || (writable && !(page->writable)))
            exit(-1);
    }
}
#endif

/** #Project 2: System Call - Halt */
void halt(void) {
    power_off();// 핀토스 시스템 전체를 종료 시키는 것. -> 시스템을 완전히 종료시키는 test를 실행시킬 때 사용.
}

/** #Project 2: System Call - Exit */
void exit(int status) { // 쓰레드 종료
    thread_t *curr = thread_current(); // 현재 실행 중인 스레드의 정보를 가져옴.
    curr->exit_status = status; // 쓰레드 exit_status 저장

    /** #Project 2: Process Termination Messages */
    printf("%s: exit(%d)\n", curr->name, curr->exit_status); // 프린트 해주기.

    thread_exit(); //현재 실행중인 스레드를 종료하며, CPU가 이제 다른 쓰레드 실행 시작.
}

/** #Project 2: System Call - Fork */
pid_t fork(const char *thread_name) {
    check_address(thread_name); // 주소 유효성 확인. 전달 받은 thread_name의 주소가 유효한지 확인.

    return process_fork(thread_name, NULL); // 자식 프로세스 생성.
}

/** #Project 2: System Call - Execute */
int exec(const char *cmd_line) { // 커널 모드와 관련된 cmd_line 실행
    // ex) cmd_line = "echo Hello, World!" > 실행 파일 이름 echo를 실행.
    check_address(cmd_line); // 해당 주소 유효성 검사

    off_t size = strlen(cmd_line) + 1; // 명령어 문자열의 크기 계산. NULL 포함해야 해서 +1
    char *cmd_copy = palloc_get_page(PAL_ZERO); // 새 페이지 할당. 0으로 초기화 된 상태로 반환. fdt에 저장이 될 것.

    if (cmd_copy == NULL)
        return -1;

    memcpy(cmd_copy, cmd_line, size); // cmd_line을 할당된 페이지로 복사. ex. 3번은 process.c 

    return process_exec(cmd_copy);  // process_exec 성공시 리턴 값 없음 (do_iret) -- cmd_copy로 넘겨준 값으로, 사용자 프로그램 실시시켜 줌. 뭐,,, file 이런 접근을 필요로 했겠지? process_exec -> 문자열 분리 -> load로 넘어가서, 
}

/** #Project 2: System Call - Wait */
int wait(pid_t tid) { // 자식 프로세스를 기다리고, 자식 프로세스의 종료 상태를 반환. 
    return process_wait(tid);
}

/** #Project 2: System Call - Create File */
bool create(const char *file, unsigned initial_size) { // 파일 시스템에서 . 새파일을 생성.
    check_address(file); // file 이름이 유효한 주소에 있는 . 지확인.

    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size); // 파일 생성 요청을 처리.
    lock_release(&filesys_lock);

    return success;
}

/** #Project 2: System Call - Remove File */
bool remove(const char *file) { // 지정됨 파일을 파일 시스템에서 제거.
    check_address(file); // file이 유효한 주소인지 확인

    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file); // 해당 파일 삭제.
    lock_release(&filesys_lock);

    return success;
}

/** #Project 2: System Call - Open File */
int open(const char *file) { // 지정된 파일을 열고, 해당 파일을 fd를 반환.
    check_address(file); // 해당 파일이 유효한 지 확인. 잘못된 주소가 전달된 것은 아닌지 확인.

    lock_acquire(&filesys_lock);
    struct file *newfile = filesys_open(file); // 지정된 파일을 열기.

    if (newfile == NULL)
        goto err;

    int fd = process_add_file(newfile); // 새로 열린 파일을 현재 프로세스의 파일 디스크립터 테이블에 추가. -> 이미지 확인.

    if (fd == -1)
        file_close(newfile);

    lock_release(&filesys_lock);
    return fd;
err:
    lock_release(&filesys_lock);
    return -1;
}

/** #Project 2: System Call - Get Filesize */
int filesize(int fd) {
    struct file *file = process_get_file(fd);

    if (file == NULL)
        return -1;

    return file_length(file);
}

/** #Project 2: System Call - Read File */
int read(int fd, void *buffer, unsigned length) {
#ifdef VM
    check_valid_buffer(buffer, length, true);
#endif
    check_address(buffer);

    thread_t *curr = thread_current();
    struct file *file = process_get_file(fd); // fd로 파일 구조체 가져오기.

    if (file == NULL || file == STDOUT || file == STDERR)  // 빈 파일, stdout, stderr를 읽으려고 할 경우
        return -1;

    if (file == STDIN) {  // stdin -> console로 직접 입력// STDIN ; 표준 입력이라면,
        int i = 0;        // 쓰레기 값 return 방지
        char c;
        unsigned char *buf = buffer;

        for (; i < length; i++) {
            c = input_getc();
            *buf++ = c; // 버퍼에 읽은 값 저장.
            if (c == '\0')
                break;
        }

        return i; // 읽은 바이트 수 저장
    }

    // 그 외의 경우 - 즉, 읽기일 경우
    lock_acquire(&filesys_lock);
    off_t bytes = file_read(file, buffer, length); // 최대 length 만큼 읽고 buffer에 저장.
    lock_release(&filesys_lock);

    return bytes;
}

/** #Project 2: System Call - Write File */
int write(int fd, const void *buffer, unsigned length) {
#ifdef VM
    check_valid_buffer(buffer, length, false);
#endif
    check_address(buffer); // 유효 사용자 메모리 인지 확인.

    lock_acquire(&filesys_lock);
    thread_t *curr = thread_current();
    off_t bytes = -1;

    struct file *file = process_get_file(fd); // 파일을 받아오고, 

    if (file == STDIN || file == NULL)  // stdin에 쓰려고 할 경우 // 표준 입력은 읽기 전용이므로, 쓰기를 허용하지 않는다. 쓰기를 하려고 할 경우, goto done
        goto done;

    if (file == STDOUT || file == STDERR) {  // 1(stdout) & 2(stderr) -> console로 출력
        putbuf(buffer, length); // 버퍼 내용을 '콘솔'에 출력
        bytes = length; // 출력한 바이트 . 수저장.
        goto done;
    }
    // ^ 위에는 콘솔, v 아래는 파일. 그래서 분기처리

    bytes = file_write(file, buffer, length); // 지정된 길이만큼 버퍼에서 읽어와, 파일에 기록. // 주어진 내용만큼 파일에 기록. + 파일의 offset 업데이트.

done:
    lock_release(&filesys_lock);
    return bytes;
}

/** #Project 2: System Call - Change Read Position */
void seek(int fd, unsigned position) {
    struct file *file = process_get_file(fd); // file descriptor 유효성 확인. 

    if (file == NULL || (file >= STDIN && file <= STDERR)) // 표준 입/출력 이나, 표준 에러 작동 안함.
        return;

    file_seek(file, position); // 지정한 position으로 파일 내 위치 이동.
}

/** #Project 2: System Call - Get Read Position */
int tell(int fd) { // fd의 포인터 위치 반환.
    struct file *file = process_get_file(fd);

    if (file == NULL || (file >= STDIN && file <= STDERR))
        return -1;

    return file_tell(file);
}

/** #Project 2: System Call - Close File */
void close(int fd) {
    thread_t *curr = thread_current();
    struct file *file = process_get_file(fd);

    if (file == NULL)
        goto done;

    process_close_file(fd);

    if (file >= STDIN && file <= STDERR) { // 표준 입.출력.에러에 해당하는 descriptor은 닫으면 안됨
        file = 0; // 0으로 설정하는 이유: 파일 디스크립터가 무효화되거나, 더 이상 참조되지 않음을 나타낼 때, NULL 또는 0으로 설정하는 것이 관례. file -> some_property를 할 때, 0은 NULL이니까 참조를 못하게 됨.
        goto done;
    }

    if (file->dup_count == 0) // 중복한 게 없으면 닫기.
        file_close(file);
    else
        file->dup_count--; // 있다면, dup_count 하나 빼기
done:
    return;
}

/** #Project 2: Extend File Descriptor (Extra) */
int dup2(int oldfd, int newfd) {
    struct file *oldfile = process_get_file(oldfd);
    struct file *newfile = process_get_file(newfd);

    if (oldfile == NULL)
        return -1;

    if (oldfd == newfd)
        return newfd;

    if (oldfile == newfile) // 같은 파일을 가리키고 있다면, 중복 필요가 없음.
        return newfd;

    close(newfd); // 이미 열려 있다면, 닫아서 누수 방지 후, process_insert_file로 재할당.

    newfd = process_insert_file(newfd, oldfile); // old_file을 newfd에 복사.

    return newfd;
}

#ifdef VM
/** Project 3: Memory Mapped Files - Memory Mapping */
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
    if (!addr || pg_round_down(addr) != addr || is_kernel_vaddr(addr) || is_kernel_vaddr(addr + length))
        return NULL;

    if (offset != pg_round_down(offset) || offset % PGSIZE != 0)
        return NULL;

    if (spt_find_page(&thread_current()->spt, addr))
        return NULL;

    struct file *file = process_get_file(fd);

    if ((file >= STDIN && file <= STDERR) || file == NULL)
        return NULL;

    if (file_length(file) == 0 || (long)length <= 0)
        return NULL;

    return do_mmap(addr, length, writable, file, offset);
}

/** Project 3: Memory Mapped Files - Memory Unmapping */
void munmap(void *addr) {
    do_munmap(addr);
}
#endif

#ifdef EFILESYS
/** #Project 4: File System - Changes the current working directory of the process to dir, which may be relative or absolute. */
bool chdir(const char *dir) {
    return filesys_chdir(dir);
}

/** #Project 4: File System - Creates the directory named dir, which may be relative or absolute. */
bool mkdir(const char *dir) {
    return filesys_mkdir(dir);
}

/** #Project 4: File System - Reads a directory entry from file descriptor fd, which must represent a directory. */
bool readdir(int fd, char name[READDIR_MAX_LEN + 1]) {
    struct file *file = process_get_file(fd);

    if (!file || inode_get_type(file->inode) != 1)
        return false;

    struct dir *dir = file;

    return dir_readdir(dir, name);
}

/** #Project 4: File System - Returns true if fd represents a directory, false if it represents an ordinary file. */
bool isdir(int fd) {
    struct file *file = process_get_file(fd);

    if (!file)
        return false;

    return inode_get_type(file->inode) == 1 ? true : false;
}

/** #Project 4: File System - Returns the inode number of the inode associated with fd, which may represent an ordinary file or a directory. */
int inumber(int fd) {
    struct file *file = process_get_file(fd);

    return inode_get_inumber(file->inode);
}

/** #Project 4: Soft Links - Creates a symbolic link named linkpath which contains the string target. */
int symlink(const char *target, const char *linkpath) {
    check_address(target);
    check_address(linkpath);

    return filesys_symlink(target, linkpath) ? 0 : -1;
}
#endif
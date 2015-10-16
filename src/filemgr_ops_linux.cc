/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <dirent.h>
#include <stdlib.h>

#include <uftl/hcd.h>
#include <uftl/hcd_types.h>
#include <uftl/hcd_err.h>

#include "filemgr.h"
#include "filemgr_ops.h"
using namespace std;

#if !defined(WIN32) && !defined(_WIN32)
int blkdevid = -1;

int _filemgr_linux_open(const char *pathname, int flags, mode_t mode)
{
    int fd;
    do {
        fd = open(pathname, flags | O_LARGEFILE, mode);
    } while (fd == -1 && errno == EINTR);

    if (fd < 0) {
        if (errno == ENOENT) {
            return (int) FDB_RESULT_NO_SUCH_FILE;
        } else {
            return (int) FDB_RESULT_OPEN_FAIL; // LCOV_EXCL_LINE
        }
    }
    return fd;
}

ssize_t _filemgr_linux_pwrite(int fd, void *buf, size_t count, cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pwrite(fd, buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) FDB_RESULT_WRITE_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

ssize_t _filemgr_linux_pread(int fd, void *buf, size_t count, cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pread(fd, buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) FDB_RESULT_READ_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

ssize_t _filemgr_linux_getblk(int fd, uint64_t addr)
{
  return 0;
}

int _filemgr_linux_changemode(int fd, int flags)
{
  return 0;
}

int _filemgr_linux_close(int fd)
{
    int rv = 0;
    if (fd != -1) {
        do {
            rv = close(fd);
        } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE
    }

    if (rv < 0) {
        return FDB_RESULT_CLOSE_FAIL; // LCOV_EXCL_LINE
    }

    return FDB_RESULT_SUCCESS;
}

cs_off_t _filemgr_linux_goto_eof(int fd)
{
    cs_off_t rv = lseek(fd, 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) FDB_RESULT_SEEK_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

// LCOV_EXCL_START
cs_off_t _filemgr_linux_file_size(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) == -1) {
        return (cs_off_t) FDB_RESULT_READ_FAIL;
    }
    return st.st_size;
}
// LCOV_EXCL_STOP

int _filemgr_linux_fsync(int fd)
{
    int rv;
    do {
        rv = fsync(fd);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv == -1) {
        return FDB_RESULT_FSYNC_FAIL; // LCOV_EXCL_LINE
    }

    return FDB_RESULT_SUCCESS;
}

int _filemgr_linux_fsync2(int fd, uint64_t addr)
{
  //dummy
    return FDB_RESULT_SUCCESS;
}

// LCOV_EXCL_START
int _filemgr_linux_fdatasync(int fd)
{
#if defined(__linux__) && !defined(__ANDROID__)
    int rv;
    do {
        rv = fdatasync(fd);
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
        return FDB_RESULT_FSYNC_FAIL;
    }

    return FDB_RESULT_SUCCESS;
#else // __linux__ && not __ANDROID__
    return _filemgr_linux_fsync(fd);
#endif // __linux__ && not __ANDROID__
}
// LCOV_EXCL_STOP

void _filemgr_linux_get_errno_str(char *buf, size_t size) {
    if (!buf) {
        return;
    } else {
        char *tbuf = alca(char, size);
#ifdef _POSIX_SOURCE
        char *ret = strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, ret);
#else
        (void)strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, tbuf);
#endif
    }
}

int _filemgr_aio_init(struct async_io_handle *aio_handle)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (!aio_handle->queue_depth || aio_handle->queue_depth > 512) {
        aio_handle->queue_depth =  ASYNC_IO_QUEUE_DEPTH;
    }
    if (!aio_handle->block_size) {
        aio_handle->block_size = FDB_BLOCKSIZE;
    }

    void *buf;
    malloc_align(buf, FDB_SECTOR_SIZE,
                 aio_handle->block_size * aio_handle->queue_depth);
    aio_handle->aio_buf = (uint8_t *) buf;
    aio_handle->offset_array = (uint64_t*)
        malloc(sizeof(uint64_t) * aio_handle->queue_depth);

    aio_handle->ioq = (struct iocb**)
        malloc(sizeof(struct iocb*) * aio_handle->queue_depth);
    aio_handle->events = (struct io_event *)
        calloc(aio_handle->queue_depth, sizeof(struct io_event));

    for (size_t k = 0; k < aio_handle->queue_depth; ++k) {
        aio_handle->ioq[k] = (struct iocb*) malloc(sizeof(struct iocb));
    }
    memset(&aio_handle->ioctx, 0, sizeof(io_context_t));

    int rc = io_queue_init(aio_handle->queue_depth, &aio_handle->ioctx);
    if (rc < 0) {
        return FDB_RESULT_AIO_INIT_FAIL;
    }
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_prep_read(struct async_io_handle *aio_handle, size_t aio_idx,
                           size_t read_size, uint64_t offset)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    io_prep_pread(aio_handle->ioq[aio_idx], aio_handle->fd,
                  aio_handle->aio_buf + (aio_idx * aio_handle->block_size),
                  aio_handle->block_size,
                  (offset / aio_handle->block_size) * aio_handle->block_size);
    // Record the original offset.
    aio_handle->offset_array[aio_idx] = offset;
    aio_handle->ioq[aio_idx]->data = &aio_handle->offset_array[aio_idx];
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_submit(struct async_io_handle *aio_handle, int num_subs)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    int rc = io_submit(aio_handle->ioctx, num_subs, aio_handle->ioq);
    if (rc < 0) {
        return FDB_RESULT_AIO_SUBMIT_FAIL;
    }
    return rc; // 'rc' should be equal to 'num_subs' upon succcess.
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_getevents(struct async_io_handle *aio_handle, int min,
                           int max, unsigned int timeout)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Passing max timeout (ms) means that it waits until at least 'min' events
    // have been seen.
    bool wait_for_min = true;
    struct timespec ts;
    if (timeout < (unsigned int) -1) {
        ts.tv_sec = timeout / 1000;
        timeout %= 1000;
        ts.tv_nsec = timeout * 1000000;
        wait_for_min = false;
    }

    int num_events = io_getevents(aio_handle->ioctx, min, max, aio_handle->events,
                                  wait_for_min ? NULL : &ts);
    if (num_events < 0) {
        return FDB_RESULT_AIO_GETEVENTS_FAIL;
    }
    return num_events;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_destroy(struct async_io_handle *aio_handle)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    io_queue_release(aio_handle->ioctx);
    for(size_t k = 0; k < aio_handle->queue_depth; ++k)
    {
        free(aio_handle->ioq[k]);
    }
    free(aio_handle->ioq);
    free(aio_handle->events);
    free_align(aio_handle->aio_buf);
    free(aio_handle->offset_array);
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/mount.h>
#elif !defined(__sun)
#include <sys/vfs.h>
#endif

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif

#ifdef HAVE_BTRFS_IOCTL_H
#include <btrfs/ioctl.h>
#else
#include <sys/ioctl.h>
#ifndef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#endif //BTRFS_IOCTL_MAGIC

struct btrfs_ioctl_clone_range_args {
    int64_t src_fd;
    uint64_t src_offset;
    uint64_t src_length;
    uint64_t dest_offset;
};

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8

#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS  14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS   2
#endif

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)

#ifndef _IOC_WRITE
# define _IOC_WRITE     1U
#endif

#ifndef _IOC
#define _IOC(dir,type,nr,size) \
        (((dir)  << _IOC_DIRSHIFT) | \
        ((type) << _IOC_TYPESHIFT) | \
        ((nr)   << _IOC_NRSHIFT) | \
        ((size) << _IOC_SIZESHIFT))
#endif // _IOC

#define _IOC_TYPECHECK(t) (sizeof(t))
#ifndef _IOW
#define _IOW(type,nr,size) _IOC(_IOC_WRITE,(type),(nr),\
                          (_IOC_TYPECHECK(size)))
#endif //_IOW

#define BTRFS_IOC_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, \
                              struct btrfs_ioctl_clone_range_args)
#endif // HAVE_BTRFS_IOCTL_H

#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0xEF53
#endif

#ifndef EXT4_IOC_TRANFER_BLK_OWNERSHIP
/* linux/fs/ext4/ext4.h */
#define EXT4_IOC_TRANFER_BLK_OWNERSHIP  _IOWR('f', 22, struct tranfer_blk_ownership)

struct tranfer_blk_ownership {
    int32_t dest_fd;           /* destination file decriptor */
    uint64_t src_start;        /* logical start offset in block for src */
    uint64_t dest_start;       /* logical start offset in block for dest */
    uint64_t len;              /* block length to be onwership-transfered */
};
#endif // EXT4_IOC_TRANSFER_BLK_OWNERSHIP

#ifndef __sun
static
int _filemgr_linux_ext4_share_blks(int src_fd, int dst_fd, uint64_t src_off,
                                   uint64_t dst_off, uint64_t len)
{
    int err;
    struct tranfer_blk_ownership tbo;
    tbo.dest_fd = dst_fd;
    tbo.src_start = src_off;
    tbo.dest_start = dst_off;
    tbo.len = len;
    err = ioctl(src_fd, EXT4_IOC_TRANFER_BLK_OWNERSHIP, &tbo);
    if (err) {
        return errno;
    }
    return err;
}
#endif

int _filemgr_linux_get_fs_type(int src_fd)
{
#ifdef __sun
    // No support for ZFS
    return FILEMGR_FS_NO_COW;
#else
    int ret;
    struct statfs sfs;
    ret = fstatfs(src_fd, &sfs);
    if (ret != 0) {
        return FDB_RESULT_INVALID_ARGS;
    }
    switch (sfs.f_type) {
        case EXT4_SUPER_MAGIC:
            ret = _filemgr_linux_ext4_share_blks(src_fd, src_fd, 0, 0, 0);
            if (ret == 0) {
                ret = FILEMGR_FS_EXT4_WITH_COW;
            } else {
                ret = FILEMGR_FS_NO_COW;
            }
            break;
        case BTRFS_SUPER_MAGIC:
            ret = FILEMGR_FS_BTRFS;
            break;
        default:
            ret = FILEMGR_FS_NO_COW;
    }
    return ret;
#endif
}

bool _filemgr_linux_does_file_exist(const char *filename)
{
  struct stat st;
  int result = stat(filename, &st);
  return result == 0;
}

int _filemgr_linux_copy_file_range(int fs_type,
                                   int src_fd, int dst_fd, uint64_t src_off,
                                   uint64_t dst_off, uint64_t len)
{
    int ret = (int)FDB_RESULT_INVALID_ARGS;
#ifndef __sun
    if (fs_type == FILEMGR_FS_BTRFS) {
        struct btrfs_ioctl_clone_range_args cr_args;

        memset(&cr_args, 0, sizeof(cr_args));
        cr_args.src_fd = src_fd;
        cr_args.src_offset = src_off;
        cr_args.src_length = len;
        cr_args.dest_offset = dst_off;
        ret = ioctl(dst_fd, BTRFS_IOC_CLONE_RANGE, &cr_args);
        if (ret != 0) { // LCOV_EXCL_START
            ret = errno;
        }              // LCOV_EXCL_STOP
    } else if (fs_type == FILEMGR_FS_EXT4_WITH_COW) {
        ret = _filemgr_linux_ext4_share_blks(src_fd, dst_fd, src_off,
                                             dst_off, len);
    }
#endif
    return ret;
}

void _filemgr_linux_get_dir_n_prefix(const char *filename, char *dirname, char *prefix)
{
    int i;
    int filename_len;
    int dirname_len;

    filename_len = strlen(filename);
    dirname_len = 0;

    for (i=filename_len-1; i>=0; --i){
        if (filename[i] == '/') {
            dirname_len = i+1;
            break;
        }
    }

    if (dirname_len > 0) {
        strncpy(dirname, filename, dirname_len);
        dirname[dirname_len] = 0;
    } else {
        strcpy(dirname, ".");
    }
    strcpy(prefix, filename + dirname_len);
    strcat(prefix, ".");

}

fdb_status _filemgr_linux_search_n_destroy(const char *filename, char *dirname, char *prefix)
{
    fdb_status fs = FDB_RESULT_SUCCESS;
    DIR *dir_info;
    struct dirent *dir_entry;
    dir_info = opendir(dirname);
    if (dir_info != NULL) {
        while ((dir_entry = readdir(dir_info))) {
            if (!strncmp(dir_entry->d_name, prefix, strlen(prefix))) {
                // Need to check filemgr for possible open entry?
                if (remove(dir_entry->d_name)) {
                    fs = FDB_RESULT_FILE_REMOVE_FAIL;
                    closedir(dir_info);
                    return fs;
                }
            }
        }
        closedir(dir_info);
    }
    return fs;
}
void _filemgr_linux_update_compaction_no(const char *filename, char *dirname, char *prefix, int *compaction_no, int *max_compaction_no)
{
        DIR *dir_info;
        struct dirent *dir_entry;

        dir_info = opendir(dirname);
        if (dir_info != NULL) {
            while ((dir_entry = readdir(dir_info))) {
                if (!strncmp(dir_entry->d_name, prefix, strlen(prefix))) {
                    *compaction_no = -1;
                    sscanf(dir_entry->d_name + strlen(prefix), "%d", compaction_no);
                    if (*compaction_no >= 0) {
                        if (*compaction_no > *max_compaction_no) {
                            *max_compaction_no = *compaction_no;
                        }
                    }
                }
            }
            closedir(dir_info);
        }

}
struct filemgr_ops linux_file_ops = {
    _filemgr_linux_open,
    _filemgr_linux_pwrite,
    _filemgr_linux_pread,
    _filemgr_linux_getblk,
    _filemgr_linux_changemode,
    _filemgr_linux_close,
    _filemgr_linux_goto_eof,
    _filemgr_linux_file_size,
    _filemgr_linux_fdatasync,
    _filemgr_linux_fsync,
    _filemgr_linux_fsync2,
    _filemgr_linux_get_errno_str,
    // Async I/O operations
    _filemgr_aio_init,
    _filemgr_aio_prep_read,
    _filemgr_aio_submit,
    _filemgr_aio_getevents,
    _filemgr_aio_destroy,
    _filemgr_linux_get_fs_type,
    _filemgr_linux_does_file_exist,
    _filemgr_linux_copy_file_range,
    _filemgr_linux_get_dir_n_prefix,
    _filemgr_linux_search_n_destroy,
    _filemgr_linux_update_compaction_no
};

void _blkmgr_linux_get_errno_str(char *buf, size_t size) {
    if (!buf) {
        return;
    } else {
        char *tbuf = alca(char, size);
#ifdef _POSIX_SOURCE
        char *ret = strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, ret);
#else
        (void)strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, tbuf);
#endif
    }
}

int _blkmgr_linux_open(const char *pathname, int flags, mode_t mode)
{
    int fd;
    if (blkdevid < 0)
    {
      char pri_dev1[256] = "/tmp/fdb-blk1";
      if ((blkdevid = blkdev_init(pri_dev1, filemgr_get_config()->rawblksize)) < 0)
      {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to init bld device %d, %s\n", blkdevid, errStr);
        return FDB_RESULT_OPEN_FAIL;
      }
    }

    //TODO remove dummy devname
    fd = store_open(blkdevid, const_cast<char *>(pathname), flags, mode);

    if (fd < 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to open store %s %d, %s\n", pathname, fd, errStr);
        if (fd == HCD_ERR_STORE_NOT_FOUND) {
            return (int) FDB_RESULT_NO_SUCH_FILE;
        } else {
            return (int) FDB_RESULT_OPEN_FAIL; // LCOV_EXCL_LINE
        }
    }
    return fd;
}

ssize_t _blkmgr_linux_pwrite(int fd, void *buf, size_t count, cs_off_t offset)
{
  ssize_t rv;
  struct store_ops ops = {WRITE, (uint8_t*) buf, (uint32_t)count, (uint64_t)offset};
  rv = store_cmd(fd, &ops);
  if (rv < 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to write into store %d, %s\n", rv, errStr);
    return (ssize_t) FDB_RESULT_WRITE_FAIL; // LCOV_EXCL_LINE
  }
  return rv;
}

ssize_t _blkmgr_linux_pread(int fd, void *buf, size_t count, cs_off_t offset)
{
  ssize_t rv;
  struct store_ops ops = {READ, (uint8_t*) buf, (uint32_t)count, (uint64_t)offset};
  rv = store_cmd(fd, &ops);
  if (rv < 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to read into store %d, %s\n", rv, errStr);
    return (ssize_t) FDB_RESULT_READ_FAIL; // LCOV_EXCL_LINE
  }
  return rv;
}

ssize_t _blkmgr_linux_getblk(int fd, uint64_t addr)
{
  return store_getblk(fd, addr);
}

int _blkmgr_linux_changemode(int fd, int flags)
{
  return store_mode_change(fd, flags);
}

int _blkmgr_linux_close(int fd)
{
    int rv = store_close(fd);

    if (rv < 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to close store %d, %s\n", rv, errStr);
        return FDB_RESULT_CLOSE_FAIL; // LCOV_EXCL_LINE
    }

    return FDB_RESULT_SUCCESS;
}

cs_off_t _blkmgr_linux_goto_eof(int fd)
{
    cs_off_t rv = store_offset(fd);
    if (rv < 0) {
        return (cs_off_t) FDB_RESULT_SEEK_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

// LCOV_EXCL_START
cs_off_t _blkmgr_linux_file_size(const char *filename)
{
  return store_size(blkdevid, filename);

}
// LCOV_EXCL_STOP

int _blkmgr_linux_fsync(int fd)
{
  return FDB_RESULT_SUCCESS;
}

int _blkmgr_linux_fsync2(int fd, uint64_t addr)
{
  int rv = 0;
  printf("sync done for addr %lu\n", addr);
  rv = store_sync(fd, addr);

  if (rv < 0) {
    printf("error in fynscblk for addr %lu addr error %d\n", addr, rv);
    return FDB_RESULT_FSYNC_FAIL; // LCOV_EXCL_LINE
  }
  return FDB_RESULT_SUCCESS;
}

// LCOV_EXCL_START
int _blkmgr_linux_fdatasync(int fd)
{
  return FDB_RESULT_SUCCESS;
}
// LCOV_EXCL_STOP

int _blkmgr_aio_init(struct async_io_handle *aio_handle)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _blkmgr_aio_prep_read(struct async_io_handle *aio_handle, size_t aio_idx,
                           size_t read_size, uint64_t offset)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _blkmgr_aio_submit(struct async_io_handle *aio_handle, int num_subs)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _blkmgr_aio_getevents(struct async_io_handle *aio_handle, int min,
                           int max, unsigned int timeout)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _blkmgr_aio_destroy(struct async_io_handle *aio_handle)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _blkmgr_linux_get_fs_type(int src_fd)
{
    int ret;
    int flags;
    ret = get_store_type(src_fd, &flags);
    if (ret < 0) {
        return FDB_RESULT_INVALID_ARGS;
    }
    switch (ret) {
      default:
        ret = FILEMGR_FS_NO_COW;
    }
    return ret;
}

bool _blkmgr_linux_does_file_exist(const char *filename)
{
  return store_exist(blkdevid, filename);
}

int _blkmgr_linux_copy_file_range(int fs_type,
                                   int src_fd, int dst_fd, uint64_t src_off,
                                   uint64_t dst_off, uint64_t len)
{
    int ret = (int)FDB_RESULT_INVALID_ARGS;
    return ret;
}
void _blkmgr_linux_get_dir_n_prefix(const char *filename, char *dirname, char *prefix)
{
    int i;
    int filename_len;
    int dirname_len;

    filename_len = strlen(filename);
    dirname_len = 0;
    for (i=filename_len-1; i>=0; --i){
        if (filename[i] == '/') {
            dirname_len = i+1;
            break;
        }
    }

    if (dirname_len > 0) {
        strncpy(dirname, filename, dirname_len);
        dirname[dirname_len] = 0;
    } else {
        strcpy(dirname, ".");
    }
    strcpy(prefix, filename + dirname_len);
    strcat(prefix, ".");
}

fdb_status _blkmgr_linux_search_n_destroy(const char *filename, char *dirname, char *prefix)
{
  fdb_status fs = FDB_RESULT_SUCCESS;
  char **store_names=(char **)malloc(32* sizeof(char *));
  for(int i=0;i<32;i++){
    store_names[i]=(char *)malloc(256 * sizeof(char));	
  } 
  int *store_remain;  // remaining stores number
  int remaining=0;
  store_remain=&remaining;	
  int store_max=32;
  int store_count=0; // Found stores number

  if (blkdevid < 0)
  {
    char pri_dev[256] = "/tmp/fdb-blk1";
    //TODO remove hard coding
    if ((blkdevid = blkdev_init(pri_dev, filemgr_get_config()->rawblksize)) < 0)
    {
      char errStr[256];
      _blkmgr_linux_get_errno_str(errStr, 256);
      printf("failed to init blk dev %d, %s\n", blkdevid, errStr);
      return FDB_RESULT_OPEN_FAIL;
    }
  }
  store_count = blkdev_storenames(blkdevid, store_names, store_max, store_remain);

  if (store_count < 0) {
    char errStr[256];
    _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to get storename of %s %s\n", filename, errStr);
    }
    else if (store_count == 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("No store in %s %s\n", filename, errStr);
    }

    if (remaining > 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("Still %d store left unsearched in %s %s\n", remaining,filename, errStr);
    }

    for(int i=0;i<store_count;i++){
	    if (!strncmp(store_names[i], prefix, strlen(prefix))) {
		// Need to check filemgr for possible open entry?
		if (store_remove(blkdevid, store_names[i])) {
		    fs = FDB_RESULT_FILE_REMOVE_FAIL;
		    return fs;
		}
	    }

    }
    free(store_names);
    return fs;
}
void _blkmgr_linux_update_compaction_no(const char *filename, char *dirname, char *prefix, int *compaction_no, int *max_compaction_no)
{
    char **store_names=(char **)malloc(32* sizeof(char *));
    for(int i=0;i<32;i++){
	store_names[i]=(char *)malloc(256 * sizeof(char));	
    } 
    int *store_remain;  // remaining stores number
    int remaining=0;
    store_remain=&remaining;
    int store_max=32;
    int store_count=0; // Found stores number
      
    if (blkdevid < 0)
    {
      char pri_dev[256] = "/tmp/fdb-blk1";
      if ((blkdevid = blkdev_init(pri_dev, filemgr_get_config()->rawblksize)) < 0)
      {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to init block device %d, %s\n", blkdevid, errStr);
        return;
      }
    }
    store_count = blkdev_storenames(blkdevid, store_names, store_max, store_remain);
    if (store_count < 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to get storename of %s %s\n", filename, errStr);
    }
    else if (store_count == 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("No store in %s %s\n", filename, errStr);
    }

    if (remaining > 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("Still %d stores left unsearched in %s %s\n", remaining, filename, errStr);
    }

    for(int i=0;i<store_count;i++){
	    if (!strncmp(store_names[i], prefix, strlen(prefix))) {
	            *compaction_no = -1;
                    sscanf(store_names[i] + strlen(prefix), "%d", compaction_no);
                    if (*compaction_no >= 0) {
                        if (*compaction_no > *max_compaction_no) {
                            *max_compaction_no = *compaction_no;
                        }
                    }
	     }
    }
    free(store_names);

}
struct filemgr_ops linux_blk_ops = {
    _blkmgr_linux_open,
    _blkmgr_linux_pwrite,
    _blkmgr_linux_pread,
    _blkmgr_linux_getblk,
    _blkmgr_linux_changemode,
    _blkmgr_linux_close,
    _blkmgr_linux_goto_eof,
    _blkmgr_linux_file_size,
    _blkmgr_linux_fdatasync,
    _blkmgr_linux_fsync,
    _blkmgr_linux_fsync2,
    _blkmgr_linux_get_errno_str,
    // Async I/O operations
    _blkmgr_aio_init,
    _blkmgr_aio_prep_read,
    _blkmgr_aio_submit,
    _blkmgr_aio_getevents,
    _blkmgr_aio_destroy,
    _blkmgr_linux_get_fs_type,
    _blkmgr_linux_does_file_exist,
    _blkmgr_linux_copy_file_range,
    _blkmgr_linux_get_dir_n_prefix,
    _blkmgr_linux_search_n_destroy,
    _blkmgr_linux_update_compaction_no
};

struct filemgr_ops * get_linux_filemgr_ops()
{
  struct filemgr_config *fconfig = filemgr_get_config();
  if (fconfig->rawblksize)
  {
    return &linux_blk_ops;
  }
  else
  {
    return &linux_file_ops;
  }
}

#endif

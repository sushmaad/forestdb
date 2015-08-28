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
#include <string>

#include <uftl/osd.h>
#include <uftl/osd_types.h>
#include <uftl/osd_err.h>

#include "filemgr.h"
#include "filemgr_ops.h"

using namespace std;
#if !defined(WIN32) && !defined(_WIN32)
int osdid = -1;

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
    int rc = 0;
    int fd;
    if (osdid < 0)
    {
      char osd_name[256] = "osd1";
      char pri_dev1[256] = "/tmp/osd-pri1";
      char pri_dev2[256] = "/tmp/osd-pri2";
      char *pri_dev[2];
      pri_dev[0] = pri_dev1;
      pri_dev[1] = pri_dev2;
      //TODO remove hard coding
      if ((osdid = osd_init(osd_name, pri_dev, 2, NULL, 0, NULL, 0, OSD_ALL_FLASH)) < 0)
      {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to init OSD %d, %s\n", osdid, errStr);
        return OSD_ERR_DEVICE_NOT_FOUND;
      }
    }

    //TODO remove dummy devname
    fd = store_open(osdid, const_cast<char *>(pathname), 4096, flags, mode);

    if (fd < 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to open store %d, %s\n", fd, errStr);
        if (fd == OSD_ERR_STORE_NOT_FOUND) {
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
#if 0
  printf("writing to file %d size %lu at addr %lu\n", fd, count, offset);
  string tmpStr((char *)buf, count);
  for (int i = 0; i < tmpStr.length(); i++)
  {
    uint8_t tCh = tmpStr[i];
    printf("%d ", tCh);
  }
  printf("\n");
#endif
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
#if 0
  printf("reading to file %d size %lu at addr %lu\n", fd, count, offset);
  string tmpStr((char*)buf, count);
  for (int i = 0; i < tmpStr.length(); i++)
  {
    uint8_t tCh = tmpStr[i];
    printf("%d ", tCh);
  }
  printf("\n");
#endif
  if (rv < 0) {
        char errStr[256];
        _blkmgr_linux_get_errno_str(errStr, 256);
        printf("failed to read into store %d, %s\n", rv, errStr);
    return (ssize_t) FDB_RESULT_READ_FAIL; // LCOV_EXCL_LINE
  }
  return rv;
}

ssize_t _blkmgr_linux_getblksize(int fd)
{
  return osd_getblksize(osdid);
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
    cs_off_t rv = 0;//lseek(fd, 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) FDB_RESULT_SEEK_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

// LCOV_EXCL_START
cs_off_t _blkmgr_linux_file_size(const char *filename)
{
  //TODO first check with store if return value is  store not found
  //check with filesystem
    struct stat st;
    if (stat(filename, &st) == -1) {
        return (cs_off_t) FDB_RESULT_READ_FAIL;
    }
    return st.st_size;
}
// LCOV_EXCL_STOP

int _blkmgr_linux_fsync(int fd)
{
  int rv;
  rv = store_sync(fd);

  if (rv < 0) {
    return FDB_RESULT_FSYNC_FAIL; // LCOV_EXCL_LINE
  }
  return FDB_RESULT_SUCCESS;
}

// LCOV_EXCL_START
int _blkmgr_linux_fdatasync(int fd)
{
  int rv;
  rv = store_sync(fd);

  if (rv < 0) {
    return FDB_RESULT_FSYNC_FAIL; // LCOV_EXCL_LINE
  }
  return FDB_RESULT_SUCCESS;
}
// LCOV_EXCL_STOP

int _blkmgr_aio_init(struct async_io_handle *aio_handle)
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

int _blkmgr_aio_prep_read(struct async_io_handle *aio_handle, size_t aio_idx,
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

int _blkmgr_aio_submit(struct async_io_handle *aio_handle, int num_subs)
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

int _blkmgr_aio_getevents(struct async_io_handle *aio_handle, int min,
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

int _blkmgr_aio_destroy(struct async_io_handle *aio_handle)
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

int _blkmgr_linux_get_fs_type(int src_fd)
{
    int ret;
    int flags;
    ret = get_store_type(src_fd, &flags);
    if (ret < 0) {
        return FDB_RESULT_INVALID_ARGS;
    }
    switch (flags) {
      default:
        ret = FILEMGR_FS_NO_COW;
    }
    return ret;
}

int _blkmgr_linux_copy_file_range(int fs_type,
                                   int src_fd, int dst_fd, uint64_t src_off,
                                   uint64_t dst_off, uint64_t len)
{
    int ret = (int)FDB_RESULT_INVALID_ARGS;
    return ret;
}

struct filemgr_ops blk_linux_ops = {
    _blkmgr_linux_open,
    _blkmgr_linux_pwrite,
    _blkmgr_linux_pread,
    _blkmgr_linux_getblksize,
    _blkmgr_linux_close,
    _blkmgr_linux_goto_eof,
    _blkmgr_linux_file_size,
    _blkmgr_linux_fdatasync,
    _blkmgr_linux_fsync,
    _blkmgr_linux_get_errno_str,
    // Async I/O operations
    _blkmgr_aio_init,
    _blkmgr_aio_prep_read,
    _blkmgr_aio_submit,
    _blkmgr_aio_getevents,
    _blkmgr_aio_destroy,
    _blkmgr_linux_get_fs_type,
    _blkmgr_linux_copy_file_range
};

struct filemgr_ops * get_linux_blkmgr_ops()
{
    return &blk_linux_ops;
}

#endif

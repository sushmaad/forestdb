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
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "filemgr.h"
#include "filemgr_ops.h"

#if defined(WIN32) || defined(_WIN32)
#include <windows.h>
#include <io.h>

static inline HANDLE handle_to_win(int fd)
{
    return (HANDLE)_get_osfhandle(fd);
}

int _filemgr_win_open(const char *pathname, int flags, mode_t mode)
{
#ifdef _MSC_VER
    int fd = _open(pathname, flags, mode);
    if (fd < 0) {
        errno_t err;
        _get_errno(&err);
        if (err == ENOENT) {
            return (int) FDB_RESULT_NO_SUCH_FILE;
        } else {
            return (int) FDB_RESULT_OPEN_FAIL;
        }
    }
    return fd;
#else
    int fd;
    do {
        fd = open(pathname, flags | O_LARGEFILE, mode);
    } while (fd == -1 && errno == EINTR);

    if (fd < 0) {
        if (errno == ENOENT) {
            return (int) FDB_RESULT_NO_SUCH_FILE;
        } else {
            return (int) FDB_RESULT_OPEN_FAIL;
        }
    }
    return fd;
#endif
}

ssize_t _filemgr_win_pwrite(int fd, void *buf, size_t count, cs_off_t offset)
{
    HANDLE file = handle_to_win(fd);
    BOOL rv;
    DWORD byteswritten;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = ((uint64_t)offset >> 32) & 0x7FFFFFFF;
    rv = WriteFile(file, buf, count, &byteswritten, &winoffs);
    if(!rv) {
        return (ssize_t) FDB_RESULT_WRITE_FAIL;
    }
    return (ssize_t) byteswritten;
}

ssize_t _filemgr_win_pread(int fd, void *buf, size_t count, cs_off_t offset)
{
    HANDLE file = handle_to_win(fd);
    BOOL rv;
    DWORD bytesread;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = ((uint64_t)offset >> 32) & 0x7FFFFFFF;
    rv = ReadFile(file, buf, count, &bytesread, &winoffs);
    if(!rv) {
        return (ssize_t) FDB_RESULT_READ_FAIL;
    }
    return (ssize_t) bytesread;
}

ssize_t _filemgr_win_getblk(int fd, uint64_t addr)
{
  return 0;
}

int _filemgr_win_changemode(int fd, int flags)
{
  return 0;
}

int _filemgr_win_remove(const char *filename)
{
  return 0;
}

int _filemgr_win_close(int fd)
{
#ifdef _MSC_VER
    int rv = 0;
    if (fd != -1) {
        rv = _close(fd);
    }

    if (rv < 0) {
        return FDB_RESULT_CLOSE_FAIL;
    }
    return FDB_RESULT_SUCCESS;
#else
    int rv = 0;
    if (fd != -1) {
        do {
            rv = close(fd);
        } while (rv == -1 && errno == EINTR);
    }

    if (rv < 0) {
        return FDB_RESULT_CLOSE_FAIL;
    }
    return FDB_RESULT_SUCCESS;
#endif
}

cs_off_t _filemgr_win_goto_eof(int fd)
{
#ifdef _MSC_VER
    cs_off_t rv = _lseeki64(fd, 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) FDB_RESULT_SEEK_FAIL;
    }
    return rv;
#else
    cs_off_t rv = lseek(fd, 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) FDB_RESULT_SEEK_FAIL;
    }
    return rv;
#endif
}

cs_off_t _filemgr_win_file_size(const char *filename)
{
#ifdef _MSC_VER
    struct _stat st;
    if (_stat(filename, &st) == -1) {
        return (cs_off_t) FDB_RESULT_READ_FAIL;
    }
    return st.st_size;
#else
    struct stat st;
    if (stat(filename, &st) == -1) {
        return (cs_off_t) FDB_RESULT_READ_FAIL;
    }
    return st.st_size;
#endif
}

int _filemgr_win_fsync(int fd)
{
    HANDLE file = handle_to_win(fd);

    if (!FlushFileBuffers(file)) {
        return FDB_RESULT_FSYNC_FAIL;
    }
    return FDB_RESULT_SUCCESS;
}

int _filemgr_win_fsync2(int fd, uint64_t addr)
{
  //dummy
    return FDB_RESULT_SUCCESS;
}

int _filemgr_win_fdatasync(int fd)
{
    return _filemgr_win_fsync(fd);
}

void _filemgr_win_get_errno_str(char *buf, size_t size)
{
    if (!buf) {
        return;
    }

    char* win_msg = NULL;
    DWORD err = GetLastError();
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (LPTSTR) &win_msg,
                   0, NULL);
    _snprintf(buf, size, "errno = %d: '%s'", err, win_msg);
    LocalFree(win_msg);
}

int _filemgr_aio_init(struct async_io_handle *aio_handle)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_prep_read(struct async_io_handle *aio_handle, size_t aio_idx,
                            size_t read_size, uint64_t offset)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_submit(struct async_io_handle *aio_handle, int num_subs)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_getevents(struct async_io_handle *aio_handle, int min,
                           int max, unsigned int timeout)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_destroy(struct async_io_handle *aio_handle)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_win_get_fs_type(int src_fd)
{
    return FILEMGR_FS_NO_COW;
}

bool _filemgr_win_does_file_exist(const char *filename)
{
  return GetFileAttributes(filename) != INVALID_FILE_ATTRIBUTES;
}

int _filemgr_win_copy_file_range(int fstype, int src_fd, int dst_fd,
                                 uint64_t src_off, uint64_t dst_off,
                                 uint64_t len)
{
    return FDB_RESULT_INVALID_ARGS;
}
void _filemgr_win_get_dir_n_prefix(const char *filename, char *dirname, char *prefix)
{
    int i;
    int filename_len;
    int dirname_len;

    filename_len = strlen(filename);
    dirname_len = 0;
    for (i=filename_len-1; i>=0; --i){
        if (filename[i] == '/' || filename[i] == '\\') {
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

fdb_status _filemgr_win_search_n_destroy(const char *filename, char *dirname, char *prefix)
{
    fdb_status fs = FDB_RESULT_SUCCESS;
    WIN32_FIND_DATA filedata;
    HANDLE hfind;
    char query_str[MAX_FNAMELEN];
    // find all files start with 'prefix'
    sprintf(query_str, "%s*", prefix);
    hfind = FindFirstFile(query_str, &filedata);
    while (hfind != INVALID_HANDLE_VALUE) {
        if (!strncmp(filedata.cFileName, prefix, strlen(prefix))) {
            // Need to check filemgr for possible open entry?
            if (remove(filedata.cFileName)) {
                fs = FDB_RESULT_FILE_REMOVE_FAIL;
                FindClose(hfind);
                hfind = INVALID_HANDLE_VALUE;
                return fs;
            }
        }

        if (!FindNextFile(hfind, &filedata)) {
            FindClose(hfind);
            hfind = INVALID_HANDLE_VALUE;
        }
    }
    
    return fs;
}
void _filemgr_win_update_compaction_no(const char *pathname, char *dirname, char *prefix, int *compaction_no, int *max_compaction_no)
{
        WIN32_FIND_DATA filedata;
        HANDLE hfind;
        char query_str[MAX_FNAMELEN];

        // find all files start with 'prefix'
        sprintf(query_str, "%s*", prefix);
        hfind = FindFirstFile(query_str, &filedata);
        while (hfind != INVALID_HANDLE_VALUE) {
            if (!strncmp(filedata.cFileName, prefix, strlen(prefix))) {
                *compaction_no = -1;
                sscanf(filedata.cFileName + strlen(prefix), "%d", compaction_no);
                if (*compaction_no >= 0) {
                    if (*compaction_no > *max_compaction_no) {
                        *max_compaction_no = *compaction_no;
                    }
                }
            }

            if (!FindNextFile(hfind, &filedata)) {
                FindClose(hfind);
                hfind = INVALID_HANDLE_VALUE;
            }
        }

}
struct filemgr_ ps win_ops = {
    _filemgr_win_open,
    _filemgr_win_pwrite,
    _filemgr_win_pread,
    _filemgr_win_getblk,
    _filemgr_win_changemode,
    _filemgr_win_close,
    _filemgr_win_remove,
    _filemgr_win_goto_eof,
    _filemgr_win_file_size,
    _filemgr_win_fdatasync,
    _filemgr_win_fsync,
    _filemgr_win_fsync2,
    _filemgr_win_get_errno_str,
    // Async I/O operations
    _filemgr_aio_init,
    _filemgr_aio_prep_read,
    _filemgr_aio_submit,
    _filemgr_aio_getevents,
    _filemgr_aio_destroy,
    _filemgr_win_get_fs_type,
    _filemgr_win_does_file_exist,
    _filemgr_win_copy_file_range,
    _filemgr_win_get_dir_n_prefix,
    _filemgr_win_search_n_destroy,
    _filemgr_win_update_compaction_no
};

struct filemgr_ops * get_win_filemgr_ops()
{
    return &win_ops;
}

#endif

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "docio.h"
#include "wal.h"
#include "fdb_internal.h"
#ifdef _DOC_COMP
#include "snappy-c.h"
#endif

#include "memleak.h"

void docio_init(struct docio_handle *handle,
                struct filemgr *file,
                bool compress_document_body)
{
    handle->file = file;
    handle->curblock = BLK_NOT_FOUND;
    handle->curpos = 0;
    handle->lastbid = BLK_NOT_FOUND;
    handle->compress_document_body = compress_document_body;
    malloc_align(handle->readbuffer, FDB_SECTOR_SIZE, file->blocksize);
}

void docio_free(struct docio_handle *handle)
{
    free_align(handle->readbuffer);
}

#ifdef __CRC32
#define _add_blk_marker(file, bid, blocksize, marker, log_callback) \
    filemgr_write_offset((file), (bid), (blocksize), BLK_MARKER_SIZE, (marker), (log_callback))
#else
#define _add_blk_marker(file, bid, blocksize, marker, log_callback) \
    FDB_RESULT_SUCCESS
#endif

INLINE fdb_status _docio_fill_zero(struct docio_handle *handle, bid_t bid,
                                   size_t pos)
{
    // Fill next few bytes (sizeof(struct docio_length)) with zero
    // to avoid false positive docio_length checksum during file scanning.
    // (Note that the checksum value of zero-filled docio_length is 0x6F.)

    size_t blocksize = handle->file->blocksize;
    size_t len_size = sizeof(struct docio_length);
    uint8_t *zerobuf = alca(uint8_t, len_size);

#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
#endif

    if (pos + len_size <= blocksize) {
        // enough space in the block
        memset(zerobuf, 0x0, len_size);
        return filemgr_write_offset(handle->file, bid, pos, len_size,
                                    zerobuf, handle->log_callback);
    } else {
        // lack of space .. we don't need to fill zero bytes.
        return FDB_RESULT_SUCCESS;
    }
}

bid_t docio_append_doc_raw(struct docio_handle *handle, uint64_t size, void *buf)
{
    uint32_t offset;
    uint8_t marker[BLK_MARKER_SIZE];
    size_t blocksize = handle->file->blocksize;
    size_t real_blocksize = blocksize;
    err_log_callback *log_callback = handle->log_callback;
#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
    memset(marker, BLK_MARKER_DOC, BLK_MARKER_SIZE);
#endif
    //if raw block device sync before allocating
    if (handle->file->rawblksize) {
      filemgr_sync(handle->file, log_callback);
    }

    if (handle->curblock == BLK_NOT_FOUND) {
        // allocate new block
        handle->curblock = filemgr_alloc(handle->file, log_callback);
        handle->curpos = 0;
    }
    if (!filemgr_is_writable(handle->file, handle->curblock)) {
        // allocate new block
        handle->curblock = filemgr_alloc(handle->file, log_callback);
        handle->curpos = 0;
    }

    if (size <= blocksize - handle->curpos) {
        fdb_status fs = FDB_RESULT_SUCCESS;
        // simply append to current block
        offset = handle->curpos;
        fs = _add_blk_marker(handle->file, handle->curblock, blocksize, marker,
                             log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Error in appending a doc block marker for a block id %" _F64
                    " into a database file '%s'", handle->curblock,
                    handle->file->filename);
            return BLK_NOT_FOUND;
        }
        fs = filemgr_write_offset(handle->file, handle->curblock, offset, size,
                                  buf, log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Error in writing a doc block with id %" _F64 ", offset %d, size %"
                    _F64 " to a database file '%s'", handle->curblock, offset, size,
                    handle->file->filename);
            return BLK_NOT_FOUND;
        }
        handle->curpos += size;

        if (_docio_fill_zero(handle, handle->curblock, handle->curpos) !=
            FDB_RESULT_SUCCESS) {
            return BLK_NOT_FOUND;
        }

        return handle->curblock * real_blocksize + offset;

    } else {
        // not simply fitted into current block
        bid_t begin, end, i, startpos;
        uint32_t nblock = size / blocksize;
        uint32_t remain = size % blocksize;
        uint64_t remainsize = size;
        fdb_status fs = FDB_RESULT_SUCCESS;

#ifdef DOCIO_BLOCK_ALIGN
        offset = blocksize - handle->curpos;
        if (remain <= blocksize - handle->curpos &&
            filemgr_alloc_multiple_cond(handle->file, handle->curblock+1,
                                        nblock + ((remain>offset)?1:0), &begin, &end,
                                        log_callback) == handle->curblock+1) {

            // start from current block
            fdb_assert(begin == handle->curblock + 1, begin, handle->curblock+1);

            fs = _add_blk_marker(handle->file, handle->curblock, blocksize,
                                 marker, log_callback);
            if (fs != FDB_RESULT_SUCCESS) {
                fdb_log(log_callback, fs,
                        "Error in appending a doc block marker for a block id %" _F64
                        " into a database file '%s'", handle->curblock,
                        handle->file->filename);
                return BLK_NOT_FOUND;
            }
            if (offset > 0) {
                fs = filemgr_write_offset(handle->file, handle->curblock,
                                          handle->curpos, offset, buf, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in writing a doc block with id %" _F64 ", offset %d, "
                            "size %" _F64 " to a database file '%s'", handle->curblock,
                            offset, size, handle->file->filename);
                    return BLK_NOT_FOUND;
                }
            }
            remainsize -= offset;

            startpos = handle->curblock * real_blocksize + handle->curpos;
        } else {
            // next block to be allocated is not continuous .. allocate new multiple blocks
            filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0),
                                   &begin, &end, log_callback);
            offset = 0;

            startpos = begin * real_blocksize;
        }

#else
        // simple append mode .. always append at the end of file
        offset = blocksize - handle->curpos;
        if (filemgr_alloc_multiple_cond(handle->file, handle->curblock+1,
                                        nblock + ((remain>offset)?1:0), &begin, &end,
                                        log_callback) == handle->curblock+1) {
            // start from current block
            fdb_assert(begin == handle->curblock + 1, begin, handle->curblock+1);

            fs = _add_blk_marker(handle->file, handle->curblock, blocksize,
                                 marker, log_callback);
            if (fs != FDB_RESULT_SUCCESS) {
                fdb_log(log_callback, fs,
                        "Error in appending a doc block marker for a block id %" _F64
                        " into a database file '%s'", handle->curblock,
                        handle->file->filename);
                return BLK_NOT_FOUND;
            }
            if (offset > 0) {
                fs = filemgr_write_offset(handle->file, handle->curblock,
                                          handle->curpos, offset, buf, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in writing a doc block with id %" _F64 ", offset %d, "
                            "size %" _F64 " to a database file '%s'", handle->curblock,
                            offset, size, handle->file->filename);
                    return BLK_NOT_FOUND;
                }
            }
            remainsize -= offset;

            startpos = handle->curblock * real_blocksize + handle->curpos;
        } else {
            // next block to be allocated is not continuous .. allocate new multiple blocks
            filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0),
                                   &begin, &end, log_callback);
            offset = 0;

            startpos = begin * real_blocksize;
        }

#endif

        for (i=begin; i<=end; ++i) {
            handle->curblock = i;
            if (remainsize >= blocksize) {
                // write entire block
                fs = _add_blk_marker(handle->file, i, blocksize, marker,
                                     log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in appending a doc block marker for a block "
                            "id %" _F64 " into a database file '%s'", i,
                            handle->file->filename);
                    return BLK_NOT_FOUND;
                }
                fs = filemgr_write_offset(handle->file, i, 0, blocksize,
                                          (uint8_t *)buf + offset, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in writing an entire doc block with id %" _F64
                            ", size %" _F64 " to a database file '%s'", i, blocksize,
                            handle->file->filename);
                    return BLK_NOT_FOUND;
                }
                offset += blocksize;
                remainsize -= blocksize;
                handle->curpos = blocksize;

            } else {
                // write rest of document
                fdb_assert(i==end, i, end);
                fs = _add_blk_marker(handle->file, i, blocksize, marker,
                                     log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in appending a doc block marker for a block "
                            "id %" _F64 " into a database file '%s'", i,
                            handle->file->filename);
                    return BLK_NOT_FOUND;
                }
                fs = filemgr_write_offset(handle->file, i, 0, remainsize,
                                          (uint8_t *)buf + offset, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in writing a doc block with id %" _F64 ", "
                            "size %" _F64 " to a database file '%s'", i, remainsize,
                            handle->file->filename);
                    return BLK_NOT_FOUND;
                }
                offset += remainsize;
                handle->curpos = remainsize;

                if (_docio_fill_zero(handle, i, handle->curpos) !=
                    FDB_RESULT_SUCCESS) {
                    return BLK_NOT_FOUND;
                }
            }
        }

        return startpos;
    }

    return 0;
}

#ifdef __ENDIAN_SAFE
INLINE struct docio_length _docio_length_encode(struct docio_length length)
{
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_encode(length.keylen);
    ret.metalen = _endian_encode(length.metalen);
    ret.bodylen = _endian_encode(length.bodylen);
    ret.bodylen_ondisk = _endian_encode(length.bodylen_ondisk);
    return ret;
}
INLINE struct docio_length _docio_length_decode(struct docio_length length)
{
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_decode(length.keylen);
    ret.metalen = _endian_decode(length.metalen);
    ret.bodylen = _endian_decode(length.bodylen);
    ret.bodylen_ondisk = _endian_decode(length.bodylen_ondisk);
    return ret;
}
#else
#define _docio_length_encode(a)
#define _docio_length_decode(a)
#endif

INLINE uint8_t _docio_length_checksum(struct docio_length length, struct docio_handle* handle)
{
    return uint8_t(get_checksum(reinterpret_cast<const uint8_t*>(&length),
                                sizeof(keylen_t) + sizeof(uint16_t) + sizeof(uint32_t)*2,
                                handle->file->crc_mode) & 0xff);
}

INLINE bid_t _docio_append_doc(struct docio_handle *handle, struct docio_object *doc)
{
    size_t _len;
    uint32_t offset = 0;
    uint32_t crc;
    uint64_t docsize;
    void *buf;
    bid_t ret_offset;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    struct docio_length length, _length;
    err_log_callback *log_callback = handle->log_callback;

    length = doc->length;
    length.bodylen_ondisk = length.bodylen;

#ifdef _DOC_COMP
    int ret;
    void *compbuf = NULL;
    uint32_t compbuf_len;
    if (doc->length.bodylen > 0 && handle->compress_document_body) {
        compbuf_len = snappy_max_compressed_length(length.bodylen);
        compbuf = (void *)malloc(compbuf_len);

        _len = compbuf_len;
        ret = snappy_compress((char*)doc->body, length.bodylen, (char*)compbuf, &_len);
        if (ret < 0) { // LCOV_EXCL_START
            fdb_log(log_callback, FDB_RESULT_COMPRESSION_FAIL,
                    "Error in compressing the doc body of key '%s' from "
                    "a database file '%s'",
                    (char *) doc->key, handle->file->filename);
            free(compbuf);
            // we use BLK_NOT_FOUND for error code of appending instead of 0
            // because document can be written at the byte offset 0
            return BLK_NOT_FOUND;
        } // LCOV_EXCL_STOP

        length.bodylen_ondisk = compbuf_len = _len;
        length.flag |= DOCIO_COMPRESSED;

        docsize = sizeof(struct docio_length) + length.keylen + length.metalen;
        docsize += compbuf_len;
    } else {
        docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
        compbuf_len = length.bodylen;
    }
#else
    docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
#endif
    docsize += sizeof(timestamp_t);

    docsize += sizeof(fdb_seqnum_t);

#ifdef __CRC32
    docsize += sizeof(crc);
#endif

    doc->length = length;
    buf = (void *)malloc(docsize);

    _length = _docio_length_encode(length);

    // calculate checksum of LENGTH using crc
    _length.checksum = _docio_length_checksum(_length, handle);

    memcpy((uint8_t *)buf + offset, &_length, sizeof(struct docio_length));
    offset += sizeof(struct docio_length);

    // copy key
    memcpy((uint8_t *)buf + offset, doc->key, length.keylen);
    offset += length.keylen;

    // copy timestamp
    _timestamp = _endian_encode(doc->timestamp);
    memcpy((uint8_t*)buf + offset, &_timestamp, sizeof(_timestamp));
    offset += sizeof(_timestamp);

    // copy seqeunce number (optional)
    _seqnum = _endian_encode(doc->seqnum);
    memcpy((uint8_t *)buf + offset, &_seqnum, sizeof(fdb_seqnum_t));
    offset += sizeof(fdb_seqnum_t);

    // copy metadata (optional)
    if (length.metalen > 0) {
        memcpy((uint8_t *)buf + offset, doc->meta, length.metalen);
        offset += length.metalen;
    }

    // copy body (optional)
    if (length.bodylen > 0) {
#ifdef _DOC_COMP
        if (length.flag & DOCIO_COMPRESSED) {
            // compressed body
            memcpy((uint8_t*)buf + offset, compbuf, compbuf_len);
            offset += compbuf_len;
            free(compbuf);
        } else {
            memcpy((uint8_t *)buf + offset, doc->body, length.bodylen);
            offset += length.bodylen;
        }
#else
        memcpy((uint8_t *)buf + offset, doc->body, length.bodylen);
        offset += length.bodylen;
#endif
    }

#ifdef __CRC32
    crc = get_checksum(reinterpret_cast<const uint8_t*>(buf),
                       docsize - sizeof(crc),
                       handle->file->crc_mode);
    memcpy((uint8_t *)buf + offset, &crc, sizeof(crc));
#endif

    ret_offset = docio_append_doc_raw(handle, docsize, buf);
    free(buf);

    return ret_offset;
}

bid_t docio_append_commit_mark(struct docio_handle *handle, uint64_t doc_offset)
{
    uint32_t offset = 0;
    uint64_t docsize;
    uint64_t _doc_offset;
    void *buf;
    bid_t ret_offset;
    struct docio_length length, _length;

    memset(&length, 0, sizeof(struct docio_length));
    length.flag = DOCIO_TXN_COMMITTED;

    docsize = sizeof(struct docio_length) + sizeof(doc_offset);
    buf = (void *)malloc(docsize);

    _length = _docio_length_encode(length);

    // calculate checksum of LENGTH using crc
    _length.checksum = _docio_length_checksum(_length, handle);

    memcpy((uint8_t *)buf + offset, &_length, sizeof(struct docio_length));
    offset += sizeof(struct docio_length);

    // copy doc_offset
    _doc_offset = _endian_encode(doc_offset);
    memcpy((uint8_t *)buf + offset, &_doc_offset, sizeof(_doc_offset));

    ret_offset = docio_append_doc_raw(handle, docsize, buf);
    free(buf);

    return ret_offset;
}

bid_t docio_append_doc(struct docio_handle *handle, struct docio_object *doc,
                       uint8_t deleted, uint8_t txn_enabled)
{
    doc->length.flag = DOCIO_NORMAL;
    if (deleted) {
        doc->length.flag |= DOCIO_DELETED;
    }
    if (txn_enabled) {
        doc->length.flag |= DOCIO_TXN_DIRTY;
    }
    return _docio_append_doc(handle, doc);
}

bid_t docio_append_doc_system(struct docio_handle *handle, struct docio_object *doc)
{
    doc->length.flag = DOCIO_NORMAL | DOCIO_SYSTEM;
    return _docio_append_doc(handle, doc);
}

INLINE fdb_status _docio_read_through_buffer(struct docio_handle *handle,
                                             bid_t bid,
                                             err_log_callback *log_callback,
                                             bool read_on_cache_miss)
{
    fdb_status status = FDB_RESULT_SUCCESS;
    // to reduce the overhead from memcpy the same block
    if (handle->lastbid != bid) {
        status = filemgr_read(handle->file, bid, handle->readbuffer,
                              log_callback, read_on_cache_miss);
        if (status != FDB_RESULT_SUCCESS) {
            if (read_on_cache_miss) {
                fdb_log(log_callback, status,
                        "Error in reading a doc block with id %" _F64 " from "
                        "a database file '%s'", bid, handle->file->filename);
            }
            return status;
        }

        if (filemgr_is_writable(handle->file, bid)) {
            // this block can be modified later .. must be re-read
            handle->lastbid = BLK_NOT_FOUND;
        }else{
            handle->lastbid = bid;
        }
    }

    return status;
}

INLINE int _docio_check_buffer(struct docio_handle *handle)
{
    uint8_t marker[BLK_MARKER_SIZE];
    marker[0] = *(((uint8_t *)handle->readbuffer)
                 + handle->file->blocksize - BLK_MARKER_SIZE);
    return (marker[0] == BLK_MARKER_DOC);
}

static uint64_t _docio_read_length(struct docio_handle *handle,
                                   uint64_t offset,
                                   struct docio_length *length,
                                   err_log_callback *log_callback,
                                   bool read_on_cache_miss)
{
    size_t blocksize = handle->file->blocksize;
    size_t real_blocksize = blocksize;
#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
#endif

    uint64_t file_pos = filemgr_get_pos(handle->file);
    if (file_pos < (offset + sizeof(struct docio_length))) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Read request with offset %" _F64 " and size %d exceeds the current "
                "size %" _F64 " of a database file '%s'",
                offset, sizeof(struct docio_length), file_pos,
                handle->file->filename);
        return offset;
    }

    bid_t bid = offset / real_blocksize;
    uint32_t pos = offset % real_blocksize;
    void *buf = handle->readbuffer;
    uint32_t restsize;

    restsize = blocksize - pos;
    // read length structure
    fdb_status fs = _docio_read_through_buffer(handle, bid, log_callback,
                                               read_on_cache_miss);
    if (fs != FDB_RESULT_SUCCESS) {
        if (read_on_cache_miss) {
            fdb_log(log_callback, fs,
                    "Error in reading a doc length from a block with block id %" _F64
                    " from a database file '%s'", bid, handle->file->filename);
        }
        return offset;
    }
    if (!_docio_check_buffer(handle)) {
        return offset;
    }

    if (restsize >= sizeof(struct docio_length)) {
        memcpy(length, (uint8_t *)buf + pos, sizeof(struct docio_length));
        pos += sizeof(struct docio_length);

    } else {
        memcpy(length, (uint8_t *)buf + pos, restsize);
        // read additional block
        bid++;
        fs = _docio_read_through_buffer(handle, bid, log_callback, true);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Error in reading a doc length from an additional block "
                    "with block id %" _F64 " from a database file '%s'",
                    bid, handle->file->filename);
            return offset;
        }
        if (!_docio_check_buffer(handle)) {
            return offset;
        }
        // memcpy rest of data
        memcpy((uint8_t *)length + restsize, buf, sizeof(struct docio_length) - restsize);
        pos = sizeof(struct docio_length) - restsize;
    }

    return bid * real_blocksize + pos;
}

static uint64_t _docio_read_doc_component(struct docio_handle *handle,
                                          uint64_t offset,
                                          uint32_t len,
                                          void *buf_out,
                                          err_log_callback *log_callback)
{
    uint32_t rest_len;
    size_t blocksize = handle->file->blocksize;
    size_t real_blocksize = blocksize;
#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
#endif

    bid_t bid = offset / real_blocksize;
    uint32_t pos = offset % real_blocksize;
    //uint8_t buf[handle->file->blocksize];
    void *buf = handle->readbuffer;
    uint32_t restsize;
    fdb_status fs = FDB_RESULT_SUCCESS;

    rest_len = len;

    while(rest_len > 0) {
        fs = _docio_read_through_buffer(handle, bid, log_callback, true);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                    "Error in reading a doc block with block id %" _F64 " from "
                    "a database file '%s'", bid, handle->file->filename);
            return 0;
        }
        restsize = blocksize - pos;

        if (restsize >= rest_len) {
            memcpy((uint8_t *)buf_out + (len - rest_len), (uint8_t *)buf + pos, rest_len);
            pos += rest_len;
            rest_len = 0;
        }else{
            memcpy((uint8_t *)buf_out + (len - rest_len), (uint8_t *)buf + pos, restsize);
            bid++;
            pos = 0;
            rest_len -= restsize;

            if (rest_len > 0 &&
                bid >= filemgr_get_pos(handle->file) / handle->file->blocksize) {
                // no more data in the file .. the file is corrupted
                fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                        "Fatal error!!! Database file '%s' is corrupted.",
                        handle->file->filename);
                // TODO: Need to return a better error code.
                return 0;
            }
        }
    }

    return bid * real_blocksize + pos;
}

#ifdef _DOC_COMP

static uint64_t _docio_read_doc_component_comp(struct docio_handle *handle,
                                               uint64_t offset,
                                               uint32_t len,
                                               uint32_t comp_len,
                                               void *buf_out,
                                               void *comp_data_out,
                                               err_log_callback *log_callback)
{
    int ret;
    size_t uncomp_size;
    uint64_t _offset;

    _offset = _docio_read_doc_component(handle, offset,
                                        comp_len, comp_data_out, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading the file with offset %" _F64 ", length %d "
                "from a database file '%s'", offset, len,
                handle->file->filename);
        return 0;
    }

    uncomp_size = len;
    ret = snappy_uncompress((char*)comp_data_out, comp_len,
                            (char*)buf_out, &uncomp_size);
    if (ret < 0) {
        fdb_log(log_callback, FDB_RESULT_COMPRESSION_FAIL,
                "Error in decompressing the data that was read with the file "
                "offset %" _F64 ", length %d from a database file '%s'",
                offset, len, handle->file->filename);
        return 0;
    }

    fdb_assert(uncomp_size == len, uncomp_size, len);
    return _offset;
}

#endif

// return length.keylen = 0 if failure
struct docio_length docio_read_doc_length(struct docio_handle *handle, uint64_t offset)
{
    uint8_t checksum;
    uint64_t _offset;
    struct docio_length length, _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback, true);
    if (_offset == offset) {
        length.keylen = 0;
        return length;
    }

    // checksum check
    checksum = _docio_length_checksum(_length, handle);
    if (checksum != _length.checksum) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "doc_length checksum mismatch error in a database file '%s'",
                handle->file->filename);
        length.keylen = 0;
        return length;
    }

    length = _docio_length_decode(_length);
    if (length.keylen == 0 || length.keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "Error in decoding the doc length metadata (key length: %d) from "
                "a database file '%s'", length.keylen, handle->file->filename);
        length.keylen = 0;
        return length;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        length.keylen + length.metalen + length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Fatal error!!! Database file '%s' is corrupted.",
                handle->file->filename);
        length.keylen = 0;
        return length;
    }

    return length;
}

// return length.keylen = 0 if failure
void docio_read_doc_key(struct docio_handle *handle, uint64_t offset,
                        keylen_t *keylen, void *keybuf)
{
    uint8_t checksum;
    uint64_t _offset;
    struct docio_length length, _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback, true);
    if (_offset == offset) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading the doc length metadata with offset %" _F64 " from "
                "a database file '%s'",
                offset, handle->file->filename);
        *keylen = 0;
        return;
    }

    // checksum check
    checksum = _docio_length_checksum(_length, handle);
    if (checksum != _length.checksum) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "doc_length checksum mismatch error in a database file '%s'",
                handle->file->filename);
        *keylen = 0;
        return;
    }

    length = _docio_length_decode(_length);
    if (length.keylen == 0 || length.keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "Error in decoding the doc length metadata (key length: %d) from "
                "a database file '%s'", length.keylen, handle->file->filename);
        *keylen = 0;
        return;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        length.keylen + length.metalen + length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Fatal error!!! Database file '%s' is corrupted.",
                handle->file->filename);
        *keylen = 0;
        return;
    }

    _offset = _docio_read_doc_component(handle, _offset, length.keylen,
                                        keybuf, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a key with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, length.keylen,
                handle->file->filename);
        *keylen = 0;
        return;
    }
    *keylen = length.keylen;
}

void free_docio_object(struct docio_object *doc, uint8_t key_alloc,
                       uint8_t meta_alloc, uint8_t body_alloc) {
    if (!doc) {
        return;
    }

    if (key_alloc) {
        free(doc->key);
        doc->key = NULL;
    }
    if (meta_alloc) {
        free(doc->meta);
        doc->meta = NULL;
    }
    if (body_alloc) {
        free(doc->body);
        doc->body = NULL;
    }
}

uint64_t docio_read_doc_key_meta(struct docio_handle *handle, uint64_t offset,
                                 struct docio_object *doc,
                                 bool read_on_cache_miss)
{
    uint8_t checksum;
    uint64_t _offset;
    int key_alloc = 0;
    int meta_alloc = 0;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    struct docio_length _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback,
                                 read_on_cache_miss);
    if (_offset == offset) {
        if (read_on_cache_miss) {
            fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                    "Error in reading the doc length metadata with offset %" _F64 " from "
                    "a database file '%s'",
                    offset, handle->file->filename);
        }
        return offset;
    }

    // checksum check
    checksum = _docio_length_checksum(_length, handle);
    if (checksum != _length.checksum) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "doc_length checksum mismatch error in a database file '%s'",
                handle->file->filename);
        return offset;
    }

    doc->length = _docio_length_decode(_length);
    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "Error in decoding the doc length metadata (key length: %d) from "
                "a database file '%s'", doc->length.keylen, handle->file->filename);
        return offset;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        doc->length.keylen + doc->length.metalen + doc->length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Fatal error!!! Database file '%s' is corrupted.",
                handle->file->filename);
        return offset;
    }

    if (doc->key == NULL) {
        doc->key = (void *)malloc(doc->length.keylen);
        key_alloc = 1;
    }
    if (doc->meta == NULL && doc->length.metalen) {
        doc->meta = (void *)malloc(doc->length.metalen);
        meta_alloc = 1;
    }

    fdb_assert(doc->key, handle, doc->length.keylen);

    _offset = _docio_read_doc_component(handle, _offset, doc->length.keylen,
                                        doc->key, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a key with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, doc->length.keylen,
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }

    // read timestamp
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(timestamp_t),
                                        &_timestamp, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a timestamp with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, sizeof(timestamp_t),
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }
    doc->timestamp = _endian_decode(_timestamp);

    // copy sequence number (optional)
    _offset = _docio_read_doc_component(handle, _offset, sizeof(fdb_seqnum_t),
                                        (void *)&_seqnum, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a sequence number with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, sizeof(fdb_seqnum_t),
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }
    doc->seqnum = _endian_decode(_seqnum);

    _offset = _docio_read_doc_component(handle, _offset, doc->length.metalen,
                                        doc->meta, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading the doc metadata with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, doc->length.metalen,
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }

    uint8_t free_meta = meta_alloc && !doc->length.metalen;
    free_docio_object(doc, 0, free_meta, 0);

    return _offset;
}

uint64_t docio_read_doc(struct docio_handle *handle, uint64_t offset,
                        struct docio_object *doc,
                        bool read_on_cache_miss)
{
    uint8_t checksum;
    uint64_t _offset;
    int key_alloc = 0;
    int meta_alloc = 0;
    int body_alloc = 0;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    void *comp_body = NULL;
    struct docio_length _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback,
                                 read_on_cache_miss);
    if (_offset == offset) {
        if (read_on_cache_miss) {
            fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                    "Error in reading the doc length metadata with offset %" _F64 " from "
                    "a database file '%s'",
                    offset, handle->file->filename);
        }
        return offset;
    }

    // checksum check
    checksum = _docio_length_checksum(_length, handle);
    if (checksum != _length.checksum) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "doc_length checksum mismatch error in a database file '%s'",
                handle->file->filename);
        return offset;
    }

    doc->length = _docio_length_decode(_length);
    if (doc->length.flag & DOCIO_TXN_COMMITTED) {
        // transaction commit mark
        // read the corresponding doc offset

        // If TXN_COMMITTED flag is set, this doc is not an actual doc, but a
        // transaction commit marker. Thus, all lengths should be zero.
        if (doc->length.keylen || doc->length.metalen ||
            doc->length.bodylen || doc->length.bodylen_ondisk) {
            fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                    "File corruption: Doc length fields in a transaction commit marker "
                    "was not zero in a database file '%s'", handle->file->filename);
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return offset;
        }

        uint64_t doc_offset;
        _offset = _docio_read_doc_component(handle, _offset,
                                            sizeof(doc_offset), &doc_offset,
                                            log_callback);
        if (_offset == 0) {
            fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                    "Error in reading an offset of a committed doc from an offset %" _F64
                    " in a database file '%s'", _offset, handle->file->filename);
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return offset;
        }
        doc->doc_offset = _endian_decode(doc_offset);
        // The offset of the actual document that pointed by this commit marker
        // should not be greater than the file size.
        if (doc->doc_offset > filemgr_get_pos(handle->file)) {
            fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                    "File corruption: Offset %" _F64 " of the actual doc pointed by the "
                    "commit marker is greater than the size %" _F64 " of a database file '%s'",
                    doc->doc_offset, filemgr_get_pos(handle->file),
                    handle->file->filename);
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return offset;
        }
        return _offset;
    }

    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "Error in decoding the doc length metadata (key length: %d) from "
                "a database file '%s'", doc->length.keylen, handle->file->filename);
        return offset;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        doc->length.keylen + doc->length.metalen + doc->length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Fatal error!!! Database file '%s' is corrupted.",
                handle->file->filename);
        return offset;
    }

    if (doc->key == NULL) {
        doc->key = (void *)malloc(doc->length.keylen);
        key_alloc = 1;
    }
    if (doc->meta == NULL && doc->length.metalen) {
        doc->meta = (void *)malloc(doc->length.metalen);
        meta_alloc = 1;
    }
    if (doc->body == NULL && doc->length.bodylen) {
        doc->body = (void *)malloc(doc->length.bodylen);
        body_alloc = 1;
    }

    fdb_assert(doc->key, handle, doc->length.keylen);

    _offset = _docio_read_doc_component(handle, _offset,
                                        doc->length.keylen,
                                        doc->key,
                                        log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a key with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, doc->length.keylen,
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }

    // read timestamp
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(timestamp_t),
                                        &_timestamp,
                                        log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a timestamp with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, sizeof(timestamp_t),
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
    doc->timestamp = _endian_decode(_timestamp);

    // copy seqeunce number (optional)
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(fdb_seqnum_t),
                                        (void *)&_seqnum,
                                        log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a sequence number with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, sizeof(fdb_seqnum_t),
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
    doc->seqnum = _endian_decode(_seqnum);

    _offset = _docio_read_doc_component(handle, _offset, doc->length.metalen,
                                        doc->meta, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading the doc metadata with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, doc->length.metalen,
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }

#ifdef _DOC_COMP
    if (doc->length.flag & DOCIO_COMPRESSED) {
        comp_body = (void*)malloc(doc->length.bodylen_ondisk);
        _offset = _docio_read_doc_component_comp(handle, _offset, doc->length.bodylen,
                                                 doc->length.bodylen_ondisk, doc->body,
                                                 comp_body, log_callback);
        if (_offset == 0) {
            fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                    "Error in reading a compressed doc with offset %" _F64 ", length %d "
                    "from a database file '%s'", _offset, doc->length.bodylen,
                    handle->file->filename);
            if (comp_body) {
                free(comp_body);
            }
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return offset;
        }
    } else {
        _offset = _docio_read_doc_component(handle, _offset, doc->length.bodylen,
                                            doc->body, log_callback);
        if (_offset == 0) {
            fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                    "Error in reading a doc with offset %" _F64 ", length %d "
                    "from a database file '%s'", _offset, doc->length.bodylen,
                    handle->file->filename);
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return offset;
        }
    }
#else
    _offset = _docio_read_doc_component(handle, _offset, doc->length.bodylen,
                                        doc->body, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a doc with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, doc->length.bodylen,
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
#endif

#ifdef __CRC32
    uint32_t crc_file, crc;
    _offset = _docio_read_doc_component(handle, _offset, sizeof(crc_file),
                                        (void *)&crc_file, log_callback);
    if (_offset == 0) {
        fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                "Error in reading a doc's CRC value with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, sizeof(crc_file),
                handle->file->filename);
        if (comp_body) {
            free(comp_body);
        }
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }

    crc = get_checksum(reinterpret_cast<const uint8_t*>(&_length),
                       sizeof(_length),
                       handle->file->crc_mode);
    crc = get_checksum(reinterpret_cast<const uint8_t*>(doc->key),
                       doc->length.keylen,
                       crc,
                       handle->file->crc_mode);
    crc = get_checksum(reinterpret_cast<const uint8_t*>(&_timestamp),
                       sizeof(timestamp_t),
                       crc,
                       handle->file->crc_mode);
    crc = get_checksum(reinterpret_cast<const uint8_t*>(&_seqnum),
                       sizeof(fdb_seqnum_t),
                       crc,
                       handle->file->crc_mode);
    crc = get_checksum(reinterpret_cast<const uint8_t*>(doc->meta),
                       doc->length.metalen,
                       crc,
                       handle->file->crc_mode);

    if (doc->length.flag & DOCIO_COMPRESSED) {
        crc = get_checksum(reinterpret_cast<const uint8_t*>(comp_body),
                           doc->length.bodylen_ondisk,
                           crc,
                           handle->file->crc_mode);
        if (comp_body) {
            free(comp_body);
        }
    } else {
        crc = get_checksum(reinterpret_cast<const uint8_t*>(doc->body),
                           doc->length.bodylen,
                           crc,
                           handle->file->crc_mode);
    }
    if (crc != crc_file) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "doc_body checksum mismatch error in a database file '%s'",
                handle->file->filename);
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
#endif

    uint8_t free_meta = meta_alloc && !doc->length.metalen;
    uint8_t free_body = body_alloc && !doc->length.bodylen;
    free_docio_object(doc, 0, free_meta, free_body);

    return _offset;
}

static int _submit_async_io_requests(struct docio_handle *handle,
                                     struct docio_object *doc_array,
                                     size_t doc_idx,
                                     struct async_io_handle *aio_handle,
                                     int size,
                                     size_t *sum_doc_size,
                                     bool keymeta_only)
{
#ifdef _ASYNC_IO
#if !defined(WIN32) && !defined(_WIN32)
    struct io_event* io_evt = NULL;
    uint8_t *buf = NULL;
    uint64_t offset = 0, _offset = 0;
    int num_events = 0;

    int num_sub = handle->file->ops->aio_submit(aio_handle, size);
    if (num_sub < 0) {
        // Error loggings
        char errno_msg[512];
        handle->file->ops->get_errno_str(errno_msg, 512);
        fdb_log(handle->log_callback, (fdb_status) num_sub,
                "Error in submitting async I/O requests to a file '%s', errno msg: %s",
                handle->file->filename, errno_msg);
        return num_sub;
    }
    fdb_assert(num_sub == size, num_sub, size);

    while (num_sub > 0) {
        num_events = handle->file->ops->aio_getevents(aio_handle, 1,
                                                      num_sub, (unsigned int) -1);
        if (num_events < 0) {
            // Error loggings
            char errno_msg[512];
            handle->file->ops->get_errno_str(errno_msg, 512);
            fdb_log(handle->log_callback, (fdb_status) num_sub,
                    "Error in getting async I/O events from the completion queue "
                    "for a file '%s', errno msg: %s", handle->file->filename, errno_msg);
            return num_events;
        }
        num_sub -= num_events;
        for (io_evt = aio_handle->events; num_events > 0; --num_events, ++io_evt) {
            buf = (uint8_t *) io_evt->obj->u.c.buf;
            offset = *((uint64_t *) io_evt->data); // Original offset.

            // Set the docio handle's buffer to the AIO buffer to read
            // a doc from the AIO buffer. If adddtional blocks need to be
            // read, then they will be sequentially read through the synchronous
            // I/O path (i.e., buffer cache -> disk read if cache miss).
            // As these additional blocks are sequential reads, we don't expect
            // asynchronous I/O to give us performance boost.
            void *tmp_buffer = handle->readbuffer;
            handle->readbuffer = buf;
            handle->lastbid = offset / aio_handle->block_size;
            memset(&doc_array[doc_idx], 0x0, sizeof(struct docio_object));
            if (keymeta_only) {
                _offset = docio_read_doc_key_meta(handle, offset,
                                                  &doc_array[doc_idx], true);
            } else {
                _offset = docio_read_doc(handle, offset, &doc_array[doc_idx],
                                         true);
            }
            if (_offset == offset) {
                ++doc_idx;
                handle->readbuffer = tmp_buffer;
                handle->lastbid = BLK_NOT_FOUND;
                continue;
            }
            handle->readbuffer = tmp_buffer;
            handle->lastbid = BLK_NOT_FOUND;

            (*sum_doc_size) += _fdb_get_docsize(doc_array[doc_idx].length);
            if (keymeta_only) {
                (*sum_doc_size) -= doc_array[doc_idx].length.bodylen_ondisk;
            }
            ++doc_idx;
        }
    }
    return size;
#else // Plan to implement async I/O in other OSs (e.g., Windows, OSx)
    return 0;
#endif
#else // Async I/O is not supported in the current OS.
    return 0;
#endif
}

size_t docio_batch_read_docs(struct docio_handle *handle,
                             uint64_t *offset_array,
                             struct docio_object *doc_array,
                             size_t array_size,
                             size_t data_size_threshold,
                             size_t batch_size_threshold,
                             struct async_io_handle *aio_handle,
                             bool keymeta_only)
{
    size_t i = 0;
    size_t sum_doc_size = 0;
    size_t doc_idx = 0;
    size_t block_size = handle->file->blocksize;
    uint64_t _offset = 0;
    int aio_size = 0;
    bool read_fail = false;
    bool read_on_cache_miss = true;

    if (aio_handle) {
        // If async I/O is supported, we will then read non-resident docs from disk
        // by using async I/O operations.
        read_on_cache_miss = false;
    }

    for (i = 0; i < array_size && i < batch_size_threshold &&
           sum_doc_size < data_size_threshold; ++i) {
        memset(&doc_array[doc_idx], 0x0, sizeof(struct docio_object));
        if (keymeta_only) {
            _offset = docio_read_doc_key_meta(handle, offset_array[i], &doc_array[doc_idx],
                                              read_on_cache_miss);
        } else {
            _offset = docio_read_doc(handle, offset_array[i], &doc_array[doc_idx],
                                     read_on_cache_miss);
        }
        if (_offset == offset_array[i]) {
            if (aio_handle) {
                // The page is not resident in the cache. Prepare and perform Async I/O
                handle->file->ops->aio_prep_read(aio_handle, aio_size,
                                                 block_size, offset_array[i]);
                if (++aio_size == (int) aio_handle->queue_depth) {
                    int num_sub = _submit_async_io_requests(handle, doc_array, doc_idx,
                                                            aio_handle, aio_size,
                                                            &sum_doc_size,
                                                            keymeta_only);
                    if (num_sub < 0) {
                        read_fail = true;
                        break;
                    }
                    fdb_assert(num_sub == aio_size, num_sub, aio_size);
                    aio_size = 0;
                    doc_idx += num_sub;
                }
            } else {
                ++doc_idx; // Error in reading a doc.
            }
        } else {
            sum_doc_size += _fdb_get_docsize(doc_array[doc_idx].length);
            if (keymeta_only) {
                sum_doc_size -= doc_array[doc_idx].length.bodylen_ondisk;
            }
            ++doc_idx;
        }
    }

    if (aio_size && !read_fail) {
        int num_sub = _submit_async_io_requests(handle, doc_array, doc_idx,
                                                aio_handle, aio_size,
                                                &sum_doc_size, keymeta_only);
        if (num_sub < 0) {
            read_fail = true;
        } else {
            doc_idx += num_sub;
        }
    }

    if (read_fail) {
        for (i = 0; i < batch_size_threshold; ++i) {
            free(doc_array[i].key);
            free(doc_array[i].meta);
            free(doc_array[i].body);
            doc_array[i].key = doc_array[i].meta = doc_array[i].body = NULL;
        }
        return (size_t) -1;
    }

    return doc_idx;
}

int docio_check_buffer(struct docio_handle *handle, bid_t bid)
{
    err_log_callback *log_callback = handle->log_callback;
    _docio_read_through_buffer(handle, bid, log_callback, true);
    return _docio_check_buffer(handle);
}


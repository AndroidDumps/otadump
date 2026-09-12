/* SPDX-License-Identifier: BSD-2-Clause */
#include "lz4_ffi.h"

#include <stddef.h>

#include "lz4.h"
#include "lz4hc.h"

enum {
  OTADUMP_LZ4_OK = 0,
  OTADUMP_LZ4_INVALID_ARGUMENT = 1,
  OTADUMP_LZ4_COMPRESSION_FAILED = 2,
  OTADUMP_LZ4_DECOMPRESSION_FAILED = 3,
  OTADUMP_LZ4_ALLOCATION_FAILED = 4,
};

static otadump_lz4_result make_result(int32_t status, int32_t source_size,
                                     int32_t output_size) {
  otadump_lz4_result result = {status, source_size, output_size};
  return result;
}

static int buffers_overlap(const uint8_t *source, int32_t source_size,
                           const uint8_t *output, int32_t output_capacity) {
  uintptr_t src_start = (uintptr_t)source;
  uintptr_t src_end = src_start + (size_t)source_size;
  uintptr_t dst_start = (uintptr_t)output;
  uintptr_t dst_end = dst_start + (size_t)output_capacity;
  return src_start < dst_end && dst_start < src_end;
}

static int valid_buffers(const uint8_t *source, int32_t source_size,
                         uint8_t *output, int32_t output_capacity) {
  return source != NULL && output != NULL && source_size > 0 &&
         output_capacity > 0 && source_size <= LZ4_MAX_INPUT_SIZE &&
         output_capacity <= LZ4_MAX_INPUT_SIZE &&
         !buffers_overlap(source, source_size, output, output_capacity);
}

otadump_lz4_result otadump_lz4_decompress_safe_partial(
    const uint8_t *source, int32_t source_size, uint8_t *output,
    int32_t output_capacity, int32_t target_output_size) {
  int written;
  if (!valid_buffers(source, source_size, output, output_capacity) ||
      target_output_size <= 0 || target_output_size > output_capacity) {
    return make_result(OTADUMP_LZ4_INVALID_ARGUMENT, 0, 0);
  }
  written = LZ4_decompress_safe_partial(
      (const char *)source, (char *)output, source_size, target_output_size,
      output_capacity);
  if (written < 0) {
    return make_result(OTADUMP_LZ4_DECOMPRESSION_FAILED, 0, 0);
  }
  return make_result(OTADUMP_LZ4_OK, source_size, written);
}

otadump_lz4_result otadump_lz4_compress_dest_size(
    const uint8_t *source, int32_t source_size, uint8_t *output,
    int32_t output_capacity) {
  int consumed = source_size;
  int written;
  if (!valid_buffers(source, source_size, output, output_capacity)) {
    return make_result(OTADUMP_LZ4_INVALID_ARGUMENT, 0, 0);
  }
  written = LZ4_compress_destSize((const char *)source, (char *)output,
                                  &consumed, output_capacity);
  if (written <= 0) {
    return make_result(OTADUMP_LZ4_COMPRESSION_FAILED, consumed, 0);
  }
  return make_result(OTADUMP_LZ4_OK, consumed, written);
}

otadump_lz4_result otadump_lz4_compress_hc_dest_size(
    const uint8_t *source, int32_t source_size, uint8_t *output,
    int32_t output_capacity, int32_t compression_level) {
  LZ4_streamHC_t *stream;
  int consumed = source_size;
  int written;
  if (!valid_buffers(source, source_size, output, output_capacity) ||
      compression_level < LZ4HC_CLEVEL_MIN ||
      compression_level > LZ4HC_CLEVEL_MAX) {
    return make_result(OTADUMP_LZ4_INVALID_ARGUMENT, 0, 0);
  }
  stream = LZ4_createStreamHC();
  if (stream == NULL) {
    return make_result(OTADUMP_LZ4_ALLOCATION_FAILED, 0, 0);
  }
  written = LZ4_compress_HC_destSize(stream, (const char *)source,
                                     (char *)output, &consumed,
                                     output_capacity, compression_level);
  LZ4_freeStreamHC(stream);
  if (written <= 0) {
    return make_result(OTADUMP_LZ4_COMPRESSION_FAILED, consumed, 0);
  }
  return make_result(OTADUMP_LZ4_OK, consumed, written);
}

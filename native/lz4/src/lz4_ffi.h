/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef OTADUMP_LZ4_FFI_H
#define OTADUMP_LZ4_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int32_t status;
  int32_t source_size;
  int32_t output_size;
} otadump_lz4_result;

otadump_lz4_result otadump_lz4_decompress_safe_partial(
    const uint8_t *source, int32_t source_size, uint8_t *output,
    int32_t output_capacity, int32_t target_output_size);

otadump_lz4_result otadump_lz4_compress_dest_size(
    const uint8_t *source, int32_t source_size, uint8_t *output,
    int32_t output_capacity);

otadump_lz4_result otadump_lz4_compress_hc_dest_size(
    const uint8_t *source, int32_t source_size, uint8_t *output,
    int32_t output_capacity, int32_t compression_level);

#ifdef __cplusplus
}
#endif

#endif

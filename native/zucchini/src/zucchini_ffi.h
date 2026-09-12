#ifndef OTADUMP_ZUCCHINI_FFI_H_
#define OTADUMP_ZUCCHINI_FFI_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum otadump_zucchini_status {
  OTADUMP_ZUCCHINI_OK = 0,
  OTADUMP_ZUCCHINI_INVALID_ARGUMENT = 1,
  OTADUMP_ZUCCHINI_INVALID_PATCH = 2,
  OTADUMP_ZUCCHINI_UNSUPPORTED_ELEMENT = 3,
  OTADUMP_ZUCCHINI_WRONG_OUTPUT_SIZE = 4,
  OTADUMP_ZUCCHINI_APPLY_ERROR = 5,
};

struct otadump_zucchini_result {
  int status;
  const char* error;
};

// All non-empty buffers must remain valid for the complete call. Input buffers
// are read-only. The output buffer must not overlap either input buffer.
struct otadump_zucchini_result otadump_zucchini_apply(
    const uint8_t* old_data,
    size_t old_size,
    const uint8_t* patch_data,
    size_t patch_size,
    uint8_t* new_data,
    size_t new_size);

#ifdef __cplusplus
}
#endif

#endif  // OTADUMP_ZUCCHINI_FFI_H_

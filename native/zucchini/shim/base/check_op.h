// Project-owned minimal substitute for the libchrome comparison check macros
// used by the apply-only Zucchini closure. CHECK_* aborts the process on
// failure. DCHECK_* compiles to an unevaluated no-op under NDEBUG, matching
// upstream official build semantics.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_CHECK_OP_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_CHECK_OP_H_

#include "base/check.h"

#define CHECK_EQ(left, right) \
  if ((left) == (right)) {    \
  } else                      \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define CHECK_GE(left, right) \
  if ((left) >= (right)) {    \
  } else                      \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define CHECK_GT(left, right) \
  if ((left) > (right)) {     \
  } else                      \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define CHECK_LE(left, right) \
  if ((left) <= (right)) {    \
  } else                      \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define CHECK_LT(left, right) \
  if ((left) < (right)) {     \
  } else                      \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define CHECK_NE(left, right) \
  if ((left) != (right)) {    \
  } else                      \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)

#if defined(NDEBUG)
#define OTADUMP_SHIM_DCHECK_NO_OP \
  while (false) ::base::shim::CheckStream(__FILE__, __LINE__, false)
#define DCHECK_EQ(left, right) OTADUMP_SHIM_DCHECK_NO_OP
#define DCHECK_GE(left, right) OTADUMP_SHIM_DCHECK_NO_OP
#define DCHECK_GT(left, right) OTADUMP_SHIM_DCHECK_NO_OP
#define DCHECK_LE(left, right) OTADUMP_SHIM_DCHECK_NO_OP
#define DCHECK_LT(left, right) OTADUMP_SHIM_DCHECK_NO_OP
#define DCHECK_NE(left, right) OTADUMP_SHIM_DCHECK_NO_OP
#else
#define DCHECK_EQ(left, right) \
  if ((left) == (right)) {     \
  } else                       \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define DCHECK_GE(left, right) \
  if ((left) >= (right)) {     \
  } else                       \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define DCHECK_GT(left, right) \
  if ((left) > (right)) {      \
  } else                       \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define DCHECK_LE(left, right) \
  if ((left) <= (right)) {     \
  } else                       \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define DCHECK_LT(left, right) \
  if ((left) < (right)) {      \
  } else                       \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#define DCHECK_NE(left, right) \
  if ((left) != (right)) {     \
  } else                       \
  ::base::shim::CheckStream(__FILE__, __LINE__, true)
#endif

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_CHECK_OP_H_

// Project-owned minimal substitute for libchrome safe numeric conversions
// used by the apply-only Zucchini closure. checked_cast and strict_cast abort
// on values outside the destination range, matching upstream CHECK semantics.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_NUMERICS_SAFE_CONVERSIONS_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_NUMERICS_SAFE_CONVERSIONS_H_

#include <cstdlib>

#include "base/numerics/checked_math.h"

namespace base {

template <typename To, typename From>
constexpr bool IsValueInRangeForNumericType(From value) {
  return shim::InRange<To>(value);
}

template <typename To, typename From>
To checked_cast(From value) {
  if (!IsValueInRangeForNumericType<To>(value))
    std::abort();
  return static_cast<To>(value);
}

template <typename To, typename From>
To strict_cast(From value) {
  return checked_cast<To>(value);
}

}  // namespace base

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_NUMERICS_SAFE_CONVERSIONS_H_

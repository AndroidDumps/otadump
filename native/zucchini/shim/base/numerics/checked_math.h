// Project-owned minimal substitute for libchrome CheckedNumeric used by the
// apply-only Zucchini closure. All arithmetic is performed in signed 128-bit
// integers, which represent every value of the integral types Zucchini uses,
// so range and overflow checks are exact.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_NUMERICS_CHECKED_MATH_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_NUMERICS_CHECKED_MATH_H_

#include <cstdlib>
#include <limits>
#include <type_traits>

namespace base {
namespace shim {

template <typename T, typename U>
constexpr bool InRange(U value) {
  static_assert(std::is_integral_v<T> && std::is_integral_v<U>);
  const __int128_t wide = static_cast<__int128_t>(value);
  return wide >= static_cast<__int128_t>(std::numeric_limits<T>::lowest()) &&
         wide <= static_cast<__int128_t>(std::numeric_limits<T>::max());
}

template <typename T, typename U>
constexpr T WideCast(U value) {
  return static_cast<T>(static_cast<__int128_t>(value));
}

}  // namespace shim

template <typename T>
class CheckedNumeric {
 public:
  CheckedNumeric() = default;
  template <typename U,
            std::enable_if_t<std::is_integral_v<U>, int> = 0>
  constexpr CheckedNumeric(U value)
      : value_(static_cast<T>(value)), valid_(shim::InRange<T>(value)) {}

  template <typename U>
  CheckedNumeric operator+(U rhs) const {
    CheckedNumeric result;
    if constexpr (std::is_same_v<U, CheckedNumeric>) {
      if (!valid_ || !rhs.valid_)
        return result.Invalid();
      return result.AssignSum(value_, rhs.value_);
    } else {
      if (!valid_)
        return result.Invalid();
      // The sum, not the operand, must fit: signed operands may be negative.
      return result.AssignSum(value_, rhs);
    }
  }

  template <typename U>
  CheckedNumeric& operator+=(U rhs) {
    *this = *this + rhs;
    return *this;
  }

  constexpr bool IsValid() const { return valid_; }

  T ValueOrDie() const {
    if (!valid_)
      std::abort();
    return value_;
  }

  template <typename U>
  constexpr T ValueOrDefault(U fallback) const {
    return valid_ ? value_ : static_cast<T>(fallback);
  }

  bool AssignIfValid(T* destination) const {
    if (!valid_)
      return false;
    *destination = value_;
    return true;
  }

 private:
  CheckedNumeric& Invalid() {
    valid_ = false;
    return *this;
  }

  template <typename U>
  CheckedNumeric& AssignSum(T lhs, U rhs) {
    const __int128_t sum =
        static_cast<__int128_t>(lhs) + static_cast<__int128_t>(rhs);
    valid_ = sum >= static_cast<__int128_t>(std::numeric_limits<T>::lowest()) &&
             sum <= static_cast<__int128_t>(std::numeric_limits<T>::max());
    if (valid_)
      value_ = static_cast<T>(sum);
    return *this;
  }

  T value_{};
  bool valid_ = true;
};

template <typename U, typename V,
          std::enable_if_t<std::is_integral_v<U>, int> = 0>
CheckedNumeric<V> operator+(U lhs, const CheckedNumeric<V>& rhs) {
  return rhs + lhs;
}

}  // namespace base

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_NUMERICS_CHECKED_MATH_H_

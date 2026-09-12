// Project-owned minimal substitute for libchrome's C++20 erase backports used
// by the apply-only Zucchini closure. Zucchini only erases from std::vector.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_CONTAINERS_CXX20_ERASE_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_CONTAINERS_CXX20_ERASE_H_

#include <algorithm>

namespace base {

template <typename Container, typename Value>
void Erase(Container& container, const Value& value) {
  container.erase(std::remove(container.begin(), container.end(), value),
                  container.end());
}

template <typename Container, typename Predicate>
void EraseIf(Container& container, Predicate predicate) {
  container.erase(std::remove_if(container.begin(), container.end(), predicate),
                  container.end());
}

}  // namespace base

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_CONTAINERS_CXX20_ERASE_H_

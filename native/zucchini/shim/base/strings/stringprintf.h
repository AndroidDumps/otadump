// Project-owned minimal substitute for base::StringPrintf used by the
// apply-only Zucchini closure for diagnostic strings.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_STRINGS_STRINGPRINTF_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_STRINGS_STRINGPRINTF_H_

#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

namespace base {

inline std::string StringPrintf(const char* format, ...) {
  va_list args;
  va_start(args, format);
  va_list copy;
  va_copy(copy, args);
  const int length = std::vsnprintf(nullptr, 0, format, copy);
  va_end(copy);
  if (length < 0) {
    va_end(args);
    return {};
  }
  std::vector<char> buffer(static_cast<size_t>(length) + 1);
  std::vsnprintf(buffer.data(), buffer.size(), format, args);
  va_end(args);
  return std::string(buffer.data(), static_cast<size_t>(length));
}

}  // namespace base

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_STRINGS_STRINGPRINTF_H_

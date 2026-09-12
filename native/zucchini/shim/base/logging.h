// Project-owned minimal substitute for libchrome logging used by the
// apply-only Zucchini closure. Zucchini only logs diagnostics on paths that
// already report failure through return values, so the streams discard their
// input. The severity macros mirror the ones libchrome's logging.h defines.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_LOGGING_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_LOGGING_H_

namespace base::shim {

class LogStream {
 public:
  LogStream(const char*, int) {}
  LogStream(const LogStream&) = delete;
  LogStream& operator=(const LogStream&) = delete;
  template <typename T>
  LogStream& operator<<(const T&) {
    return *this;
  }
};

}  // namespace base::shim

#define INFO 0
#define WARNING 1
#define ERROR 2

#define LOG(severity) ::base::shim::LogStream(__FILE__, __LINE__)
#define LOG_IF(severity, condition) \
  if (!(condition)) {               \
  } else                            \
  ::base::shim::LogStream(__FILE__, __LINE__)

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_LOGGING_H_

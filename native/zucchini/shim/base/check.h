// Project-owned minimal substitute for the libchrome check macros used by the
// apply-only Zucchini closure. CHECK aborts the process on failure, matching
// upstream release semantics. DCHECK compiles to an unevaluated no-op because
// the boundary is built with NDEBUG, matching upstream official builds.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_CHECK_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_CHECK_H_

#include <cstdio>
#include <cstdlib>

namespace base::shim {

class CheckStream {
 public:
  CheckStream(const char* file, int line, bool fatal)
      : file_(file), line_(line), fatal_(fatal) {}
  CheckStream(const CheckStream&) = delete;
  CheckStream& operator=(const CheckStream&) = delete;
  ~CheckStream() {
    if (fatal_) {
      std::fprintf(stderr, "otadump zucchini check failed at %s:%d\n", file_,
                   line_);
      std::abort();
    }
  }
  template <typename T>
  CheckStream& operator<<(const T&) {
    return *this;
  }

 private:
  const char* file_;
  int line_;
  bool fatal_;
};

}  // namespace base::shim

#define CHECK(condition) \
  ::base::shim::CheckStream(__FILE__, __LINE__, !(condition))

#if defined(NDEBUG)
#define DCHECK(condition) \
  ::base::shim::CheckStream(__FILE__, __LINE__, false)
#else
#define DCHECK(condition) \
  ::base::shim::CheckStream(__FILE__, __LINE__, !(condition))
#endif

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_CHECK_H_

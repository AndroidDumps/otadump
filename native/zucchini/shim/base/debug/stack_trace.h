// Project-owned minimal substitute for base::debug::StackTrace used by the
// apply-only Zucchini closure. Zucchini only appends the trace to a discarded
// diagnostic log, so no unwinding is required.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_DEBUG_STACK_TRACE_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_DEBUG_STACK_TRACE_H_

#include <string>

namespace base::debug {

class StackTrace {
 public:
  StackTrace() = default;
  std::string ToString() const { return {}; }
};

}  // namespace base::debug

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_DEBUG_STACK_TRACE_H_

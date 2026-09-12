// Project-owned minimal substitute for libchrome callbacks used by the
// apply-only Zucchini closure. Zucchini binds plain functions, member
// functions on raw pointers, and copyable lambdas, then invokes the result
// synchronously, so std::function plus std::invoke covers the full surface.
#ifndef OTADUMP_ZUCCHINI_SHIM_BASE_CALLBACK_H_
#define OTADUMP_ZUCCHINI_SHIM_BASE_CALLBACK_H_

#include <functional>
#include <tuple>
#include <type_traits>
#include <utility>

namespace base {

template <typename Signature>
class RepeatingCallback;

template <typename Result, typename... Args>
class RepeatingCallback<Result(Args...)> {
 public:
  RepeatingCallback() = default;
  template <typename Callable,
            std::enable_if_t<!std::is_same_v<std::decay_t<Callable>,
                                             RepeatingCallback>,
                             int> = 0>
  RepeatingCallback(Callable callable) : callable_(std::move(callable)) {}

  Result Run(Args... args) const {
    return callable_(std::forward<Args>(args)...);
  }
  explicit operator bool() const { return static_cast<bool>(callable_); }

 private:
  std::function<Result(Args...)> callable_;
};

template <typename Callable, typename... Bound>
auto BindRepeating(Callable&& callable, Bound&&... bound) {
  return [callable = std::decay_t<Callable>(std::forward<Callable>(callable)),
          bound = std::tuple<std::decay_t<Bound>...>(
              std::forward<Bound>(bound)...)](auto&&... args) mutable {
    return std::apply(
        [&](auto&... values) -> decltype(auto) {
          return std::invoke(callable, values...,
                             std::forward<decltype(args)>(args)...);
        },
        bound);
  };
}

// Ownership is irrelevant at this boundary because every callback is invoked
// synchronously while its target is alive.
template <typename T>
T* Unretained(T* pointer) {
  return pointer;
}

}  // namespace base

#endif  // OTADUMP_ZUCCHINI_SHIM_BASE_CALLBACK_H_

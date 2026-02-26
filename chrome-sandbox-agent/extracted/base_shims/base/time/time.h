// Copyright 2012 The Chromium Authors
// Standalone shim: base/time/time.h

#ifndef BASE_TIME_TIME_H_
#define BASE_TIME_TIME_H_

#include <cstdint>
#include <ctime>

namespace base {

class TimeDelta {
 public:
  constexpr TimeDelta() : delta_us_(0) {}

  static constexpr TimeDelta FromSeconds(int64_t s) { return TimeDelta(s * 1000000); }
  static constexpr TimeDelta FromMilliseconds(int64_t ms) { return TimeDelta(ms * 1000); }
  static constexpr TimeDelta FromMicroseconds(int64_t us) { return TimeDelta(us); }

  int64_t InSeconds() const { return delta_us_ / 1000000; }
  int64_t InMilliseconds() const { return delta_us_ / 1000; }
  int64_t InMicroseconds() const { return delta_us_; }

  bool is_zero() const { return delta_us_ == 0; }
  bool is_positive() const { return delta_us_ > 0; }

 private:
  explicit constexpr TimeDelta(int64_t us) : delta_us_(us) {}
  int64_t delta_us_;
};

class Time {
 public:
  static Time Now() {
    Time t;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    t.us_ = static_cast<int64_t>(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
    return t;
  }

 private:
  int64_t us_ = 0;
};

class TimeTicks {
 public:
  static TimeTicks Now() {
    TimeTicks t;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    t.us_ = static_cast<int64_t>(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
    return t;
  }

  TimeDelta operator-(const TimeTicks& other) const {
    return TimeDelta::FromMicroseconds(us_ - other.us_);
  }

 private:
  int64_t us_ = 0;
};

// Free-function constructors matching Chromium style
inline constexpr TimeDelta Milliseconds(int64_t ms) {
  return TimeDelta::FromMilliseconds(ms);
}
inline constexpr TimeDelta Seconds(int64_t s) {
  return TimeDelta::FromSeconds(s);
}
inline constexpr TimeDelta Microseconds(int64_t us) {
  return TimeDelta::FromMicroseconds(us);
}

}  // namespace base

#endif  // BASE_TIME_TIME_H_

// Copyright 2013 The Chromium Authors
// Standalone shim: base/strings/safe_sprintf.h
// Chrome's SafeSPrintf is type-aware: %x/%d auto-size based on the argument's
// actual C++ type (32-bit for int/uint32_t, 64-bit for long/uint64_t).
// This shim replicates that behavior using variadic templates.

#ifndef BASE_STRINGS_SAFE_SPRINTF_H_
#define BASE_STRINGS_SAFE_SPRINTF_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace base {
namespace strings {

namespace internal {

// Write a single character to buffer, respecting bounds.
inline void PutChar(char* buf, size_t N, size_t& pos, char c) {
  if (pos < N - 1) buf[pos] = c;
  pos++;
}

// Write an unsigned integer in the given base.
template <typename T>
void WriteUnsigned(char* buf, size_t N, size_t& pos, T val, int base,
                   bool prefix = false) {
  static_assert(std::is_unsigned_v<T>);
  if (prefix && base == 16) {
    PutChar(buf, N, pos, '0');
    PutChar(buf, N, pos, 'x');
  }
  char tmp[24];
  int len = 0;
  if (val == 0) {
    tmp[len++] = '0';
  } else {
    while (val > 0) {
      int digit = val % base;
      tmp[len++] = digit < 10 ? ('0' + digit) : ('a' + digit - 10);
      val /= base;
    }
  }
  for (int i = len - 1; i >= 0; i--)
    PutChar(buf, N, pos, tmp[i]);
}

// Write a signed integer in base 10.
template <typename T>
void WriteSigned(char* buf, size_t N, size_t& pos, T val) {
  using U = std::make_unsigned_t<T>;
  if (val < 0) {
    PutChar(buf, N, pos, '-');
    // Handle minimum value carefully
    WriteUnsigned(buf, N, pos, static_cast<U>(-(val + 1)) + 1u, 10);
  } else {
    WriteUnsigned(buf, N, pos, static_cast<U>(val), 10);
  }
}

// Arg: a type-erased argument with its type info preserved.
struct Arg {
  enum Type { SIGNED, UNSIGNED, STRING, CHAR, POINTER };
  Type type;
  union {
    int64_t s;
    uint64_t u;
    const char* str;
    char c;
    const void* ptr;
  };
  int size;  // bytes of original type: 1, 2, 4, or 8

  // Constructors for different types
  Arg(signed char v) : type(SIGNED), s(v), size(1) {}
  Arg(short v) : type(SIGNED), s(v), size(2) {}
  Arg(int v) : type(SIGNED), s(v), size(4) {}
  Arg(long v) : type(SIGNED), s(v), size(8) {}
  Arg(long long v) : type(SIGNED), s(v), size(8) {}
  Arg(unsigned char v) : type(UNSIGNED), u(v), size(1) {}
  Arg(unsigned short v) : type(UNSIGNED), u(v), size(2) {}
  Arg(unsigned int v) : type(UNSIGNED), u(v), size(4) {}
  Arg(unsigned long v) : type(UNSIGNED), u(v), size(8) {}
  Arg(unsigned long long v) : type(UNSIGNED), u(v), size(8) {}
  Arg(const char* v) : type(STRING), str(v ? v : "<null>"), size(0) {}
  Arg(char v) : type(CHAR), c(v), size(1) {}
  Arg(const void* v) : type(POINTER), ptr(v), size(0) {}
};

inline ssize_t FormatImpl(char* buf, size_t N, const char* fmt,
                          const Arg* args, size_t nargs) {
  size_t pos = 0;
  size_t arg_idx = 0;

  for (const char* p = fmt; *p; p++) {
    if (*p != '%') {
      PutChar(buf, N, pos, *p);
      continue;
    }
    p++;
    if (*p == '%') {
      PutChar(buf, N, pos, '%');
      continue;
    }
    if (*p == '\0') break;

    // Consume flag '#'
    bool alt = false;
    if (*p == '#') { alt = true; p++; }

    // Consume width (ignored for simplicity)
    while (*p >= '0' && *p <= '9') p++;

    // Consume length modifier (ignored - we use actual C++ type)
    if (*p == 'l' || *p == 'z' || *p == 'j' || *p == 't') p++;
    if (*p == 'l') p++;  // ll

    char spec = *p;
    if (arg_idx >= nargs) {
      // Not enough args
      PutChar(buf, N, pos, '?');
      continue;
    }
    const Arg& a = args[arg_idx++];

    switch (spec) {
      case 'x': case 'X': {
        // Type-aware hex: use the arg's actual size
        uint64_t val = (a.type == Arg::SIGNED)
                           ? static_cast<uint64_t>(a.s)
                           : a.u;
        // Mask to the original type width
        if (a.size <= 4) val &= 0xFFFFFFFFULL;
        if (alt) {
          PutChar(buf, N, pos, '0');
          PutChar(buf, N, pos, 'x');
        }
        WriteUnsigned(buf, N, pos, val, 16);
        break;
      }
      case 'd': case 'i': {
        int64_t val = (a.type == Arg::UNSIGNED)
                          ? static_cast<int64_t>(a.u)
                          : a.s;
        WriteSigned(buf, N, pos, val);
        break;
      }
      case 'u': {
        uint64_t val = (a.type == Arg::SIGNED)
                           ? static_cast<uint64_t>(a.s)
                           : a.u;
        WriteUnsigned(buf, N, pos, val, 10);
        break;
      }
      case 'o': {
        uint64_t val = (a.type == Arg::SIGNED)
                           ? static_cast<uint64_t>(a.s)
                           : a.u;
        if (a.size <= 4) val &= 0xFFFFFFFFULL;
        WriteUnsigned(buf, N, pos, val, 8);
        break;
      }
      case 's': {
        const char* s = (a.type == Arg::STRING) ? a.str : "?";
        while (*s) PutChar(buf, N, pos, *s++);
        break;
      }
      case 'c': {
        PutChar(buf, N, pos, (a.type == Arg::CHAR) ? a.c
                                                     : '?');
        break;
      }
      case 'p': {
        PutChar(buf, N, pos, '0');
        PutChar(buf, N, pos, 'x');
        WriteUnsigned(buf, N, pos,
                      reinterpret_cast<uintptr_t>(a.ptr), 16);
        break;
      }
      default:
        PutChar(buf, N, pos, '?');
        break;
    }
  }

  // Null-terminate
  if (N > 0) buf[pos < N ? pos : N - 1] = '\0';
  return static_cast<ssize_t>(pos);
}

}  // namespace internal

// SafeSNPrintf: type-aware formatting into a buffer.
template <typename... Args>
ssize_t SafeSNPrintf(char* buf, size_t N, const char* fmt, Args... args) {
  internal::Arg arg_array[] = {internal::Arg(args)..., internal::Arg(0)};
  return internal::FormatImpl(buf, N, fmt, arg_array, sizeof...(args));
}

// SafeSPrintf: fixed-size buffer variant.
template <size_t N, typename... Args>
ssize_t SafeSPrintf(char (&buf)[N], const char* fmt, Args... args) {
  return SafeSNPrintf(buf, N, fmt, args...);
}

}  // namespace strings
}  // namespace base

#endif  // BASE_STRINGS_SAFE_SPRINTF_H_

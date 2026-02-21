// Copyright 2012 The Chromium Authors
// Standalone shim: base/compiler_specific.h
// Provides compiler attribute macros used by the sandbox code.

#ifndef BASE_COMPILER_SPECIFIC_H_
#define BASE_COMPILER_SPECIFIC_H_

#include "build/build_config.h"

// Attribute testing
#if defined(__has_attribute)
#define HAS_ATTRIBUTE(x) __has_attribute(x)
#else
#define HAS_ATTRIBUTE(x) 0
#endif

#if defined(__has_builtin)
#define HAS_BUILTIN(x) __has_builtin(x)
#else
#define HAS_BUILTIN(x) 0
#endif

#if defined(__has_feature)
#define HAS_FEATURE(x) __has_feature(x)
#else
#define HAS_FEATURE(x) 0
#endif

// Inlining
#if defined(__clang__) && HAS_ATTRIBUTE(always_inline)
#define ALWAYS_INLINE inline __attribute__((always_inline))
#elif defined(__GNUC__)
#define ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define ALWAYS_INLINE inline
#endif

#if defined(__clang__) && HAS_ATTRIBUTE(noinline)
#define NOINLINE __attribute__((noinline))
#elif defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

// Printf format checking
#if defined(__GNUC__) || defined(__clang__)
#define PRINTF_FORMAT(format_param, dots_param) \
    __attribute__((format(printf, format_param, dots_param)))
#else
#define PRINTF_FORMAT(format_param, dots_param)
#endif

// Tail call / merge attributes
#if HAS_ATTRIBUTE(not_tail_called)
#define NOT_TAIL_CALLED __attribute__((not_tail_called))
#else
#define NOT_TAIL_CALLED
#endif

#if HAS_ATTRIBUTE(nomerge)
#define NOMERGE __attribute__((nomerge))
#else
#define NOMERGE
#endif

// Sanitizer attributes
#define NO_SANITIZE(what)
#define DISABLE_CFI_ICALL

// Trivial ABI
#define TRIVIAL_ABI

// Analyzer support
#define ANALYZER_ASSUME_TRUE(arg) (arg)
#define ANALYZER_SKIP_THIS_PATH()

// Pretty function name
#if defined(__GNUC__) || defined(__clang__)
#define PRETTY_FUNCTION __PRETTY_FUNCTION__
#else
#define PRETTY_FUNCTION __func__
#endif

// Stack attributes
#define STACK_UNINITIALIZED
#if HAS_ATTRIBUTE(no_stack_protector)
#define NO_STACK_PROTECTOR __attribute__((no_stack_protector))
#else
#define NO_STACK_PROTECTOR
#endif

// Buffer safety annotations (pass through)
#define UNSAFE_BUFFERS(...) __VA_ARGS__
#define UNSAFE_TODO(...) __VA_ARGS__
#define UNSAFE_BUFFER_USAGE

// GSL annotations
#define GSL_POINTER
#define GSL_OWNER

// Lifetime annotations
#define LIFETIME_BOUND

// no_unique_address
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 9)
#define NO_UNIQUE_ADDRESS [[no_unique_address]]
#else
#define NO_UNIQUE_ADDRESS
#endif

// Preserve most
#define PRESERVE_MOST

// Weak symbol
#if defined(__GNUC__) || defined(__clang__)
#define WEAK_SYMBOL __attribute__((weak))
#else
#define WEAK_SYMBOL
#endif

// Returns non-null
#if HAS_ATTRIBUTE(returns_nonnull)
#define RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define RETURNS_NONNULL
#endif

// Packed
#if defined(__GNUC__) || defined(__clang__)
#define PACKED_OBJ __attribute__((packed))
#else
#define PACKED_OBJ
#endif

// Enable if
#define ENABLE_IF_ATTR(cond, msg)

// Warn unused result
#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))

#endif  // BASE_COMPILER_SPECIFIC_H_

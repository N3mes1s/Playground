// Copyright 2012 The Chromium Authors
// Standalone shim for build/build_config.h
// Provides platform detection macros used throughout Chromium.

#ifndef BUILD_BUILD_CONFIG_H_
#define BUILD_BUILD_CONFIG_H_

// We only target Linux x86_64 for this standalone extraction.
#define BUILDFLAG_INTERNAL_IS_LINUX() (1)
#define BUILDFLAG_INTERNAL_IS_CHROMEOS() (0)
#define BUILDFLAG_INTERNAL_IS_ANDROID() (0)
#define BUILDFLAG_INTERNAL_IS_IOS() (0)
#define BUILDFLAG_INTERNAL_IS_APPLE() (0)
#define BUILDFLAG_INTERNAL_IS_MAC() (0)
#define BUILDFLAG_INTERNAL_IS_WIN() (0)
#define BUILDFLAG_INTERNAL_IS_FUCHSIA() (0)
#define BUILDFLAG_INTERNAL_IS_POSIX() (1)
#define BUILDFLAG_INTERNAL_IS_OZONE() (0)

// Feature flags used by sandbox tests
#define BUILDFLAG_INTERNAL_ENABLE_MUTEX_PRIORITY_INHERITANCE() (0)
#define BUILDFLAG_INTERNAL_CLANG_PROFILING() (0)

#define BUILDFLAG(flag) (BUILDFLAG_INTERNAL_##flag())

// Architecture detection
#if defined(__x86_64__) || defined(_M_X64)
#define ARCH_CPU_X86_FAMILY 1
#define ARCH_CPU_X86_64 1
#define ARCH_CPU_64_BITS 1
#define ARCH_CPU_LITTLE_ENDIAN 1
#elif defined(__aarch64__)
#define ARCH_CPU_ARM_FAMILY 1
#define ARCH_CPU_ARM64 1
#define ARCH_CPU_64_BITS 1
#define ARCH_CPU_LITTLE_ENDIAN 1
#elif defined(__i386__) || defined(_M_IX86)
#define ARCH_CPU_X86_FAMILY 1
#define ARCH_CPU_X86 1
#define ARCH_CPU_32_BITS 1
#define ARCH_CPU_LITTLE_ENDIAN 1
#elif defined(__arm__)
#define ARCH_CPU_ARM_FAMILY 1
#define ARCH_CPU_ARMEL 1
#define ARCH_CPU_32_BITS 1
#define ARCH_CPU_LITTLE_ENDIAN 1
#endif

// Compiler detection
#if defined(__clang__)
#define COMPILER_CLANG 1
#elif defined(__GNUC__)
#define COMPILER_GCC 1
#endif

#endif  // BUILD_BUILD_CONFIG_H_

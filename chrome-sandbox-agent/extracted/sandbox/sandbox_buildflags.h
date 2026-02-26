// Standalone shim: sandbox/sandbox_buildflags.h
#ifndef SANDBOX_SANDBOX_BUILDFLAGS_H_
#define SANDBOX_SANDBOX_BUILDFLAGS_H_

// Seccomp-BPF is always enabled in our standalone Linux build
#define BUILDFLAG_INTERNAL_USE_SECCOMP_BPF() (1)

#endif  // SANDBOX_SANDBOX_BUILDFLAGS_H_

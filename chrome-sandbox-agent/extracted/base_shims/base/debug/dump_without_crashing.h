// Standalone shim: base/debug/dump_without_crashing.h
#ifndef BASE_DEBUG_DUMP_WITHOUT_CRASHING_H_
#define BASE_DEBUG_DUMP_WITHOUT_CRASHING_H_

namespace base::debug {
inline void DumpWithoutCrashing() {}
}

#define SCOPED_CRASH_KEY_STRING256(category, name, value)
#define SCOPED_CRASH_KEY_BOOL(category, name, value)

#endif

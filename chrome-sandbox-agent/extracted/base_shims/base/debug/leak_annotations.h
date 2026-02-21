// Stub: base/debug/leak_annotations.h
#ifndef BASE_DEBUG_LEAK_ANNOTATIONS_H_
#define BASE_DEBUG_LEAK_ANNOTATIONS_H_
// No-op for non-LSan builds
#define ANNOTATE_LEAKING_OBJECT_PTR(p) ((void)(p))
#define ANNOTATE_SCOPED_MEMORY_LEAK
#endif

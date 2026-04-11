/*
 * DK PAL Implementation - The 72 Drawbridge Kernel functions
 *
 * These are the functions the NTUM (sqlpal.dll) calls through the PAL.
 * Each function uses Windows x64 calling convention (rcx, rdx, r8, r9).
 */

#ifndef DK_PAL_H
#define DK_PAL_H

#include <stdint.h>

/* DK status codes (NTSTATUS-like) */
#define DK_STATUS_SUCCESS          0x00000000
#define DK_STATUS_NOT_IMPLEMENTED  0xC0000002
#define DK_STATUS_INVALID_PARAM    0xC000000D
#define DK_STATUS_NO_MEMORY        0xC0000017

/* DK handle type */
typedef uint64_t DK_HANDLE;
#define DK_NULL_HANDLE 0

/*
 * All DK functions use Windows x64 calling convention.
 * On Linux (SysV ABI), we receive args in rdi,rsi,rdx,rcx
 * but the NTUM calls us with args in rcx,rdx,r8,r9.
 *
 * Since the trampoline already switched the stack to LibOS space
 * and the NTUM's own code uses Win64, calls FROM the NTUM to us
 * come in Win64 convention. We need __attribute__((ms_abi)) to
 * receive them correctly.
 */
#ifdef __GNUC__
#define DK_API __attribute__((ms_abi))
#else
#define DK_API
#endif

/* Stream operations */
DK_API uint64_t DK_StreamOpen(const void *uri, uint64_t uri_len,
                               uint64_t access, uint64_t share_mode,
                               uint64_t create_disp, uint64_t flags,
                               DK_HANDLE *out_handle);
DK_API uint64_t DK_StreamRead(DK_HANDLE stream, uint64_t offset,
                               void *buffer, uint64_t bytes_to_read,
                               uint64_t *bytes_read);
DK_API uint64_t DK_StreamWrite(DK_HANDLE stream, uint64_t offset,
                                const void *buffer, uint64_t bytes_to_write,
                                uint64_t *bytes_written);
DK_API uint64_t DK_StreamClose(DK_HANDLE handle);
DK_API uint64_t DK_StreamFlush(DK_HANDLE stream);
DK_API uint64_t DK_StreamSetLength(DK_HANDLE stream, uint64_t length);
DK_API uint64_t DK_StreamMap(DK_HANDLE stream, void *address,
                              uint64_t offset, uint64_t size,
                              uint64_t protect, void **mapped);
DK_API uint64_t DK_StreamMapPeBinary(DK_HANDLE stream, void **base,
                                      uint64_t *entry_point);
DK_API uint64_t DK_StreamUnmap(void *address, uint64_t size);
DK_API uint64_t DK_StreamDelete(DK_HANDLE stream);
DK_API uint64_t DK_StreamControl(DK_HANDLE in_handle, uint64_t op_code,
                                  void *in_buf, uint64_t in_size,
                                  void *out_buf, uint64_t out_size);
DK_API uint64_t DK_StreamAttributesQuery(const void *uri, void *attrs);
DK_API uint64_t DK_StreamAttributesQueryByHandle(DK_HANDLE stream, 
                                                   uint64_t flags, void *attrs);
DK_API uint64_t DK_StreamEnumerateChildren(DK_HANDLE stream, void *buf,
                                            uint64_t buf_size, uint64_t *used);
DK_API uint64_t DK_StreamRename(DK_HANDLE stream, const void *new_name);
DK_API uint64_t DK_StreamChangesRegister(DK_HANDLE stream, uint64_t filter,
                                          uint64_t watch_tree, DK_HANDLE *event);
DK_API uint64_t DK_StreamChangesPoll(DK_HANDLE stream, void *buf, uint64_t *size);
DK_API uint64_t DK_StreamRangeLock(DK_HANDLE stream, uint64_t off, uint64_t len,
                                    uint64_t exclusive);
DK_API uint64_t DK_StreamRangeUnlock(DK_HANDLE stream, uint64_t off, uint64_t len);
DK_API uint64_t DK_StreamGetEvent(DK_HANDLE stream, uint64_t event_id,
                                   DK_HANDLE *event);
DK_API uint64_t DK_StreamEventSelect(DK_HANDLE stream, DK_HANDLE event,
                                      uint64_t poll_events, DK_HANDLE *async);

/* Memory */
DK_API uint64_t DK_VirtualMemoryAllocate(void **address, uint64_t *size,
                                          uint64_t alloc_type, uint64_t protect);
DK_API uint64_t DK_VirtualMemoryFree(void *address, uint64_t size, uint64_t free_type);
DK_API uint64_t DK_VirtualMemoryProtect(void *address, uint64_t size,
                                         uint64_t new_protect, uint64_t *old_protect);

/* Threading */
DK_API uint64_t DK_ThreadCreate(void *start_routine, void *stack_ptr,
                                 uint64_t flags, DK_HANDLE *thread);
DK_API void     DK_ThreadExit(uint64_t exit_code);
DK_API uint64_t DK_ThreadYieldExecution(void);
DK_API uint64_t DK_ThreadInterrupt(DK_HANDLE thread);
DK_API uint64_t DK_ThreadSetAffinity(DK_HANDLE thread, uint64_t group, uint64_t mask);

/* Synchronization */
DK_API uint64_t DK_NotificationEventCreate(uint64_t initial_state, DK_HANDLE *event);
DK_API uint64_t DK_SynchronizationEventCreate(uint64_t initial_state, DK_HANDLE *event);
DK_API uint64_t DK_EventSet(DK_HANDLE event);
DK_API uint64_t DK_EventClear(DK_HANDLE event);
DK_API uint64_t DK_EventPeek(DK_HANDLE event, uint64_t *signaled);
DK_API uint64_t DK_ObjectsWaitAny(uint64_t count, DK_HANDLE *objects,
                                   uint64_t timeout, uint64_t *index);

/* Objects */
DK_API uint64_t DK_ObjectClose(DK_HANDLE handle);
DK_API uint64_t DK_ObjectReference(DK_HANDLE handle);

/* Process */
DK_API uint64_t DK_ProcessCreate(void *params, DK_HANDLE *process);
DK_API void     DK_ProcessExit(uint64_t exit_code);
DK_API uint64_t DK_ProcessTerminate(DK_HANDLE process, uint64_t exit_code);
DK_API uint64_t DK_ProcessGetExitCode(DK_HANDLE process, uint64_t *exit_code);

/* System */
DK_API uint64_t DK_SystemTimeQuery(uint64_t clock_type, uint64_t *time);
DK_API uint64_t DK_RandomBitsRead(void *buffer, uint64_t length);

/* Console */
DK_API uint64_t DK_ConsoleCreate(DK_HANDLE *console);

/* ABI dispatch */
DK_API uint64_t DK_AbiGetVersion(void *in_buf, uint64_t in_size,
                                  void *out_buf, uint64_t out_size);
DK_API uint64_t DK_AbiGetFunction(uint64_t abi_id, void **func_ptr);

/* Exception */
DK_API uint64_t DK_ExceptionRecordFree(void *record);

/* Cache */
DK_API uint64_t DK_InstructionCacheFlush(void *base, uint64_t length);

/* Initialize all DK PAL functions */
void dk_pal_init(void);

/* Get the PAL dispatch table for WINDOWS_LIBOS_PARAMETERS */
void *dk_pal_get_table(void);

#endif /* DK_PAL_H */

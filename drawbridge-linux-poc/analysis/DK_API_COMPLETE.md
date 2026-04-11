# Drawbridge Kernel (DK) API - Complete PAL Interface

Extracted from sqlpal.dll trace strings. These are the ~72 functions
that the NTUM calls through the PAL to the Linux host.

## ABI Negotiation
- `DKAbiGetFunction(abiIdAndVersion)` - Get function pointer by ABI ID

## Stream I/O (Files, Network, Pipes)
- `DKStreamOpen` - Open a stream (file, pipe, network)
- `DKStreamRead(stream, readOffset, bytesToRead)`
- `DKStreamWrite(stream, writeOffset, bytesToWrite)`
- `DKStreamClose` (via DKObjectClose)
- `DKStreamFlush(stream)`
- `DKStreamMap(stream, offset)` - Memory-map a stream
- `DKStreamMapPeBinary(stream)` - Map a PE file from stream
- `DKStreamUnmap`
- `DKStreamSetLength(stream, length)` - Truncate/extend
- `DKStreamDelete(stream)` - Delete a file
- `DKStreamRename(stream)` - Rename
- `DKStreamControl(inHandle, operationCode)` - ioctl equivalent
- `DKStreamAttributesQuery` - stat() equivalent
- `DKStreamAttributesQueryByHandle(stream, queryFlags)`
- `DKStreamEnumerateChildren(stream)` - readdir() equivalent
- `DKStreamChangesRegister(stream, filter, watchTree)` - inotify
- `DKStreamChangesPoll(stream)`
- `DKStreamRangeLock/RangeUnlock(stream, offset, length)`
- `DKStreamSetZeroData(stream)`
- `DKStreamQueryAllocatedRanges(stream)`
- `DKStreamEnableSparse(stream, isSparse)`
- `DKStreamReadScatter/ReadScatterEx` - Scatter/gather I/O
- `DKStreamWriteGather/WriteGatherEx`
- `DKStreamGetEvent(stream, eventId)`
- `DKStreamEventSelect(stream, event, pollEvents)`

## Memory Management
- `DKVirtualMemoryAllocate(desiredAddress, desiredLength, allocationType, protect)`
- `DKVirtualMemoryFree(baseAddress, regionLength, freeType)`
- `DKVirtualMemoryProtect(baseAddress, regionLength, newProtect)`
- `DKInstructionCacheFlush(baseAddress, length)`

## Threading
- `DKThreadCreate(startRoutine, initialStackPointer)`
- `DKThreadExit`
- `DKThreadInterrupt(thread)`
- `DKThreadSetAffinity(thread, group, mask)`
- `DKThreadAssertAffinity(thread, group, mask)`
- `DKThreadYieldExecution`
- `DKDkThreadSetRegisters` - Set thread register context

## Synchronization
- `DKNotificationEventCreate(initialState)` - Manual-reset event
- `DKSynchronizationEventCreate(initialState)` - Auto-reset event
- `DKEventSet(event)`
- `DKEventClear(event)`
- `DKEventPeek(event)` - Check without waiting
- `DKObjectsWaitAny(objectCount, timeout)` - WaitForMultipleObjects

## Object Management
- `DKObjectClose(handle)`
- `DKObjectReference(handle)` - AddRef

## Process Management
- `DKProcessCreate`
- `DKProcessExit(exitCode)`
- `DKProcessTerminate(process, exitCode)`
- `DKProcessGetExitCode(process)`

## System
- `DKSystemTimeQuery(clockType)` - Clock/time
- `DKRandomBitsRead(length)` - Cryptographic random

## Console
- `DKConsoleCreate`
- `DKConsoleEventPoll(console)`
- `DKConsoleNotifyUpdate(console)`

## Async I/O
- `DKAsyncPoll(asyncRequest)`
- `DKAsyncCancel(asyncRequest)`
- `DKAsyncCancelPumpIoRequest`

## Enclave (SGX)
- `DKEnclaveAttest(enclaveData, enclaveDataLength)`
- `DKEnclavePagesCommit(address, size)`
- `DKEnclavePagesFree(address, size)`
- `DKEnclavePagesProtect(address, size, protect)`
- `DKEnclavePagesRemove(address, size)`

## Exception Handling
- `DKExceptionRecordFree`

## Linux PAL Mapping

| DK Function | Linux Implementation |
|-------------|---------------------|
| DKStreamOpen | `open()` / `socket()` |
| DKStreamRead | `pread()` |
| DKStreamWrite | `pwrite()` |
| DKStreamMap | `mmap()` |
| DKStreamMapPeBinary | `mmap()` + section parsing |
| DKStreamFlush | `fsync()` |
| DKStreamDelete | `unlink()` |
| DKStreamRename | `rename()` |
| DKStreamEnumerateChildren | `getdents64()` |
| DKStreamChangesRegister | `inotify_add_watch()` |
| DKVirtualMemoryAllocate | `mmap(MAP_ANONYMOUS)` |
| DKVirtualMemoryFree | `munmap()` |
| DKVirtualMemoryProtect | `mprotect()` |
| DKThreadCreate | `clone()` / `pthread_create()` |
| DKThreadExit | `pthread_exit()` |
| DKNotificationEventCreate | `eventfd()` |
| DKEventSet | `write(eventfd)` |
| DKObjectsWaitAny | `epoll_wait()` / `poll()` |
| DKSystemTimeQuery | `clock_gettime()` |
| DKRandomBitsRead | `getrandom()` |
| DKProcessExit | `exit_group()` |
| DKConsoleCreate | pty / pipe |

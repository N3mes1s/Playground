//! # Synchronization Primitives
//!
//! Provides spinlock-based synchronization for the unikernel.
//! Since we run in a single-address-space with cooperative scheduling,
//! these are simpler than traditional OS mutexes.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use core::ops::{Deref, DerefMut};

/// A simple spinlock.
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin with hint to reduce power consumption
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }

    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// A one-shot event flag.
pub struct Event {
    signaled: AtomicBool,
}

impl Event {
    pub const fn new() -> Self {
        Event {
            signaled: AtomicBool::new(false),
        }
    }

    pub fn signal(&self) {
        self.signaled.store(true, Ordering::Release);
    }

    pub fn wait(&self) {
        while !self.signaled.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    pub fn is_signaled(&self) -> bool {
        self.signaled.load(Ordering::Acquire)
    }

    pub fn reset(&self) {
        self.signaled.store(false, Ordering::Release);
    }
}

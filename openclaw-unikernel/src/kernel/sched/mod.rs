//! # Cooperative Scheduler
//!
//! A lightweight, cooperative (non-preemptive) task scheduler designed for
//! the unikernel's single-address-space model. Tasks yield voluntarily.
//!
//! This is modeled after async executors — each "task" is a pinned future
//! that gets polled. The agent loop, network stack, channel listeners,
//! and heartbeat engine all run as cooperative tasks.

use alloc::collections::VecDeque;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

/// Unique task identifier.
pub type TaskId = u64;

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);
static SCHEDULER_READY: AtomicBool = AtomicBool::new(false);

/// Task state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
    Completed,
}

/// A cooperative task — wraps a closure that returns whether it's done.
pub struct Task {
    pub id: TaskId,
    pub name: &'static str,
    pub state: TaskState,
    /// The task function. Returns `true` when the task is complete.
    func: Box<dyn FnMut() -> bool + Send>,
}

impl Task {
    pub fn new(name: &'static str, func: Box<dyn FnMut() -> bool + Send>) -> Self {
        Task {
            id: NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed),
            name,
            state: TaskState::Ready,
            func,
        }
    }

    /// Poll the task. Returns `true` if the task has completed.
    pub fn poll(&mut self) -> bool {
        self.state = TaskState::Running;
        let done = (self.func)();
        if done {
            self.state = TaskState::Completed;
        } else {
            self.state = TaskState::Ready;
        }
        done
    }
}

/// The scheduler's run queue.
static mut RUN_QUEUE: Option<VecDeque<Task>> = None;
static mut COMPLETED: Option<Vec<TaskId>> = None;

/// Initialize the scheduler.
pub fn init() {
    unsafe {
        RUN_QUEUE = Some(VecDeque::new());
        COMPLETED = Some(Vec::new());
    }
    SCHEDULER_READY.store(true, Ordering::SeqCst);
}

/// Spawn a new task into the scheduler.
pub fn spawn(name: &'static str, func: Box<dyn FnMut() -> bool + Send>) -> TaskId {
    let task = Task::new(name, func);
    let id = task.id;
    unsafe {
        if let Some(ref mut queue) = RUN_QUEUE {
            queue.push_back(task);
        }
    }
    id
}

/// Run one round of the scheduler — polls each ready task once.
/// Returns the number of tasks still active.
pub fn tick() -> usize {
    if !SCHEDULER_READY.load(Ordering::Relaxed) {
        return 0;
    }

    unsafe {
        let queue = match RUN_QUEUE.as_mut() {
            Some(q) => q,
            None => return 0,
        };

        // Pop-and-push-back in-place to avoid allocating a new VecDeque
        let len = queue.len();
        for _ in 0..len {
            if let Some(mut task) = queue.pop_front() {
                let done = task.poll();
                if done {
                    if let Some(ref mut completed) = COMPLETED {
                        completed.push(task.id);
                    }
                    // Task dropped — not pushed back
                } else {
                    queue.push_back(task);
                }
            }
        }

        queue.len()
    }
}

/// Yield the current task — in a unikernel, this is just a scheduler tick.
pub fn yield_now() {
    tick();
}

/// Get the number of queued tasks.
pub fn task_count() -> usize {
    unsafe {
        RUN_QUEUE.as_ref().map_or(0, |q| q.len())
    }
}

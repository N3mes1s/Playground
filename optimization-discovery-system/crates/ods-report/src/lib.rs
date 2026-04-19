//! PR body + dev-mode report generation. The output is the product's public
//! face: numbers, CI bounds, syscall/alloc deltas, recipe IDs, compat evidence,
//! and a one-command reproduction recipe. Non-deterministic text is out of
//! bounds - every number in the body is traceable to a stored measurement.

pub mod markdown;

pub use markdown::{render_pr_body, ReportInputs};

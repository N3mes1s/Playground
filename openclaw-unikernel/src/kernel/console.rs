//! # Console I/O
//!
//! Provides output via two backends:
//! - VGA text-mode buffer (0xB8000) for display
//! - COM1 serial port (0x3F8) for headless/QEMU operation
//!
//! Both are initialized at boot and written to simultaneously.

use core::fmt;
use super::{inb, outb};

const VGA_BUFFER: usize = 0xB8000;
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;
const SERIAL_PORT: u16 = 0x3F8;

static mut VGA_COL: usize = 0;
static mut VGA_ROW: usize = 0;
static mut INITIALIZED: bool = false;

/// Color codes for VGA text mode.
#[repr(u8)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

/// Initialize both VGA and serial console.
pub fn init() {
    unsafe {
        // Initialize serial port COM1
        outb(SERIAL_PORT + 1, 0x00); // Disable interrupts
        outb(SERIAL_PORT + 3, 0x80); // Enable DLAB
        outb(SERIAL_PORT + 0, 0x03); // 38400 baud (lo)
        outb(SERIAL_PORT + 1, 0x00); // 38400 baud (hi)
        outb(SERIAL_PORT + 3, 0x03); // 8 bits, no parity, one stop bit
        outb(SERIAL_PORT + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
        outb(SERIAL_PORT + 4, 0x0B); // IRQs enabled, RTS/DSR set

        // Clear VGA screen
        let vga = VGA_BUFFER as *mut u16;
        for i in 0..(VGA_WIDTH * VGA_HEIGHT) {
            *vga.add(i) = 0x0F20; // White on black, space character
        }

        VGA_COL = 0;
        VGA_ROW = 0;
        INITIALIZED = true;
    }
}

/// Write a string to both VGA and serial.
pub fn puts(s: &str) {
    for byte in s.bytes() {
        put_char(byte);
    }
}

/// Write a single character to both outputs.
fn put_char(c: u8) {
    serial_write(c);
    vga_write(c);
}

fn serial_write(c: u8) {
    unsafe {
        // Wait for transmit buffer empty
        while (inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        outb(SERIAL_PORT, c);
    }
}

fn vga_write(c: u8) {
    unsafe {
        if !INITIALIZED {
            return;
        }
        match c {
            b'\n' => {
                VGA_COL = 0;
                VGA_ROW += 1;
                if VGA_ROW >= VGA_HEIGHT {
                    scroll_vga();
                }
            }
            b'\r' => {
                VGA_COL = 0;
            }
            c => {
                let vga = VGA_BUFFER as *mut u16;
                let idx = VGA_ROW * VGA_WIDTH + VGA_COL;
                *vga.add(idx) = (0x0F << 8) | (c as u16);
                VGA_COL += 1;
                if VGA_COL >= VGA_WIDTH {
                    VGA_COL = 0;
                    VGA_ROW += 1;
                    if VGA_ROW >= VGA_HEIGHT {
                        scroll_vga();
                    }
                }
            }
        }
    }
}

unsafe fn scroll_vga() {
    let vga = VGA_BUFFER as *mut u16;
    // Move all rows up by one
    for row in 1..VGA_HEIGHT {
        for col in 0..VGA_WIDTH {
            let src = row * VGA_WIDTH + col;
            let dst = (row - 1) * VGA_WIDTH + col;
            unsafe { *vga.add(dst) = *vga.add(src) };
        }
    }
    // Clear last row
    for col in 0..VGA_WIDTH {
        let idx = (VGA_HEIGHT - 1) * VGA_WIDTH + col;
        unsafe { *vga.add(idx) = 0x0F20 };
    }
    unsafe { VGA_ROW = VGA_HEIGHT - 1 };
}

/// Kernel writer implementing `fmt::Write` for formatted output.
pub struct KernelWriter;

impl fmt::Write for KernelWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        puts(s);
        Ok(())
    }
}

/// Print formatted output to the console.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::kernel::console::KernelWriter, $($arg)*);
    });
}

/// Print formatted output with a newline.
#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ({
        $crate::kprint!($($arg)*);
        $crate::kprint!("\n");
    });
}

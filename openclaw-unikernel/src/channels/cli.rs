//! # CLI Channel
//!
//! In the unikernel, the CLI channel reads from the serial port (COM1).
//! This is the primary interactive interface when running under QEMU.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

pub struct CliChannel {
    config: ChannelConfig,
    running: bool,
    input_buffer: Vec<u8>,
    pending_messages: Vec<ChannelMessage>,
    msg_counter: u64,
}

impl CliChannel {
    pub fn new(config: ChannelConfig) -> Self {
        CliChannel {
            config,
            running: false,
            input_buffer: Vec::with_capacity(4096),
            pending_messages: Vec::new(),
            msg_counter: 0,
        }
    }

    /// Check if a character is available on the serial port.
    fn serial_available(&self) -> bool {
        unsafe { (crate::kernel::inb(0x3F8 + 5) & 0x01) != 0 }
    }

    /// Read one character from the serial port.
    fn serial_read(&self) -> u8 {
        unsafe { crate::kernel::inb(0x3F8) }
    }
}

impl Channel for CliChannel {
    fn name(&self) -> &str {
        "cli"
    }

    fn start(&mut self) -> Result<(), String> {
        self.running = true;
        crate::kernel::console::puts("openclaw> ");
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        if !self.running {
            return Vec::new();
        }

        // Non-blocking read from serial port
        while self.serial_available() {
            let byte = self.serial_read();

            match byte {
                b'\r' | b'\n' => {
                    // Echo newline
                    crate::kernel::console::puts("\n");

                    if !self.input_buffer.is_empty() {
                        let content = String::from_utf8_lossy(&self.input_buffer).into_owned();
                        self.input_buffer.clear();

                        // Check for quit commands
                        let trimmed = content.trim();
                        if trimmed == "/quit" || trimmed == "/exit" {
                            crate::kernel::console::puts("[openclaw] goodbye.\n");
                            self.running = false;
                            return Vec::new();
                        }

                        self.msg_counter += 1;
                        self.pending_messages.push(ChannelMessage {
                            id: format!("cli-{}", self.msg_counter),
                            channel: String::from("cli"),
                            sender: String::from("user"),
                            content,
                            timestamp: crate::kernel::rdtsc(),
                            metadata: MessageMetadata::default(),
                        });
                    }

                    crate::kernel::console::puts("openclaw> ");
                }
                0x7F | 0x08 => {
                    // Backspace
                    if !self.input_buffer.is_empty() {
                        self.input_buffer.pop();
                        crate::kernel::console::puts("\x08 \x08");
                    }
                }
                byte if byte >= 0x20 => {
                    // Printable character
                    self.input_buffer.push(byte);
                    // Echo
                    crate::kernel::console::puts(
                        core::str::from_utf8(&[byte]).unwrap_or("?")
                    );
                }
                _ => {} // Ignore control characters
            }
        }

        // Drain pending messages
        let messages = core::mem::take(&mut self.pending_messages);
        messages
    }

    fn send_message(&self, _to: &str, content: &str) -> Result<(), String> {
        crate::kernel::console::puts("\n");
        crate::kernel::console::puts(content);
        crate::kernel::console::puts("\n\n");
        Ok(())
    }

    fn health_check(&self) -> Result<(), String> {
        if self.running {
            Ok(())
        } else {
            Err(String::from("CLI channel not running"))
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}

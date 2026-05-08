//! Custom in-memory tracing layer for the Observe tab's log pane.
//!
//! Why we ship this: `tui-logger` is the off-the-shelf option but it's pinned
//! to ratatui 0.29 as of writing, and we're on 0.30. The logic we need is
//! small — capture each tracing event into a ring buffer with elapsed-time,
//! level, target, and message — so we own it.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use ratatui::style::{Color, Style};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// One captured tracing event.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub at: Instant,
    pub level: tracing::Level,
    pub target: String,
    pub message: String,
}

impl LogEntry {
    pub fn level_style(&self) -> Style {
        match self.level {
            tracing::Level::ERROR => Style::default().fg(Color::Red),
            tracing::Level::WARN => Style::default().fg(Color::Yellow),
            tracing::Level::INFO => Style::default().fg(Color::Green),
            tracing::Level::DEBUG => Style::default().fg(Color::Cyan),
            tracing::Level::TRACE => Style::default().fg(Color::DarkGray),
        }
    }

    pub fn level_label(&self) -> &'static str {
        match self.level {
            tracing::Level::ERROR => "ERR",
            tracing::Level::WARN => "WRN",
            tracing::Level::INFO => "INF",
            tracing::Level::DEBUG => "DBG",
            tracing::Level::TRACE => "TRC",
        }
    }
}

/// Shared ring buffer of recent log entries. Cheaply cloneable — the inner
/// `Mutex` is `parking_lot` so it's poison-free.
#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<Mutex<VecDeque<LogEntry>>>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let mut buf = self.inner.lock();
        if buf.len() == self.capacity {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Snapshot the most recent N entries (newest last).
    pub fn snapshot(&self, n: usize) -> Vec<LogEntry> {
        let buf = self.inner.lock();
        let start = buf.len().saturating_sub(n);
        buf.iter().skip(start).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new(2000)
    }
}

/// `tracing_subscriber::Layer` that writes events into the LogBuffer.
pub struct LogLayer {
    pub buffer: LogBuffer,
}

impl LogLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            let _ = write!(self.0, " {}={}", field.name(), value);
        }
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let metadata = event.metadata();
        self.buffer.push(LogEntry {
            at: Instant::now(),
            level: *metadata.level(),
            target: metadata.target().to_string(),
            message: visitor.0,
        });
    }
}

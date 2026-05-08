//! Event types and the async fan-in loop.
//!
//! Standard ratatui pattern: a single `mpsc::UnboundedSender<Event>` collects
//! crossterm input, periodic ticks, render frames, and application-level
//! messages from background tasks (BACnet polling, HTTP requests, etc.).
//! The TUI render loop drains this channel via `tokio::select!`.

use std::time::Duration;

use futures::StreamExt;
use ratatui::crossterm::event::{
    Event as CTEvent, EventStream, KeyEvent, KeyEventKind, MouseEvent,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// All events flowing into the TUI render loop.
#[derive(Debug, Clone)]
pub enum Event {
    /// Periodic state refresh — fires every ~250ms. Used by background pollers.
    Tick,
    /// Render trigger — fires at ~60Hz cap.
    Render,
    /// Crossterm keyboard event (already filtered to `KeyEventKind::Press`).
    Key(KeyEvent),
    /// Crossterm mouse event.
    Mouse(MouseEvent),
    /// Terminal resize.
    Resize(u16, u16),
    /// A toast-style status message.
    Status(StatusKind, String),
}

#[derive(Debug, Clone, Copy)]
pub enum StatusKind {
    Info,
    Ok,
    Warn,
    Err,
}

/// Sender handle for tasks that want to push events into the TUI loop.
pub type AppSender = UnboundedSender<Event>;

/// Receiver handle owned by the render loop.
pub type AppReceiver = UnboundedReceiver<Event>;

/// Spawn the input/tick/render fan-in. Returns the receiver and a handle to
/// the background task. Cancelling `shutdown` stops the task cleanly.
pub fn spawn(shutdown: CancellationToken) -> (AppReceiver, AppSender, JoinHandle<()>) {
    let (tx, rx) = unbounded_channel::<Event>();
    let task_tx = tx.clone();
    let handle = tokio::spawn(run_event_loop(task_tx, shutdown));
    (rx, tx, handle)
}

async fn run_event_loop(tx: AppSender, shutdown: CancellationToken) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut render = tokio::time::interval(Duration::from_millis(16));
    // Skip the immediate first tick that intervals fire by default.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    render.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut events = EventStream::new();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tick.tick() => {
                if tx.send(Event::Tick).is_err() { break; }
            }
            _ = render.tick() => {
                if tx.send(Event::Render).is_err() { break; }
            }
            Some(Ok(ev)) = events.next() => {
                if !forward(&tx, ev) { break; }
            }
        }
    }
}

fn forward(tx: &AppSender, ev: CTEvent) -> bool {
    let outgoing = match ev {
        // Filter out Release/Repeat: Windows crossterm fires both Press and
        // Release for every key, which would double-handle keystrokes.
        CTEvent::Key(k) if k.kind == KeyEventKind::Press => Event::Key(k),
        CTEvent::Mouse(m) => Event::Mouse(m),
        CTEvent::Resize(w, h) => Event::Resize(w, h),
        _ => return true, // ignore but keep the loop alive
    };
    tx.send(outgoing).is_ok()
}

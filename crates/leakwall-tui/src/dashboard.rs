use crate::TuiError;
use chrono::{DateTime, Utc};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use leakwall_proxy::{Action, ProxyEvent, ScanMode};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};

/// Traffic entry displayed in the TUI.
#[derive(Clone)]
pub struct TrafficEntry {
    timestamp: DateTime<Utc>,
    host: String,
    method: String,
    path: String,
    action: Action,
    _match_count: usize,
    detail: Option<String>,
}

/// State for the TUI dashboard.
pub struct DashboardState {
    pub mode: Arc<RwLock<ScanMode>>,
    pub display_mode: ScanMode,
    pub pid: Option<u32>,
    pub command: String,
    pub start_time: Instant,
    pub total_requests: usize,
    pub blocked_count: usize,
    pub warned_count: usize,
    pub caught_count: usize,
    pub total_bytes_scanned: usize,
    pub traffic: Vec<TrafficEntry>,
    pub scroll_offset: usize,
    pub should_quit: bool,
}

impl DashboardState {
    pub fn new(mode: Arc<RwLock<ScanMode>>, display_mode: ScanMode, command: String) -> Self {
        Self {
            mode,
            display_mode,
            pid: None,
            command,
            start_time: Instant::now(),
            total_requests: 0,
            blocked_count: 0,
            warned_count: 0,
            caught_count: 0,
            total_bytes_scanned: 0,
            traffic: Vec::new(),
            scroll_offset: 0,
            should_quit: false,
        }
    }

    fn handle_event(&mut self, event: ProxyEvent) {
        match event {
            ProxyEvent::RequestIntercepted {
                timestamp,
                host,
                method,
                path,
                body_size,
                scan_result,
                action,
            } => {
                self.total_requests += 1;
                self.total_bytes_scanned += body_size;

                let match_count = scan_result.matches.len();
                let detail = if match_count > 0 {
                    let names: Vec<_> = scan_result
                        .matches
                        .iter()
                        .map(|m| m.pattern_name.as_str())
                        .collect();
                    Some(format!("{} — {}", names.join(", "), action))
                } else {
                    None
                };

                match &action {
                    Action::Blocked => self.blocked_count += 1,
                    Action::Warned => self.warned_count += 1,
                    Action::Redacted { count } => self.caught_count += count,
                    Action::Passed => {}
                }

                self.traffic.push(TrafficEntry {
                    timestamp,
                    host,
                    method,
                    path,
                    action,
                    _match_count: match_count,
                    detail,
                });
            }
            ProxyEvent::AgentStarted { pid, command } => {
                self.pid = Some(pid);
                self.command = command;
            }
            ProxyEvent::AgentExited { .. } => {
                self.should_quit = true;
            }
            ProxyEvent::ProxyError { .. } => {}
        }
    }

    /// Cycle through scan modes and propagate to the shared proxy state.
    async fn cycle_mode(&mut self) {
        let new_mode = match self.display_mode {
            ScanMode::WarnOnly => ScanMode::Redact,
            ScanMode::Redact => ScanMode::Block,
            ScanMode::Block => ScanMode::WarnOnly,
        };
        self.display_mode = new_mode.clone();
        *self.mode.write().await = new_mode;
    }
}

/// Run the TUI dashboard, consuming events from the broadcast channel.
pub async fn run_dashboard(
    mut event_rx: broadcast::Receiver<ProxyEvent>,
    mode: Arc<RwLock<ScanMode>>,
    command: String,
) -> Result<(), TuiError> {
    enable_raw_mode().map_err(|e| TuiError::Terminal(e.to_string()))?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)
        .map_err(|e| TuiError::Terminal(e.to_string()))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| TuiError::Terminal(e.to_string()))?;

    let display_mode = mode.read().await.clone();
    let mut state = DashboardState::new(mode, display_mode, command);

    loop {
        // Draw
        terminal
            .draw(|f| draw_dashboard(f, &state))
            .map_err(|e| TuiError::Render(e.to_string()))?;

        // Handle events with 100ms tick
        tokio::select! {
            event = event_rx.recv() => {
                if let Ok(event) = event {
                    state.handle_event(event);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Tick — check for keyboard input
                if event::poll(Duration::from_millis(0)).unwrap_or(false) {
                    if let Ok(Event::Key(key)) = event::read() {
                        if key.kind == KeyEventKind::Press {
                            match key.code {
                                KeyCode::Char('q') => {
                                    state.should_quit = true;
                                }
                                KeyCode::Up => {
                                    state.scroll_offset =
                                        state.scroll_offset.saturating_sub(1);
                                }
                                KeyCode::Down => {
                                    if state.scroll_offset
                                        < state.traffic.len().saturating_sub(1)
                                    {
                                        state.scroll_offset += 1;
                                    }
                                }
                                KeyCode::Char('m') => {
                                    state.cycle_mode().await;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        if state.should_quit {
            break;
        }
    }

    // Cleanup
    disable_raw_mode().map_err(|e| TuiError::Terminal(e.to_string()))?;
    crossterm::execute!(std::io::stdout(), LeaveAlternateScreen)
        .map_err(|e| TuiError::Terminal(e.to_string()))?;

    Ok(())
}

fn draw_dashboard(f: &mut ratatui::Frame, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Traffic
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Header
    let elapsed = state.start_time.elapsed();
    let minutes = elapsed.as_secs() / 60;
    let seconds = elapsed.as_secs() % 60;

    let pid_str = state
        .pid
        .map(|p| format!("PID {p}"))
        .unwrap_or_else(|| "starting...".into());

    let header = Paragraph::new(Line::from(vec![
        Span::styled("Protecting: ", Style::default().fg(Color::White)),
        Span::styled(&state.command, Style::default().fg(Color::Cyan)),
        Span::raw(format!(" ({pid_str})")),
        Span::raw(" | "),
        Span::styled(
            format!("Mode: {}", state.display_mode),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format!(
            " | Session: {minutes}m {seconds:02}s | Requests: {} | Blocked: {}",
            state.total_requests, state.blocked_count
        )),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" leakwall "));
    f.render_widget(header, chunks[0]);

    // Traffic list
    let visible_start = state.scroll_offset;
    let items: Vec<ListItem> = state
        .traffic
        .iter()
        .skip(visible_start)
        .map(|entry| {
            let time = entry.timestamp.format("%H:%M:%S").to_string();
            let icon = match &entry.action {
                Action::Passed => "🟢",
                Action::Warned => "🟡",
                Action::Redacted { .. } => "🔴",
                Action::Blocked => "🔴",
            };

            let mut lines = vec![Line::from(vec![
                Span::raw(format!(" {time} {icon} ")),
                Span::styled(
                    format!("{} {}{}", entry.method, entry.host, entry.path),
                    Style::default().fg(Color::White),
                ),
                Span::raw("  "),
                action_span(&entry.action),
            ])];

            if let Some(ref detail) = entry.detail {
                lines.push(Line::from(vec![
                    Span::raw("          ↳ "),
                    Span::styled(detail, Style::default().fg(Color::Yellow)),
                ]));
            }

            ListItem::new(lines)
        })
        .collect();

    let traffic = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent Traffic "),
    );
    f.render_widget(traffic, chunks[1]);

    // Status bar
    let mb_scanned = state.total_bytes_scanned as f64 / (1024.0 * 1024.0);
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!("Caught: {} secrets", state.caught_count),
            Style::default().fg(Color::Red),
        ),
        Span::raw(format!(
            " | Warned: {} | Scanned: {mb_scanned:.1}MB",
            state.warned_count
        )),
    ]))
    .block(Block::default().borders(Borders::ALL))
    .style(Style::default());

    f.render_widget(status, chunks[2]);
}

fn action_span(action: &Action) -> Span<'static> {
    match action {
        Action::Passed => Span::styled("[OK]", Style::default().fg(Color::Green)),
        Action::Warned => Span::styled("[WARNED]", Style::default().fg(Color::Yellow)),
        Action::Redacted { count } => Span::styled(
            format!("[REDACTED {count}]"),
            Style::default().fg(Color::Red),
        ),
        Action::Blocked => Span::styled(
            "[BLOCKED]",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}

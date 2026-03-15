use crate::TuiError;
use chrono::{DateTime, Utc};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use leakwall_proxy::{Action, ProxyEvent};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

// ── Data model ──────────────────────────────────────────────────────────────

enum SessionStatus {
    Active,
    Exited(Option<i32>),
}

struct SessionStats {
    pid: u32,
    command: String,
    cwd: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    status: SessionStatus,
    total_requests: usize,
    total_bytes: usize,
    passed: usize,
    warned: usize,
    redacted_requests: usize,
    redacted_count: usize,
    blocked: usize,
    pattern_hits: HashMap<String, usize>,
}

impl SessionStats {
    fn new(pid: u32, command: String, cwd: Option<String>) -> Self {
        Self {
            pid,
            command,
            cwd,
            start_time: Some(Utc::now()),
            end_time: None,
            status: SessionStatus::Active,
            total_requests: 0,
            total_bytes: 0,
            passed: 0,
            warned: 0,
            redacted_requests: 0,
            redacted_count: 0,
            blocked: 0,
            pattern_hits: HashMap::new(),
        }
    }

    fn apply_request(
        &mut self,
        body_size: usize,
        action: &Action,
        matches: &[leakwall_secrets::scanner::SecretMatch],
    ) {
        self.total_requests += 1;
        self.total_bytes += body_size;
        for m in matches {
            *self.pattern_hits.entry(m.pattern_name.clone()).or_default() += 1;
        }
        match action {
            Action::Passed => self.passed += 1,
            Action::Warned => self.warned += 1,
            Action::Redacted { count } => {
                self.redacted_requests += 1;
                self.redacted_count += count;
            }
            Action::Blocked => self.blocked += 1,
        }
    }

    /// Short display label: tilde-prefixed cwd, or `<command>` fallback.
    fn display_label(&self) -> String {
        if let Some(ref cwd) = self.cwd {
            tilde_shorten(cwd)
        } else {
            format!("<{}>", first_word(&self.command))
        }
    }

    fn is_active(&self) -> bool {
        matches!(self.status, SessionStatus::Active)
    }

    fn status_str(&self) -> String {
        match &self.status {
            SessionStatus::Active => "ACTIVE".into(),
            SessionStatus::Exited(Some(code)) => format!("DONE ({code})"),
            SessionStatus::Exited(None) => "DONE".into(),
        }
    }

    fn elapsed_str(&self) -> String {
        let start = match self.start_time {
            Some(t) => t,
            None => return "?".into(),
        };
        let end = match self.end_time {
            Some(t) => t,
            None => Utc::now(),
        };
        let secs = (end - start).num_seconds().max(0) as u64;
        format!("{}m {:02}s", secs / 60, secs % 60)
    }
}

/// Replace $HOME prefix with `~`.
pub fn tilde_shorten(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.display().to_string();
        if path.starts_with(&home_str) {
            return format!("~{}", &path[home_str.len()..]);
        }
    }
    path.to_string()
}

fn first_word(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or(s)
}

const MAX_INACTIVE: usize = 10;

// ── View state ───────────────────────────────────────────────────────────────

enum MonitorView {
    SessionList,
    SessionDetail(u32),
}

struct MonitorState {
    session_order: Vec<u32>,
    sessions: HashMap<u32, SessionStats>,
    view: MonitorView,
    selected: usize,
    detail_scroll: usize,
    should_quit: bool,
}

impl MonitorState {
    fn new() -> Self {
        Self {
            session_order: Vec::new(),
            sessions: HashMap::new(),
            view: MonitorView::SessionList,
            selected: 0,
            detail_scroll: 0,
            should_quit: false,
        }
    }

    fn apply(&mut self, event: ProxyEvent) {
        match event {
            ProxyEvent::AgentStarted { pid, command, cwd } => {
                if !self.sessions.contains_key(&pid) {
                    self.session_order.push(pid);
                }
                self.sessions
                    .insert(pid, SessionStats::new(pid, command, cwd));
            }
            ProxyEvent::AgentExited { pid, exit_code } => {
                if let Some(s) = self.sessions.get_mut(&pid) {
                    s.status = SessionStatus::Exited(exit_code);
                    s.end_time = Some(Utc::now());
                }
                // Evict oldest inactive sessions beyond the cap.
                let mut inactive: Vec<u32> = self
                    .session_order
                    .iter()
                    .copied()
                    .filter(|p| self.sessions.get(p).is_some_and(|s| !s.is_active()))
                    .collect();
                if inactive.len() > MAX_INACTIVE {
                    inactive
                        .sort_by(|a, b| self.sessions[a].end_time.cmp(&self.sessions[b].end_time));
                    for &evict in inactive.iter().take(inactive.len() - MAX_INACTIVE) {
                        self.sessions.remove(&evict);
                        self.session_order.retain(|&p| p != evict);
                    }
                    // Clamp cursor after eviction.
                    let max = self.display_order().len().saturating_sub(1);
                    self.selected = self.selected.min(max);
                }
            }
            ProxyEvent::RequestIntercepted {
                body_size,
                scan_result,
                action,
                ..
            } => {
                // Attribute to the last active session.
                if let Some(&pid) = self
                    .session_order
                    .iter()
                    .rev()
                    .find(|&&p| self.sessions.get(&p).is_some_and(|s| s.is_active()))
                {
                    if let Some(s) = self.sessions.get_mut(&pid) {
                        s.apply_request(body_size, &action, &scan_result.matches);
                    }
                }
            }
            ProxyEvent::ProxyError { .. } => {}
        }
    }

    fn active_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_active()).count()
    }

    /// Display order: active sessions (newest start first), then up to
    /// MAX_INACTIVE inactive sessions (most recently ended first).
    fn display_order(&self) -> Vec<u32> {
        let mut active: Vec<u32> = self
            .session_order
            .iter()
            .copied()
            .filter(|pid| self.sessions.get(pid).is_some_and(|s| s.is_active()))
            .collect();
        let mut inactive: Vec<u32> = self
            .session_order
            .iter()
            .copied()
            .filter(|pid| self.sessions.get(pid).is_some_and(|s| !s.is_active()))
            .collect();

        active.sort_by(|a, b| {
            self.sessions[b]
                .start_time
                .cmp(&self.sessions[a].start_time)
        });
        inactive.sort_by(|a, b| self.sessions[b].end_time.cmp(&self.sessions[a].end_time));
        inactive.truncate(MAX_INACTIVE);

        active.extend(inactive);
        active
    }

    fn selected_pid(&self) -> Option<u32> {
        self.display_order().get(self.selected).copied()
    }
}

// ── Log tailing ──────────────────────────────────────────────────────────────

async fn tail_log(log_path: PathBuf, tx: mpsc::Sender<ProxyEvent>) {
    // Wait for file to exist
    loop {
        if log_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let file = match tokio::fs::File::open(&log_path).await {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut lines = tokio::io::BufReader::new(file).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if let Ok(event) = serde_json::from_str::<ProxyEvent>(&line) {
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
                // malformed lines are silently skipped
            }
            Ok(None) => {
                // EOF — wait and retry
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// ── TUI rendering ────────────────────────────────────────────────────────────

fn draw(f: &mut ratatui::Frame, state: &MonitorState) {
    match state.view {
        MonitorView::SessionList => draw_session_list(f, state),
        MonitorView::SessionDetail(pid) => {
            if let Some(session) = state.sessions.get(&pid) {
                draw_session_detail(f, session);
            }
        }
    }
}

fn draw_session_list(f: &mut ratatui::Frame, state: &MonitorState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(f.area());

    let total = state.session_order.len();
    let active = state.active_count();
    let header = Paragraph::new(format!("{total} sessions ({active} active)")).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" leakwall monitor "),
    );
    f.render_widget(header, chunks[0]);

    let order = state.display_order();
    let items: Vec<ListItem> = order
        .iter()
        .enumerate()
        .map(|(i, &pid)| {
            let s = &state.sessions[&pid];
            let cursor = if i == state.selected { "> " } else { "  " };
            let status_str = s.status_str();
            let label = s.display_label();
            let line = Line::from(vec![
                Span::raw(format!("{cursor}{label:<30}")),
                if s.is_active() {
                    Span::styled(format!("[{status_str}]"), Style::default().fg(Color::Green))
                } else {
                    Span::styled(
                        format!("[{status_str}]"),
                        Style::default().fg(Color::DarkGray),
                    )
                },
                Span::raw(format!(
                    "  {:>4} req  {:>2} redc",
                    s.total_requests, s.redacted_requests
                )),
            ]);
            let item = ListItem::new(line);
            if i == state.selected {
                item.style(Style::default().add_modifier(Modifier::BOLD))
            } else {
                item
            }
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(" Sessions "));
    f.render_widget(list, chunks[1]);

    let footer = Paragraph::new("  ↑↓ navigate  Enter: detail  q: quit")
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn draw_session_detail(f: &mut ratatui::Frame, s: &SessionStats) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(f.area());

    let status_str = s.status_str();
    let title = s.display_label();
    let header_text = format!(
        "  PID {} • {} • {} • {}",
        s.pid,
        first_word(&s.command),
        status_str,
        s.elapsed_str()
    );
    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {title} ")),
    );
    f.render_widget(header, chunks[0]);

    let mb = s.total_bytes as f64 / (1024.0 * 1024.0);
    let stats_text = vec![
        Line::from(format!(
            "  Requests: {:<8}  Bytes: {:.1} MB",
            s.total_requests, mb
        )),
        Line::from(format!(
            "  Passed:   {:<8}  Warned:  {}",
            s.passed, s.warned
        )),
        Line::from(format!(
            "  Redacted: {} ({}){}Blocked: {}",
            s.redacted_requests, s.redacted_count, "  ", s.blocked
        )),
    ];
    let stats =
        Paragraph::new(stats_text).block(Block::default().borders(Borders::ALL).title(" Stats "));
    f.render_widget(stats, chunks[1]);

    // Pattern hits sorted by count desc
    let mut hits: Vec<(&String, usize)> = s.pattern_hits.iter().map(|(k, &v)| (k, v)).collect();
    hits.sort_by(|a, b| b.1.cmp(&a.1));

    let max_hits = hits.first().map(|(_, n)| *n).unwrap_or(1).max(1);
    let bar_width = 10usize;

    let items: Vec<ListItem> = hits
        .iter()
        .map(|(name, count)| {
            let filled = (count * bar_width / max_hits).min(bar_width);
            let bar = format!("{}{}", "█".repeat(filled), " ".repeat(bar_width - filled));
            ListItem::new(Line::from(format!("  {name:<25} {bar}  {count} hits")))
        })
        .collect();

    let pattern_list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Top patterns detected "),
    );
    f.render_widget(pattern_list, chunks[2]);

    let footer = Paragraph::new("  Esc: back  ↑↓ scroll  q: quit")
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[3]);
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Run the monitor TUI, tailing `log_path` in real time.
pub async fn run_monitor(log_path: PathBuf) -> Result<(), TuiError> {
    let (tx, mut rx) = mpsc::channel::<ProxyEvent>(1024);

    let log_path_clone = log_path.clone();
    tokio::spawn(async move {
        tail_log(log_path_clone, tx).await;
    });

    enable_raw_mode().map_err(|e| TuiError::Terminal(e.to_string()))?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)
        .map_err(|e| TuiError::Terminal(e.to_string()))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| TuiError::Terminal(e.to_string()))?;

    let mut state = MonitorState::new();

    loop {
        terminal
            .draw(|f| draw(f, &state))
            .map_err(|e| TuiError::Render(e.to_string()))?;

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Drain incoming events
                while let Ok(ev) = rx.try_recv() {
                    state.apply(ev);
                }
                // Handle keyboard
                if event::poll(Duration::from_millis(0)).unwrap_or(false) {
                    if let Ok(Event::Key(key)) = event::read() {
                        if key.kind == KeyEventKind::Press {
                            match &state.view {
                                MonitorView::SessionList => match key.code {
                                    KeyCode::Char('q') => state.should_quit = true,
                                    KeyCode::Up => {
                                        state.selected = state.selected.saturating_sub(1);
                                    }
                                    KeyCode::Down => {
                                        let max =
                                            state.display_order().len().saturating_sub(1);
                                        if state.selected < max {
                                            state.selected += 1;
                                        }
                                    }
                                    KeyCode::Enter => {
                                        if let Some(pid) = state.selected_pid() {
                                            state.view = MonitorView::SessionDetail(pid);
                                            state.detail_scroll = 0;
                                        }
                                    }
                                    _ => {}
                                },
                                MonitorView::SessionDetail(_) => match key.code {
                                    KeyCode::Char('q') => state.should_quit = true,
                                    KeyCode::Esc | KeyCode::Left => {
                                        state.view = MonitorView::SessionList;
                                    }
                                    KeyCode::Up => {
                                        state.detail_scroll = state.detail_scroll.saturating_sub(1);
                                    }
                                    KeyCode::Down => {
                                        state.detail_scroll += 1;
                                    }
                                    _ => {}
                                },
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

    disable_raw_mode().map_err(|e| TuiError::Terminal(e.to_string()))?;
    crossterm::execute!(std::io::stdout(), LeaveAlternateScreen)
        .map_err(|e| TuiError::Terminal(e.to_string()))?;

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use leakwall_proxy::Action;

    fn make_scan_result(patterns: &[&str]) -> leakwall_secrets::scanner::ScanResult {
        use leakwall_secrets::scanner::{MatchSource, ScanResult, SecretMatch};
        use leakwall_secrets::Severity;
        use std::time::Duration;
        ScanResult {
            matches: patterns
                .iter()
                .map(|&name| SecretMatch {
                    pattern_name: name.to_string(),
                    matched_text_preview: "REDACTED".to_string(),
                    byte_offset: 0,
                    match_length: 7,
                    source: MatchSource::Pattern,
                    severity: Severity::High,
                })
                .collect(),
            scan_duration: Duration::ZERO,
            body_size: 0,
        }
    }

    #[test]
    fn agent_started_deserializes_without_cwd() {
        let json = r#"{"AgentStarted":{"pid":123,"command":"claude"}}"#;
        let event: ProxyEvent = serde_json::from_str(json).unwrap();
        match event {
            ProxyEvent::AgentStarted { pid, cwd, .. } => {
                assert_eq!(pid, 123);
                assert!(cwd.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn agent_started_deserializes_with_cwd() {
        let json = r#"{"AgentStarted":{"pid":456,"command":"claude","cwd":"/home/user/project"}}"#;
        let event: ProxyEvent = serde_json::from_str(json).unwrap();
        match event {
            ProxyEvent::AgentStarted { pid, cwd, .. } => {
                assert_eq!(pid, 456);
                assert_eq!(cwd.as_deref(), Some("/home/user/project"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn session_stats_apply_request() {
        let mut s = SessionStats::new(1, "claude".into(), None);
        let result = make_scan_result(&["aws_key"]);
        s.apply_request(1024, &Action::Redacted { count: 2 }, &result.matches);
        assert_eq!(s.total_requests, 1);
        assert_eq!(s.total_bytes, 1024);
        assert_eq!(s.redacted_requests, 1);
        assert_eq!(s.redacted_count, 2);
        assert_eq!(s.pattern_hits["aws_key"], 1);
    }

    #[test]
    fn monitor_state_session_lifecycle() {
        let mut state = MonitorState::new();
        state.apply(ProxyEvent::AgentStarted {
            pid: 10,
            command: "claude".into(),
            cwd: None,
        });
        assert!(state.sessions[&10].is_active());
        assert_eq!(state.active_count(), 1);

        state.apply(ProxyEvent::AgentExited {
            pid: 10,
            exit_code: Some(0),
        });
        assert!(!state.sessions[&10].is_active());
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn display_label_fallback_without_cwd() {
        let s = SessionStats::new(1, "claude --some-flag".into(), None);
        assert_eq!(s.display_label(), "<claude>");
    }

    #[test]
    fn tilde_shorten_replaces_home() {
        if let Some(home) = dirs::home_dir() {
            let path = format!("{}/Documents/project", home.display());
            let short = tilde_shorten(&path);
            assert!(short.starts_with('~'));
            assert!(!short.starts_with(&home.display().to_string()));
        }
    }
}

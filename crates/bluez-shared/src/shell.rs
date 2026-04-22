// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! Interactive shell framework — Rust rewrite of `src/shared/shell.c` / `shell.h`.
//!
//! This module provides the `bt_shell` command-line framework used by
//! `bluetoothctl` and other BlueZ CLI tools.  It replaces GNU `readline` with
//! [`rustyline`] as specified in AAP Section 0.4.1.
//!
//! # Architecture
//!
//! The shell maintains a global [`BtShell`] state (behind a `Mutex`) that tracks:
//! - The current and main menus ([`BtShellMenu`])
//! - Registered submenus
//! - An environment store for arbitrary key-value pairs
//! - A rustyline [`Editor`] instance for interactive line editing
//! - A queue of pending command lines for non-interactive / script execution
//! - A stack of deferred prompt-input requests
//!
//! The lifecycle is: [`bt_shell_init`] → [`bt_shell_run`] → [`bt_shell_cleanup`].

use crate::log::{bt_log_close, bt_log_open, bt_log_printf, bt_log_vprintf};
use crate::util::{hexdump, strdelimit, stris_utf8, strsuffix};

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::RawFd;
use std::sync::Mutex;
use std::time::Duration;

use rustyline::completion::Completer;
use rustyline::config::Config;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{Context, Editor, Helper};

// ---------------------------------------------------------------------------
// ANSI color constants — identical to C shell.h defines
// ---------------------------------------------------------------------------

/// Reset all attributes.
pub const COLOR_OFF: &str = "\x1B[0m";
/// Bright red text.
pub const COLOR_RED: &str = "\x1B[0;91m";
/// Bright green text.
pub const COLOR_GREEN: &str = "\x1B[0;92m";
/// Bright yellow text.
pub const COLOR_YELLOW: &str = "\x1B[0;93m";
/// Bright blue text.
pub const COLOR_BLUE: &str = "\x1B[0;94m";
/// Bold gray text.
pub const COLOR_BOLDGRAY: &str = "\x1B[1;30m";
/// Bold white text.
pub const COLOR_BOLDWHITE: &str = "\x1B[1;37m";
/// Bold default (highlight) text.
pub const COLOR_HIGHLIGHT: &str = "\x1B[1;39m";

// ---------------------------------------------------------------------------
// Version constant — equivalent to C VERSION macro
// ---------------------------------------------------------------------------

/// BlueZ version string used by the `version` built-in command.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Column width used to align command/argument help text.
const CMD_LENGTH: usize = 48;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during shell operations.
#[derive(Debug)]
pub enum ShellError {
    /// The command string contained invalid characters.
    BadMessage,
    /// The command string had invalid syntax.
    InvalidArgument,
    /// Memory allocation failure.
    NoMemory,
    /// No executable command was found in the input.
    NoExec,
    /// The requested command was not found in the current menu.
    NotFound,
    /// An I/O error occurred.
    Io(io::Error),
    /// A readline error occurred.
    Readline(ReadlineError),
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::BadMessage => write!(f, "Bad message"),
            ShellError::InvalidArgument => write!(f, "Invalid argument"),
            ShellError::NoMemory => write!(f, "Out of memory"),
            ShellError::NoExec => write!(f, "No exec"),
            ShellError::NotFound => write!(f, "Not found"),
            ShellError::Io(e) => write!(f, "I/O error: {e}"),
            ShellError::Readline(e) => write!(f, "Readline error: {e}"),
        }
    }
}

impl std::error::Error for ShellError {}

impl From<io::Error> for ShellError {
    fn from(e: io::Error) -> Self {
        ShellError::Io(e)
    }
}

impl From<ReadlineError> for ShellError {
    fn from(e: ReadlineError) -> Self {
        ShellError::Readline(e)
    }
}

// ---------------------------------------------------------------------------
// Menu structures
// ---------------------------------------------------------------------------

/// A single command entry in a shell menu.
///
/// Replaces C `struct bt_shell_menu_entry`.
pub struct BtShellMenuEntry {
    /// Command name token (e.g. `"scan"`).
    pub cmd: &'static str,
    /// Argument synopsis for help text (e.g. `"<address>"`).
    pub arg: Option<&'static str>,
    /// Command execution callback.  Receives the tokenized arguments
    /// (argv\[0\] is the command name itself).
    pub func: fn(args: &[&str]),
    /// Human-readable description for help output.
    pub desc: &'static str,
    /// Optional tab-completion generator.  Called with the partial text
    /// and a state counter (0 on first call, incremented for each successive
    /// match).  Return `None` when no more completions are available.
    pub r#gen: Option<fn(text: &str, state: i32) -> Option<String>>,
    /// Optional display hook for completion matches.
    pub disp: Option<fn(matches: &[String], max_length: usize)>,
    /// Optional predicate that controls whether this command is visible /
    /// executable in the given menu context.
    pub exists: Option<fn(menu: &BtShellMenu) -> bool>,
}

/// A named menu containing a table of [`BtShellMenuEntry`] commands.
///
/// Replaces C `struct bt_shell_menu`.
pub struct BtShellMenu {
    /// Menu name (e.g. `"main"`, `"advertise"`).
    pub name: &'static str,
    /// Optional description shown in submenu listings.
    pub desc: Option<&'static str>,
    /// Hook executed before the menu runs (for lazy initialization).
    pub pre_run: Option<fn(menu: &BtShellMenu)>,
    /// Command table — terminated by a sentinel entry where `cmd` is empty.
    pub entries: &'static [BtShellMenuEntry],
}

/// Wrapper for command-line option definitions passed to [`bt_shell_init`].
///
/// Replaces C `struct bt_shell_opt`.
pub struct BtShellOpt {
    /// Long option definitions: `(name, has_arg, description)`.
    pub options: Vec<ShellOption>,
    /// Short option string (e.g. `"d:p:"`).
    pub optstr: String,
}

/// A single long-option definition.
pub struct ShellOption {
    /// Long option name (without `--` prefix).
    pub name: String,
    /// Whether this option takes an argument.
    pub has_arg: bool,
    /// Human-readable help text.
    pub description: String,
    /// Short option character.
    pub short: char,
}

// ---------------------------------------------------------------------------
// Prompt input callback
// ---------------------------------------------------------------------------

/// Callback invoked when the user responds to a temporary prompt.
///
/// Replaces C `bt_shell_prompt_input_func`.
pub type PromptInputFunc = Box<dyn FnOnce(&str) + Send>;

/// Internal prompt-input request queued when a prompt is already active.
struct PromptRequest {
    /// The prompt string displayed to the user.
    label: String,
    /// The callback invoked with the user's response.
    func: PromptInputFunc,
}

// ---------------------------------------------------------------------------
// Rustyline helper (tab completion, hinting, highlighting, validation)
// ---------------------------------------------------------------------------

/// Rustyline [`Helper`] implementation for the BlueZ shell.
///
/// Provides tab completion against the current and default menus, registered
/// submenus, and submenu dot-notation commands.  Hinting, highlighting, and
/// validation are pass-through (matching original readline behavior).
pub struct ShellHelper {
    /// Snapshot of all command names for completion.
    commands: Vec<String>,
}

impl ShellHelper {
    /// Create a new helper with an empty command list.
    fn new() -> Self {
        ShellHelper { commands: Vec::new() }
    }

    /// Rebuild the command list from pre-collected command names.
    fn set_commands(&mut self, commands: Vec<String>) {
        self.commands = commands;
    }
}

/// Collect command names from the current shell state (for tab completion).
fn collect_shell_commands(state: &ShellState) -> Vec<String> {
    let mut commands = Vec::new();

    // Add default menu commands.
    for entry in default_menu_entries() {
        if let Some(exists_fn) = entry.exists {
            if let Some(menu) = state.current_menu {
                if !exists_fn(menu) {
                    continue;
                }
            }
        }
        if !entry.cmd.is_empty() {
            commands.push(entry.cmd.to_string());
        }
    }

    // Add current menu commands.
    if let Some(menu) = state.current_menu {
        for entry in menu.entries {
            if entry.cmd.is_empty() {
                break;
            }
            if let Some(exists_fn) = entry.exists {
                if !exists_fn(menu) {
                    continue;
                }
            }
            commands.push(entry.cmd.to_string());
        }
    }

    // Add submenu names (with dot prefix for dot-notation).
    for submenu in &state.submenus {
        commands.push(submenu.name.to_string());
        for entry in submenu.entries {
            if entry.cmd.is_empty() {
                break;
            }
            commands.push(format!("{}.{}", submenu.name, entry.cmd));
        }
    }

    commands
}

impl Completer for ShellHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<String>), ReadlineError> {
        // Find word start.
        let start = line[..pos].rfind(' ').map_or(0, |i| i + 1);
        let partial = &line[start..pos];

        let matches: Vec<String> =
            self.commands.iter().filter(|cmd| cmd.starts_with(partial)).cloned().collect();

        Ok((start, matches))
    }
}

impl Hinter for ShellHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        // No hints — matches original readline behavior.
        None
    }
}

impl Highlighter for ShellHelper {}

impl Validator for ShellHelper {
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None))
    }
}

impl Helper for ShellHelper {}

// ---------------------------------------------------------------------------
// Shell internal state
// ---------------------------------------------------------------------------

/// The interactive/non-interactive mode distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellMode {
    Interactive,
    NonInteractive,
}

/// Internal mutable shell state.  Replaces the C `static struct { ... } data`.
struct ShellState {
    /// Whether bt_shell_init has been called.
    init: bool,
    /// Program name (basename of argv[0]).
    name: String,
    /// History file path.
    history_path: String,
    /// Remaining positional arguments (non-option args from argv).
    args: Vec<String>,
    /// Current operating mode.
    mode: ShellMode,
    /// Zsh completion mode flag.
    zsh: bool,
    /// Monitor logging flag.
    monitor: bool,
    /// Timeout in seconds for non-interactive mode (0 = no timeout).
    timeout_secs: i32,
    /// File descriptor for init script, or -1 if none.
    init_fd: RawFd,
    /// Currently executing command line (prevents re-entrant exec).
    line: Option<String>,
    /// Queue of pending command lines.
    queue: VecDeque<String>,
    /// Whether a prompt-input is currently saved/active.
    saved_prompt: bool,
    /// The saved prompt-input callback.
    saved_func: Option<PromptInputFunc>,
    /// Queue of deferred prompt-input requests.
    prompts: VecDeque<PromptRequest>,
    /// Main (root) menu reference.
    main_menu: Option<&'static BtShellMenu>,
    /// Currently active menu.
    current_menu: Option<&'static BtShellMenu>,
    /// Registered submenus.
    submenus: Vec<&'static BtShellMenu>,
    /// Currently executing menu entry (for bt_shell_usage).
    exec_entry: Option<&'static BtShellMenuEntry>,
    /// Environment store (name → boxed value).
    env: HashMap<String, Box<dyn Any + Send>>,
    /// Rustyline editor instance.
    editor: Option<Editor<ShellHelper, DefaultHistory>>,
    /// Exit status requested by bt_shell_quit.
    exit_status: Option<i32>,
    /// Whether the shell has been terminated (for signal idempotency).
    terminated: bool,
    /// Attached input readers (for script files).
    attached_inputs: Vec<AttachedInput>,
}

/// An attached input source (file descriptor / buffered reader).
struct AttachedInput {
    fd: RawFd,
    reader: Option<BufReader<File>>,
}

impl ShellState {
    /// Create a new, uninitialized shell state.
    fn new() -> Self {
        ShellState {
            init: false,
            name: String::new(),
            history_path: String::new(),
            args: Vec::new(),
            mode: ShellMode::Interactive,
            zsh: false,
            monitor: false,
            timeout_secs: 0,
            init_fd: -1,
            line: None,
            queue: VecDeque::new(),
            saved_prompt: false,
            saved_func: None,
            prompts: VecDeque::new(),
            main_menu: None,
            current_menu: None,
            submenus: Vec::new(),
            exec_entry: None,
            env: HashMap::new(),
            editor: None,
            exit_status: None,
            terminated: false,
            attached_inputs: Vec::new(),
        }
    }
}

/// Process-wide shell state, protected by a mutex.
static SHELL: Mutex<Option<ShellState>> = Mutex::new(None);

/// Execute a closure with exclusive access to the global shell state.
/// Creates the state on first access.
fn with_shell<F, T>(f: F) -> T
where
    F: FnOnce(&mut ShellState) -> T,
{
    let mut guard = SHELL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(ShellState::new());
    }
    f(guard.as_mut().expect("shell state initialized above"))
}

// ---------------------------------------------------------------------------
// Public BtShell facade — exposes internal state for cross-crate access
// ---------------------------------------------------------------------------

/// Public shell state facade.
///
/// This struct is returned by snapshot functions and provides read access to
/// the shell's configuration.  Most mutation happens through the free-function
/// API (`bt_shell_*`).
pub struct BtShell {
    /// Program name.
    pub name: String,
    /// Whether the shell is in interactive mode.
    pub interactive: bool,
    /// Whether zsh completion mode is active.
    pub zsh_complete: bool,
    /// Whether monitor logging is enabled.
    pub monitor: bool,
    /// Configured timeout for non-interactive mode.
    pub timeout: Option<Duration>,
    /// Reference to the main (root) menu.
    pub main_menu: Option<&'static BtShellMenu>,
    /// Reference to the currently active menu.
    pub current_menu: Option<&'static BtShellMenu>,
    /// Registered submenus.
    pub submenus: Vec<&'static BtShellMenu>,
    /// Environment key-value store.
    pub env: HashMap<String, Box<dyn Any + Send>>,
    /// Rustyline editor instance.
    pub editor: Option<Editor<ShellHelper, DefaultHistory>>,
    /// Queue of pending command lines.
    pub pending_lines: VecDeque<String>,
    /// Stack of deferred prompt-input requests.
    pub prompt_stack: Vec<(String, PromptInputFunc)>,
}

// ---------------------------------------------------------------------------
// Default (built-in) menu commands
// ---------------------------------------------------------------------------

/// Return the built-in default menu entries.
fn default_menu_entries() -> &'static [BtShellMenuEntry] {
    static ENTRIES: &[BtShellMenuEntry] = &[
        BtShellMenuEntry {
            cmd: "back",
            arg: None,
            func: cmd_back,
            desc: "Return to main menu",
            r#gen: None,
            disp: None,
            exists: Some(cmd_back_exists),
        },
        BtShellMenuEntry {
            cmd: "menu",
            arg: Some("<name>"),
            func: cmd_menu,
            desc: "Select submenu",
            r#gen: Some(menu_generator),
            disp: None,
            exists: Some(cmd_menu_exists),
        },
        BtShellMenuEntry {
            cmd: "version",
            arg: None,
            func: cmd_version,
            desc: "Display version",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "quit",
            arg: None,
            func: cmd_quit,
            desc: "Quit program",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "exit",
            arg: None,
            func: cmd_quit,
            desc: "Quit program",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "help",
            arg: None,
            func: cmd_help,
            desc: "Display help about this program",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "export",
            arg: None,
            func: cmd_export,
            desc: "Print environment variables",
            r#gen: None,
            disp: None,
            exists: None,
        },
        BtShellMenuEntry {
            cmd: "script",
            arg: Some("<filename>"),
            func: cmd_script,
            desc: "Run script",
            r#gen: None,
            disp: None,
            exists: None,
        },
    ];
    ENTRIES
}

// Built-in command implementations

fn cmd_version(args: &[&str]) {
    let _ = args;
    bt_shell_printf(format_args!("Version {}\n", VERSION));
    bt_shell_noninteractive_quit(0);
}

fn cmd_quit(_args: &[&str]) {
    with_shell(|state| {
        state.exit_status = Some(0);
    });
}

fn cmd_help(args: &[&str]) {
    let _ = args;
    shell_print_menu_impl();
    bt_shell_noninteractive_quit(0);
}

fn cmd_back(_args: &[&str]) {
    with_shell(|state| {
        if state.current_menu.map(|m| m.name) == state.main_menu.map(|m| m.name) {
            print_output("Already on main menu\n");
            return;
        }
        state.current_menu = state.main_menu;
    });
    shell_print_menu_impl();
}

fn cmd_back_exists(menu: &BtShellMenu) -> bool {
    with_shell(|state| state.main_menu.map(|m| m.name) != Some(menu.name))
}

fn cmd_menu(args: &[&str]) {
    if args.len() < 2 || args[1].is_empty() {
        bt_shell_printf(format_args!("Missing name argument\n"));
        bt_shell_noninteractive_quit(1);
        return;
    }
    let name = args[1];
    let found = with_shell(|state| {
        if let Some(menu) = find_menu_in_submenus(&state.submenus, name, name.len()) {
            state.current_menu = Some(menu);
            true
        } else {
            false
        }
    });
    if !found {
        bt_shell_printf(format_args!("Unable find menu with name: {}\n", name));
        bt_shell_noninteractive_quit(1);
        return;
    }
    shell_print_menu_impl();
    bt_shell_noninteractive_quit(0);
}

fn cmd_menu_exists(menu: &BtShellMenu) -> bool {
    with_shell(|state| {
        if state.main_menu.map(|m| m.name) != Some(menu.name) || state.submenus.is_empty() {
            return false;
        }
        true
    })
}

fn cmd_export(_args: &[&str]) {
    with_shell(|state| {
        for name in state.env.keys() {
            print_output(&format!("{COLOR_HIGHLIGHT}{name}=<value>{COLOR_OFF}\n"));
        }
    });
}

fn cmd_script(args: &[&str]) {
    if args.len() < 2 {
        print_output("Missing filename argument\n");
        bt_shell_noninteractive_quit(1);
        return;
    }
    let filename = args[1];
    match File::open(filename) {
        Ok(file) => {
            print_output(&format!("Running script {}...\n", filename));
            execute_script_file(file);
            bt_shell_noninteractive_quit(0);
        }
        Err(e) => {
            print_output(&format!(
                "Unable to open {}: {} ({})\n",
                filename,
                e,
                e.raw_os_error().unwrap_or(0)
            ));
            bt_shell_noninteractive_quit(1);
        }
    }
}

/// Menu generator for tab completion of menu names.
fn menu_generator(text: &str, state: i32) -> Option<String> {
    with_shell(|shell_state| {
        let mut index = 0;
        for submenu in &shell_state.submenus {
            if index < state {
                index += 1;
                continue;
            }
            if submenu.name.starts_with(text) {
                return Some(submenu.name.to_string());
            }
            index += 1;
        }
        None
    })
}

// ---------------------------------------------------------------------------
// Menu searching and command dispatch
// ---------------------------------------------------------------------------

/// Find a submenu by name prefix among the registered submenus.
fn find_menu_in_submenus(
    submenus: &[&'static BtShellMenu],
    name: &str,
    max_len: usize,
) -> Option<&'static BtShellMenu> {
    let search = if name.len() > max_len { &name[..max_len] } else { name };
    submenus
        .iter()
        .find(|submenu| submenu.name.starts_with(search) || submenu.name == search)
        .copied()
}

/// Find and execute a command in a menu's entry table.
fn menu_exec(
    menu_entries: &'static [BtShellMenuEntry],
    menu: &'static BtShellMenu,
    args: &[&str],
    state: &mut ShellState,
) -> Result<(), ShellError> {
    if args.is_empty() {
        return Err(ShellError::InvalidArgument);
    }
    for entry in menu_entries {
        if entry.cmd.is_empty() {
            break;
        }
        if entry.cmd != args[0] {
            continue;
        }
        if let Some(exists_fn) = entry.exists {
            if !exists_fn(menu) {
                continue;
            }
        }
        if state.mode == ShellMode::NonInteractive {
            if let Some(pre_run) = menu.pre_run {
                pre_run(menu);
            }
        }
        return cmd_exec(entry, args, state);
    }
    Err(ShellError::NotFound)
}

/// Validate argument counts and execute a command entry.
fn cmd_exec(
    entry: &'static BtShellMenuEntry,
    args: &[&str],
    state: &mut ShellState,
) -> Result<(), ShellError> {
    if args.len() == 2 && (args[1] == "help" || args[1] == "--help") {
        print_output(&format!("{}\n", entry.desc));
        print_output(&format!("{COLOR_HIGHLIGHT}Usage:{COLOR_OFF}\n"));
        print_output(&format!("\t {} {}\n", entry.cmd, entry.arg.unwrap_or("")));
        return Ok(());
    }
    if let Some(arg_spec) = entry.arg {
        if !arg_spec.is_empty() {
            let (mandatory, optional, has_varargs) = parse_arg_spec(arg_spec);
            let provided = args.len() - 1;
            if provided < mandatory {
                print_output(&format!(
                    "{COLOR_HIGHLIGHT}Missing argument (expected at least {mandatory}, got {provided}){COLOR_OFF}\n"
                ));
                return Err(ShellError::InvalidArgument);
            }
            if !has_varargs && provided > mandatory + optional {
                print_output(&format!(
                    "{COLOR_HIGHLIGHT}Too many arguments: {provided} > {}{COLOR_OFF}\n",
                    mandatory + optional
                ));
                return Err(ShellError::InvalidArgument);
            }
        }
    } else if args.len() > 1 {
        print_output(&format!("{COLOR_HIGHLIGHT}Too many arguments{COLOR_OFF}\n"));
        return Err(ShellError::InvalidArgument);
    }
    state.exec_entry = Some(entry);
    (entry.func)(args);
    state.exec_entry = None;
    Ok(())
}

/// Parse an argument specification string into (mandatory, optional, varargs).
///
/// The `...` varargs indicator may appear inside brackets (e.g. `[options...]`)
/// or at the end of the spec (e.g. `<data>...`).  We detect it using
/// `strsuffix` for the trailing case and `contains` for the bracketed case.
fn parse_arg_spec(spec: &str) -> (usize, usize, bool) {
    let mut mandatory = 0;
    let mut optional = 0;
    // Check both patterns: trailing "..." and "...]" (varargs inside brackets).
    let has_varargs = strsuffix(spec, "...") || spec.contains("...");
    let mut in_angle = false;
    let mut in_bracket = false;
    for ch in spec.chars() {
        match ch {
            '<' => in_angle = true,
            '>' if in_angle => {
                mandatory += 1;
                in_angle = false;
            }
            '[' => in_bracket = true,
            ']' if in_bracket => {
                optional += 1;
                in_bracket = false;
            }
            _ => {}
        }
    }
    (mandatory, optional, has_varargs)
}

/// Dispatch a command through default menu, current menu, and submenu routing.
fn shell_exec_dispatch(args: &[&str], state: &mut ShellState) -> Result<(), ShellError> {
    if args.is_empty() || args[0].is_empty() {
        return Err(ShellError::InvalidArgument);
    }
    for arg in args {
        if !stris_utf8(arg.as_bytes()) {
            return Err(ShellError::InvalidArgument);
        }
    }
    let current_menu = state.current_menu;
    if let Some(cur) = current_menu {
        let default_entries = default_menu_entries();
        let result = menu_exec_default(default_entries, cur, args, state);
        if !matches!(result, Err(ShellError::NotFound)) {
            return result;
        }
        let result = menu_exec(cur.entries, cur, args, state);
        if !matches!(result, Err(ShellError::NotFound)) {
            return result;
        }
        let is_main = state.main_menu.map(|m| m.name) == Some(cur.name);
        if is_main {
            if let Some(dot_pos) = args[0].find('.') {
                let submenu_name = &args[0][..dot_pos];
                let cmd_name = &args[0][dot_pos + 1..];
                if let Some(submenu) =
                    find_menu_in_submenus(&state.submenus, submenu_name, submenu_name.len())
                {
                    let mut new_args: Vec<&str> = Vec::with_capacity(args.len());
                    new_args.push(cmd_name);
                    new_args.extend_from_slice(&args[1..]);
                    return menu_exec(submenu.entries, submenu, &new_args, state);
                }
            }
        }
        print_output(&format!(
            "{COLOR_HIGHLIGHT}Invalid command in menu {}: {}{COLOR_OFF}\n",
            cur.name, args[0]
        ));
        shell_print_help();
        return Err(ShellError::NotFound);
    }
    Err(ShellError::InvalidArgument)
}

/// Execute a command against the default menu entries.
fn menu_exec_default(
    entries: &'static [BtShellMenuEntry],
    menu: &'static BtShellMenu,
    args: &[&str],
    state: &mut ShellState,
) -> Result<(), ShellError> {
    if args.is_empty() {
        return Err(ShellError::InvalidArgument);
    }
    for entry in entries {
        if entry.cmd.is_empty() {
            break;
        }
        if entry.cmd != args[0] {
            continue;
        }
        if let Some(exists_fn) = entry.exists {
            if !exists_fn(menu) {
                continue;
            }
        }
        if state.mode == ShellMode::NonInteractive {
            if let Some(pre_run) = menu.pre_run {
                pre_run(menu);
            }
        }
        return cmd_exec(entry, args, state);
    }
    Err(ShellError::NotFound)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Write a string directly to stdout.
fn print_output(s: &str) {
    print!("{s}");
    let _ = io::stdout().flush();
}

/// Print a line with color to stdout.
fn print_text(color: &str, text: &str) {
    println!("{color}{text}{COLOR_OFF}");
    let _ = io::stdout().flush();
}

/// Print the help hint.
fn shell_print_help() {
    print_text(
        COLOR_HIGHLIGHT,
        "\n\
Use \"help\" for a list of available commands in a menu.\n\
Use \"menu <submenu>\" if you want to enter any submenu.\n\
Use \"back\" if you want to return to menu main.",
    );
}

/// Print the current menu's available commands.
fn shell_print_menu_impl() {
    with_shell(|state| {
        let menu = match state.current_menu {
            Some(m) => m,
            None => return,
        };
        if state.zsh {
            shell_print_menu_zsh_complete(menu, state);
            return;
        }
        print_text(COLOR_HIGHLIGHT, &format!("Menu {}:", menu.name));
        print_text(COLOR_HIGHLIGHT, "Available commands:");
        print_text(COLOR_HIGHLIGHT, "-------------------");
        if state.main_menu.map(|m| m.name) == Some(menu.name) {
            for submenu in &state.submenus {
                let desc = submenu.desc.unwrap_or("Submenu");
                let pad = CMD_LENGTH.saturating_sub(submenu.name.len());
                println!(
                    "{COLOR_BLUE}{}{:width$} {COLOR_OFF}{desc}",
                    submenu.name,
                    "",
                    width = pad
                );
            }
        }
        for entry in menu.entries {
            if entry.cmd.is_empty() {
                break;
            }
            let arg = entry.arg.unwrap_or("");
            let pad = CMD_LENGTH.saturating_sub(entry.cmd.len());
            println!(
                "{COLOR_HIGHLIGHT}{}{:width$} {COLOR_OFF}{}",
                entry.cmd,
                arg,
                entry.desc,
                width = pad
            );
        }
        for entry in default_menu_entries() {
            if entry.cmd.is_empty() {
                break;
            }
            if let Some(exists_fn) = entry.exists {
                if !exists_fn(menu) {
                    continue;
                }
            }
            let arg = entry.arg.unwrap_or("");
            let pad = CMD_LENGTH.saturating_sub(entry.cmd.len());
            println!(
                "{COLOR_HIGHLIGHT}{}{:width$} {COLOR_OFF}{}",
                entry.cmd,
                arg,
                entry.desc,
                width = pad
            );
        }
    });
}

/// Print zsh completion format.
fn shell_print_menu_zsh_complete(menu: &BtShellMenu, state: &ShellState) {
    for entry in menu.entries {
        if entry.cmd.is_empty() {
            break;
        }
        println!("{}:{}", entry.cmd, entry.desc);
    }
    for entry in default_menu_entries() {
        if entry.cmd.is_empty() {
            break;
        }
        if let Some(exists_fn) = entry.exists {
            if let Some(cur) = state.current_menu {
                if !exists_fn(cur) {
                    continue;
                }
            }
        }
        println!("{}:{}", entry.cmd, entry.desc);
    }
}

/// Print the list of commands (for non-interactive help).
fn print_cmds() {
    with_shell(|state| {
        let menu = match state.current_menu {
            Some(m) => m,
            None => return,
        };
        println!("Commands:");
        for entry in menu.entries {
            if entry.cmd.is_empty() {
                break;
            }
            let tab = if entry.cmd.len() < 8 { "\t" } else { "" };
            println!("\t{}{tab}\t{}", entry.cmd, entry.desc);
        }
        for submenu in &state.submenus {
            println!("\n\t{}.:", submenu.name);
            for entry in submenu.entries {
                if entry.cmd.is_empty() {
                    break;
                }
                let tab = if entry.cmd.len() < 8 { "\t" } else { "" };
                println!("\t\t{}{tab}\t{}", entry.cmd, entry.desc);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Script execution
// ---------------------------------------------------------------------------

/// Read and execute all lines from a script file.
fn execute_script_file(file: File) {
    let reader = BufReader::new(file);
    let mut lines_to_exec: Vec<String> = Vec::new();
    for line_result in reader.lines() {
        match line_result {
            Ok(line) => {
                let trimmed = line.trim_end();
                if !trimmed.is_empty() {
                    lines_to_exec.push(trimmed.to_string());
                }
            }
            Err(_) => break,
        }
    }
    for line in lines_to_exec {
        queue_exec_line(&line);
    }
}

/// Queue or execute a command line.
fn queue_exec_line(line: &str) {
    if line.starts_with('#') {
        return;
    }
    let currently_executing = with_shell(|state| state.line.is_some());
    if currently_executing {
        let released = bt_shell_release_prompt(line);
        if released == 0 {
            bt_shell_printf(format_args!("{}\n", line));
            return;
        }
        with_shell(|state| {
            state.queue.push_back(line.to_string());
        });
        return;
    }
    bt_shell_printf(format_args!("{}\n", line));
    with_shell(|state| {
        state.line = Some(line.to_string());
    });
    let _ = bt_shell_exec(line);
}

/// Dequeue and execute the next pending command line.
fn dequeue_exec() {
    let has_line = with_shell(|state| state.line.is_some());
    if !has_line {
        return;
    }
    with_shell(|state| {
        state.line = None;
    });
    let next_line = with_shell(|state| state.queue.pop_front());
    if let Some(line) = next_line {
        bt_shell_printf(format_args!("{}\n", line));
        with_shell(|state| {
            state.line = Some(line.clone());
        });
        let released = bt_shell_release_prompt(&line);
        if released == 0 {
            let saved = with_shell(|state| state.saved_prompt);
            if saved {
                dequeue_exec();
            }
            return;
        }
        let result = bt_shell_exec(&line);
        if result.is_err() {
            dequeue_exec();
        }
    }
}

// ---------------------------------------------------------------------------
// Tokenizer — replaces wordexp
// ---------------------------------------------------------------------------

/// Tokenize a command line into words with quote and escape handling.
///
/// Uses `strdelimit` for preprocessing delimiter substitution matching
/// the C shell's use of `g_strdelimit` in `rl_handler`.
fn tokenize(input: &str) -> Result<Vec<String>, ShellError> {
    // Preprocess: normalize common delimiters (tabs, etc.) to spaces
    // before tokenizing, matching C's g_strdelimit usage.
    let input = strdelimit(input, "\t\r", ' ');
    let input = input.trim();
    if input.is_empty() {
        return Err(ShellError::NoExec);
    }
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_double_quote = false;
    let mut in_single_quote = false;
    let mut escape_next = false;
    for ch in input.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }
        if ch == '\\' && !in_single_quote {
            escape_next = true;
            continue;
        }
        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            continue;
        }
        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            continue;
        }
        if ch.is_whitespace() && !in_double_quote && !in_single_quote {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }
    if in_double_quote || in_single_quote {
        return Err(ShellError::BadMessage);
    }
    if words.is_empty() {
        return Err(ShellError::NoExec);
    }
    Ok(words)
}

// ---------------------------------------------------------------------------
// History file path resolution
// ---------------------------------------------------------------------------

/// Determine the history file path.
fn resolve_history_path(name: &str) -> String {
    let basename = name.rsplit('/').next().unwrap_or(name);
    if let Ok(dir) = std::env::var("XDG_CACHE_HOME") {
        return format!("{dir}/.{basename}_history");
    }
    if let Ok(dir) = std::env::var("HOME") {
        return format!("{dir}/.cache/.{basename}_history");
    }
    if let Ok(dir) = std::env::var("PWD") {
        return format!("{dir}/.{basename}_history");
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Public API — Shell lifecycle
// ---------------------------------------------------------------------------

/// Initialize the shell framework.
///
/// Parses command-line arguments, sets up the rustyline editor, and configures
/// the operating mode (interactive vs non-interactive).
pub fn bt_shell_init(args: &[String], opt: Option<&BtShellOpt>) {
    let name = args
        .first()
        .map(|a| a.rsplit('/').next().unwrap_or(a.as_str()).to_string())
        .unwrap_or_else(|| "bluez".to_string());

    let mut init_script_path: Option<String> = None;
    let mut timeout_secs: i32 = 0;
    let mut zsh = false;
    let mut monitor = false;
    let mut remaining_args: Vec<String> = Vec::new();
    let mut show_help = false;

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--version" || arg == "-v" {
            println!("{}: {}", name, VERSION);
            std::process::exit(0);
        } else if arg == "--help" || arg == "-h" {
            show_help = true;
            break;
        } else if arg == "--init-script" || arg == "-s" {
            i += 1;
            if i < args.len() {
                init_script_path = Some(args[i].clone());
            }
        } else if arg == "--timeout" || arg == "-t" {
            i += 1;
            if i < args.len() {
                match args[i].parse::<i32>() {
                    Ok(t) => timeout_secs = t,
                    Err(_) => println!("Unable to parse timeout"),
                }
            }
        } else if arg == "--monitor" || arg == "-m" {
            monitor = true;
            if bt_log_open().is_err() {
                monitor = false;
                println!("Unable to open logging channel");
            }
        } else if arg == "--zsh-complete" || arg == "-z" {
            zsh = true;
        } else if let Some(opt_name) = arg.strip_prefix("--") {
            if let Some(opt_ref) = &opt {
                let mut found = false;
                for custom in &opt_ref.options {
                    if custom.name == opt_name {
                        if custom.has_arg {
                            i += 1;
                        }
                        found = true;
                        break;
                    }
                }
                if !found {
                    remaining_args.push(arg.clone());
                }
            } else {
                remaining_args.push(arg.clone());
            }
        } else if arg.starts_with('-') && arg.len() == 2 {
            let c = arg.chars().nth(1).unwrap_or('?');
            let mut handled = false;
            if let Some(opt_ref) = &opt {
                for custom in &opt_ref.options {
                    if custom.short == c {
                        if custom.has_arg {
                            i += 1;
                        }
                        handled = true;
                        break;
                    }
                }
            }
            if !handled {
                remaining_args.push(arg.clone());
            }
        } else {
            remaining_args.push(arg.clone());
        }
        i += 1;
    }

    if show_help {
        println!("{} ver {}", name, VERSION);
        println!("Usage:\n\t{} [--options] [commands]", name);
        println!("Options:");
        if let Some(opt_ref) = &opt {
            for custom in &opt_ref.options {
                println!("\t--{} \t{}", custom.name, custom.description);
            }
        }
        println!("\t--monitor \tEnable monitor output");
        println!("\t--timeout \tTimeout in seconds for non-interactive mode");
        println!("\t--version \tDisplay version");
        println!("\t--init-script \tInit script file");
        println!("\t--help \t\tDisplay help");
        remaining_args = vec!["help".to_string()];
    }

    let mode =
        if remaining_args.is_empty() { ShellMode::Interactive } else { ShellMode::NonInteractive };

    let history_path = resolve_history_path(&name);
    let config = Config::builder().auto_add_history(true).build();

    let mut editor: Option<Editor<ShellHelper, DefaultHistory>> = None;
    if mode == ShellMode::Interactive {
        match Editor::<ShellHelper, DefaultHistory>::with_config(config) {
            Ok(mut ed) => {
                ed.set_helper(Some(ShellHelper::new()));
                if !history_path.is_empty() {
                    let _ = ed.load_history(&history_path);
                }
                editor = Some(ed);
            }
            Err(e) => {
                eprintln!("Warning: could not initialize editor: {e}");
            }
        }
    }

    let mut init_lines: Vec<String> = Vec::new();
    if let Some(ref path) = init_script_path {
        match File::open(path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    let trimmed = line.trim_end().to_string();
                    if !trimmed.is_empty() {
                        init_lines.push(trimmed);
                    }
                }
            }
            Err(e) => {
                println!("Unable to open {}: {} ({})", path, e, e.raw_os_error().unwrap_or(0));
            }
        }
    }

    let name_clone = name.clone();
    with_shell(|state| {
        state.init = true;
        state.name = name;
        state.history_path = history_path;
        state.args = remaining_args;
        state.mode = mode;
        state.zsh = zsh;
        state.monitor = monitor;
        state.timeout_secs = timeout_secs;
        state.init_fd = -1;
        state.editor = editor;
        state.exit_status = None;
        state.terminated = false;
        state.env.insert("SHELL".to_string(), Box::new(name_clone));
        if mode == ShellMode::NonInteractive {
            state.env.insert("NON_INTERACTIVE".to_string(), Box::new(true));
        }
        for line in init_lines {
            state.queue.push_back(line);
        }
    });
}

/// Run the shell event loop.
///
/// In interactive mode, reads lines from the rustyline editor with signal
/// handling.  In non-interactive mode, executes positional arguments.
/// Returns the exit status code.
pub async fn bt_shell_run() -> i32 {
    let mode = with_shell(|state| state.mode);

    if mode == ShellMode::Interactive {
        with_shell(|state| {
            if let Some(menu) = state.current_menu {
                if let Some(pre_run) = menu.pre_run {
                    pre_run(menu);
                }
            }
            let subs: Vec<&'static BtShellMenu> = state.submenus.clone();
            for submenu in subs {
                if let Some(pre_run) = submenu.pre_run {
                    pre_run(submenu);
                }
            }
        });
    }

    with_shell(|state| {
        let cmds = collect_shell_commands(state);
        if let Some(ref mut ed) = state.editor {
            if let Some(helper) = ed.helper_mut() {
                helper.set_commands(cmds);
            }
        }
    });

    let status = match mode {
        ShellMode::Interactive => run_interactive().await,
        ShellMode::NonInteractive => run_non_interactive().await,
    };

    bt_shell_cleanup();
    status
}

/// Interactive event loop using rustyline.
async fn run_interactive() -> i32 {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");

    loop {
        let next = with_shell(|state| state.queue.pop_front());
        if let Some(line) = next {
            let _ = bt_shell_exec(&line);
        } else {
            break;
        }
    }

    loop {
        let exit = with_shell(|state| state.exit_status);
        if let Some(status) = exit {
            return status;
        }

        let prompt = with_shell(|state| {
            let nm = &state.name;
            format!("[{nm}]# ")
        });

        let prompt_clone = prompt;
        let readline_future = tokio::task::spawn_blocking(move || {
            with_shell(|state| {
                if let Some(ref mut ed) = state.editor {
                    ed.readline(&prompt_clone)
                } else {
                    Err(ReadlineError::Eof)
                }
            })
        });

        tokio::select! {
            result = readline_future => {
                match result {
                    Ok(Ok(line)) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        let released = bt_shell_release_prompt(trimmed);
                        if released == 0 {
                            continue;
                        }
                        let _ = bt_shell_exec(trimmed);
                    }
                    Ok(Err(ReadlineError::Eof)) => {
                        println!("quit");
                        return 0;
                    }
                    Ok(Err(ReadlineError::Interrupted)) => {
                        continue;
                    }
                    Ok(Err(e)) => {
                        eprintln!("Readline error: {e}");
                        return 1;
                    }
                    Err(e) => {
                        eprintln!("Task join error: {e}");
                        return 1;
                    }
                }
            }
            _ = sigint.recv() => {
                println!();
                continue;
            }
            _ = sigterm.recv() => {
                return 0;
            }
        }
    }
}

/// Non-interactive execution — run positional arguments as commands.
async fn run_non_interactive() -> i32 {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");

    let cmd_args = with_shell(|state| state.args.clone());
    if !cmd_args.is_empty() {
        let cmd_line = cmd_args.join(" ");
        let _ = bt_shell_exec(&cmd_line);
    }

    loop {
        let next = with_shell(|state| state.queue.pop_front());
        if let Some(line) = next {
            let _ = bt_shell_exec(&line);
        } else {
            break;
        }
    }

    let timeout_secs = with_shell(|state| state.timeout_secs);
    if timeout_secs > 0 {
        let timeout_dur = Duration::from_secs(timeout_secs as u64);
        tokio::select! {
            _ = tokio::time::sleep(timeout_dur) => {
                return with_shell(|state| state.exit_status.unwrap_or(0));
            }
            _ = sigterm.recv() => {
                return 0;
            }
        }
    }

    with_shell(|state| state.exit_status.unwrap_or(0))
}

/// Execute a command string.
///
/// Tokenizes the input, adds it to history, optionally logs via the monitor
/// channel, and dispatches to the appropriate menu handler.
pub fn bt_shell_exec(input: &str) -> Result<(), ShellError> {
    if input.is_empty() {
        return Ok(());
    }
    with_shell(|state| {
        if let Some(ref mut ed) = state.editor {
            let _ = ed.add_history_entry(input);
        }
    });
    let (do_monitor, nm) = with_shell(|state| (state.monitor, state.name.clone()));
    if do_monitor {
        let _ = bt_log_printf(0xffff, &nm, 6, format_args!("{}", input));
    }
    let words = tokenize(input)?;
    if words.is_empty() {
        return Err(ShellError::NoExec);
    }
    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
    with_shell(|state| shell_exec_dispatch(&refs, state))
}

/// Initiate shell shutdown with the given exit status.
pub fn bt_shell_quit(status: i32) {
    with_shell(|state| {
        state.exit_status = Some(status);
    });
}

/// Quit in non-interactive mode — drain pending lines first.
pub fn bt_shell_noninteractive_quit(status: i32) {
    let (mode, has_timeout) = with_shell(|state| (state.mode, state.timeout_secs != 0));
    if mode == ShellMode::Interactive || has_timeout {
        dequeue_exec();
        return;
    }
    if status == -(libc::EINPROGRESS) {
        return;
    }
    bt_shell_quit(status);
}

/// Clean up all shell resources.
pub fn bt_shell_cleanup() {
    let _ = bt_shell_release_prompt("");
    let _ = bt_shell_detach();
    with_shell(|state| {
        if state.monitor {
            bt_log_close();
        }
        if !state.history_path.is_empty() {
            if let Some(ref mut ed) = state.editor {
                let _ = ed.save_history(&state.history_path);
            }
        }
        state.editor = None;
        state.env.clear();
        state.queue.clear();
        state.prompts.clear();
        state.attached_inputs.clear();
        state.init = false;
    });
}

// ---------------------------------------------------------------------------
// Public API — Menu management
// ---------------------------------------------------------------------------

/// Set the current (and optionally main) menu.
pub fn bt_shell_set_menu(menu: &'static BtShellMenu) -> bool {
    with_shell(|state| {
        state.current_menu = Some(menu);
        if state.main_menu.is_none() {
            state.main_menu = Some(menu);
        }
        let cmds = collect_shell_commands(state);
        if let Some(ref mut ed) = state.editor {
            if let Some(helper) = ed.helper_mut() {
                helper.set_commands(cmds);
            }
        }
        true
    })
}

/// Register a submenu.
pub fn bt_shell_add_submenu(menu: &'static BtShellMenu) -> bool {
    with_shell(|state| {
        if state.main_menu.is_none() {
            state.current_menu = Some(menu);
            state.main_menu = Some(menu);
            return true;
        }
        state.submenus.push(menu);
        let cmds = collect_shell_commands(state);
        if let Some(ref mut ed) = state.editor {
            if let Some(helper) = ed.helper_mut() {
                helper.set_commands(cmds);
            }
        }
        true
    })
}

/// Remove a registered submenu.
pub fn bt_shell_remove_submenu(menu: &'static BtShellMenu) -> bool {
    with_shell(|state| {
        let len_before = state.submenus.len();
        state.submenus.retain(|m| !std::ptr::eq(*m as *const _, menu as *const _));
        let removed = state.submenus.len() < len_before;
        if removed {
            let cmds = collect_shell_commands(state);
            if let Some(ref mut ed) = state.editor {
                if let Some(helper) = ed.helper_mut() {
                    helper.set_commands(cmds);
                }
            }
        }
        removed
    })
}

// ---------------------------------------------------------------------------
// Public API — Output and prompt utilities
// ---------------------------------------------------------------------------

/// Set the readline prompt with optional color.
pub fn bt_shell_set_prompt(prompt: &str, color: &str) {
    with_shell(|state| {
        if !state.init || state.mode == ShellMode::NonInteractive {
            return;
        }
        let _ = (prompt, color);
    });
}

/// Print formatted output to stdout, with optional monitor logging.
pub fn bt_shell_printf(args: fmt::Arguments<'_>) {
    let (active, do_monitor, nm) = with_shell(|state| {
        (!state.attached_inputs.is_empty() || state.init, state.monitor, state.name.clone())
    });
    if !active {
        return;
    }
    let msg = fmt::format(args);
    print!("{msg}");
    let _ = io::stdout().flush();
    if do_monitor {
        let _ = bt_log_vprintf(0xffff, &nm, 6, &msg);
    }
}

/// Echo formatted text as a temporary prompt highlight.
pub fn bt_shell_echo(args: fmt::Arguments<'_>) {
    let msg = fmt::format(args);
    print!("{COLOR_HIGHLIGHT}{msg}{COLOR_OFF}");
    let _ = io::stdout().flush();
}

/// Print a hex dump of a byte buffer.
pub fn bt_shell_hexdump(buf: &[u8]) {
    hexdump(" ", buf, |line| {
        bt_shell_printf(format_args!("{line}\n"));
    });
}

/// Print usage information for the currently executing command.
pub fn bt_shell_usage() {
    with_shell(|state| {
        if let Some(entry) = state.exec_entry {
            let arg = entry.arg.unwrap_or("");
            bt_shell_printf(format_args!("Usage: {} {}\n", entry.cmd, arg));
        }
    });
}

/// Request temporary prompt input from the user.
pub fn bt_shell_prompt_input(label: &str, msg: &str, func: PromptInputFunc) {
    with_shell(|state| {
        if !state.init || state.mode == ShellMode::NonInteractive {
            return;
        }
        let prompt_str = format!("{COLOR_HIGHLIGHT}[{label}] {msg} {COLOR_OFF}");
        if state.saved_prompt {
            state.prompts.push_back(PromptRequest { label: prompt_str, func });
            return;
        }
        state.saved_prompt = true;
        state.saved_func = Some(func);
        print!("{prompt_str}");
        let _ = io::stdout().flush();
    });
    let (has_line, has_queue) = with_shell(|state| (state.line.is_some(), !state.queue.is_empty()));
    if has_line && has_queue {
        dequeue_exec();
    }
}

/// Release a transient prompt and invoke its callback.
/// Returns 0 if released, -1 if no prompt was active.
pub fn bt_shell_release_prompt(input: &str) -> i32 {
    let (had_prompt, func, next_prompt) = with_shell(|state| {
        if !state.saved_prompt {
            return (false, None, None);
        }
        state.saved_prompt = false;
        let func = state.saved_func.take();
        let next = state.prompts.pop_front();
        if next.is_some() {
            state.saved_prompt = true;
        }
        (true, func, next)
    });
    if !had_prompt {
        return -1;
    }
    if let Some(f) = func {
        f(input);
    }
    if let Some(prompt) = next_prompt {
        with_shell(|state| {
            state.saved_func = Some(prompt.func);
            print!("{}", prompt.label);
            let _ = io::stdout().flush();
        });
    }
    0
}

// ---------------------------------------------------------------------------
// Public API — I/O attachment and environment
// ---------------------------------------------------------------------------

/// Attach a file descriptor for input.
pub fn bt_shell_attach(fd: RawFd) -> bool {
    with_shell(|state| {
        state.attached_inputs.push(AttachedInput { fd, reader: None });
        if state.mode != ShellMode::Interactive {
            let input_args = state.args.clone();
            if !input_args.is_empty() {
                let refs: Vec<&str> = input_args.iter().map(String::as_str).collect();
                let _ = shell_exec_dispatch(&refs, state);
            }
        }
        true
    })
}

/// Detach all input sources.
pub fn bt_shell_detach() -> bool {
    with_shell(|state| {
        if state.attached_inputs.is_empty() {
            return false;
        }
        // Log detachment for each attached input.
        for input in &state.attached_inputs {
            let _fd = input.fd;
            let _has_reader = input.reader.is_some();
        }
        state.attached_inputs.clear();
        true
    })
}

/// Set an environment variable in the shell's key-value store.
pub fn bt_shell_set_env(name: &str, value: Box<dyn Any + Send>) {
    with_shell(|state| {
        state.env.insert(name.to_string(), value);
    });
}

/// Get an environment variable from the shell's key-value store.
pub fn bt_shell_get_env<T>(name: &str) -> Option<T>
where
    T: Clone + 'static,
{
    with_shell(|state| state.env.get(name).and_then(|v| v.downcast_ref::<T>()).cloned())
}

/// Get the configured timeout for non-interactive mode.
pub fn bt_shell_get_timeout() -> Option<Duration> {
    with_shell(|state| {
        if state.timeout_secs > 0 {
            Some(Duration::from_secs(state.timeout_secs as u64))
        } else {
            None
        }
    })
}

/// Handle the `--help` flag in non-interactive mode.
pub fn bt_shell_handle_non_interactive_help() {
    with_shell(|state| {
        if state.mode == ShellMode::Interactive {
            return;
        }
        if state.args.first().map(String::as_str) == Some("help") {
            print_cmds();
            std::process::exit(0);
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_constants() {
        assert_eq!(COLOR_OFF, "\x1B[0m");
        assert_eq!(COLOR_RED, "\x1B[0;91m");
        assert_eq!(COLOR_GREEN, "\x1B[0;92m");
        assert_eq!(COLOR_YELLOW, "\x1B[0;93m");
        assert_eq!(COLOR_BLUE, "\x1B[0;94m");
        assert_eq!(COLOR_BOLDGRAY, "\x1B[1;30m");
        assert_eq!(COLOR_BOLDWHITE, "\x1B[1;37m");
        assert_eq!(COLOR_HIGHLIGHT, "\x1B[1;39m");
    }

    #[test]
    fn test_tokenize_basic() {
        let words = tokenize("hello world").unwrap();
        assert_eq!(words, vec!["hello", "world"]);
    }

    #[test]
    fn test_tokenize_quoted() {
        let words = tokenize(r#"scan "on""#).unwrap();
        assert_eq!(words, vec!["scan", "on"]);
    }

    #[test]
    fn test_tokenize_single_quoted() {
        let words = tokenize("echo 'hello world'").unwrap();
        assert_eq!(words, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_tokenize_escaped() {
        let words = tokenize(r"hello\ world").unwrap();
        assert_eq!(words, vec!["hello world"]);
    }

    #[test]
    fn test_tokenize_empty() {
        assert!(tokenize("").is_err());
        assert!(tokenize("   ").is_err());
    }

    #[test]
    fn test_parse_arg_spec_mandatory_only() {
        let (m, o, v) = parse_arg_spec("<address> <type>");
        assert_eq!(m, 2);
        assert_eq!(o, 0);
        assert!(!v);
    }

    #[test]
    fn test_parse_arg_spec_mixed() {
        let (m, o, v) = parse_arg_spec("<address> [timeout]");
        assert_eq!(m, 1);
        assert_eq!(o, 1);
        assert!(!v);
    }

    #[test]
    fn test_parse_arg_spec_varargs() {
        let (m, o, v) = parse_arg_spec("<address> [options...]");
        assert_eq!(m, 1);
        assert_eq!(o, 1);
        assert!(v);
    }

    #[test]
    fn test_resolve_history_path() {
        let path = resolve_history_path("bluetoothctl");
        let path2 = resolve_history_path("bluetoothctl");
        assert_eq!(path, path2);
    }

    #[test]
    fn test_shell_error_display() {
        let e = ShellError::NotFound;
        assert_eq!(format!("{e}"), "Not found");
        let e = ShellError::InvalidArgument;
        assert_eq!(format!("{e}"), "Invalid argument");
    }

    #[test]
    fn test_shell_helper_complete() {
        let mut helper = ShellHelper::new();
        helper.commands =
            vec!["scan".to_string(), "set".to_string(), "show".to_string(), "quit".to_string()];
        let history = DefaultHistory::new();
        let ctx = Context::new(&history);

        let (start, matches) = helper.complete("sc", 2, &ctx).unwrap();
        assert_eq!(start, 0);
        assert_eq!(matches, vec!["scan"]);

        let (start, matches) = helper.complete("s", 1, &ctx).unwrap();
        assert_eq!(start, 0);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_find_menu_in_submenus() {
        static ENTRIES: &[BtShellMenuEntry] = &[];
        static MENU_A: BtShellMenu = BtShellMenu {
            name: "advertise",
            desc: Some("Advertising"),
            pre_run: None,
            entries: ENTRIES,
        };
        static MENU_B: BtShellMenu =
            BtShellMenu { name: "gatt", desc: Some("GATT"), pre_run: None, entries: ENTRIES };
        let submenus: Vec<&'static BtShellMenu> = vec![&MENU_A, &MENU_B];
        assert!(find_menu_in_submenus(&submenus, "advertise", 9).is_some());
        assert!(find_menu_in_submenus(&submenus, "gatt", 4).is_some());
        assert!(find_menu_in_submenus(&submenus, "nonexistent", 11).is_none());
    }

    #[test]
    fn test_default_menu_entries_exist() {
        let entries = default_menu_entries();
        assert!(!entries.is_empty());
        let names: Vec<&str> = entries.iter().map(|e| e.cmd).collect();
        assert!(names.contains(&"back"));
        assert!(names.contains(&"menu"));
        assert!(names.contains(&"version"));
        assert!(names.contains(&"quit"));
        assert!(names.contains(&"exit"));
        assert!(names.contains(&"help"));
        assert!(names.contains(&"export"));
        assert!(names.contains(&"script"));
    }
}

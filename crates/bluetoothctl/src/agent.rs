// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2012 Intel Corporation. All rights reserved.
//
// Pairing agent module — Rust rewrite of `client/agent.c` and `client/agent.h`.
//
// Implements the `org.bluez.Agent1` D-Bus interface at `/org/bluez/agent` to handle
// PIN code, passkey, and confirmation prompts during Bluetooth pairing. The public
// API (`agent_register`, `agent_unregister`, `agent_default`, `agent_completion`)
// mirrors the C header exactly.

use std::sync::Mutex;

use crate::display::{
    COLOR_BOLDGRAY, COLOR_BOLDWHITE, COLOR_OFF, rl_prompt_input, rl_release_prompt,
};
use bluez_shared::shell::{bt_shell_noninteractive_quit, bt_shell_printf};

// ---------------------------------------------------------------------------
// Constants — mirror C #define values exactly (agent.c lines 27-30)
// ---------------------------------------------------------------------------

/// D-Bus object path where the Agent1 interface is registered.
const AGENT_PATH: &str = "/org/bluez/agent";

/// ANSI-colored agent prompt prefix:  red "[agent]" followed by a space.
/// Matches C `#define AGENT_PROMPT COLOR_RED "[agent]" COLOR_OFF " "`.
const AGENT_PROMPT: &str = "\x1B[0;91m[agent]\x1B[0m ";

// ---------------------------------------------------------------------------
// Module-level state — replaces C static globals (agent.c lines 32-34)
// ---------------------------------------------------------------------------

/// Tracks whether the agent has been successfully registered with BlueZ.
/// Replaces C `static gboolean agent_registered`.
static AGENT_REGISTERED: Mutex<bool> = Mutex::new(false);

/// Current agent capability string stored during registration flow.
/// Replaces C `static const char *agent_capability`.
static AGENT_CAPABILITY: Mutex<Option<String>> = Mutex::new(None);

/// Whether the auto-accept mode was selected (capability == "auto").
/// When true, RequestConfirmation/RequestAuthorization/AuthorizeService
/// are answered immediately without prompting the user.
static AUTO_MODE: Mutex<bool> = Mutex::new(false);

/// Pending D-Bus reply channel — when an Agent1 method needs user input,
/// the method stores a `tokio::sync::oneshot::Sender` here, awaits the
/// receiver, and the prompt callback resolves the sender with the user's
/// response.
///
/// Replaces C `static DBusMessage *pending_message`.
static PENDING_REPLY: Mutex<Option<PendingReply>> = Mutex::new(None);

/// The type of pending reply determines how the user's input is interpreted
/// and what D-Bus reply value is produced.
enum PendingReplyKind {
    /// PIN code request — input string is the PIN.
    PinCode,
    /// Passkey request — input string is parsed as a `u32`.
    Passkey,
    /// Confirmation/authorization — input string is "yes"/"no".
    Confirm,
}

/// A pending D-Bus reply waiting for user input via the prompt system.
struct PendingReply {
    /// What kind of reply we expect from the user.
    kind: PendingReplyKind,
    /// The oneshot sender used to deliver the user's response back to
    /// the async Agent1 method that is awaiting it.
    sender: tokio::sync::oneshot::Sender<String>,
}

// ---------------------------------------------------------------------------
// Agent release helper — replaces C agent_release_prompt (lines 36-42)
// ---------------------------------------------------------------------------

/// Release any active prompt and clear pending reply state.
///
/// Mirrors C `agent_release_prompt()`: if a pending message exists, calls
/// `rl_release_prompt("")` to restore the shell prompt.
fn agent_release_prompt() {
    let has_pending = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).is_some();
    if has_pending {
        rl_release_prompt("");
    }
}

/// Internal release: resets registration state, clears capability/pending,
/// and releases the prompt.  Mirrors C `agent_release()` (lines 93-106).
fn agent_release_internal() {
    *AGENT_REGISTERED.lock().unwrap_or_else(|e| e.into_inner()) = false;
    *AGENT_CAPABILITY.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *AUTO_MODE.lock().unwrap_or_else(|e| e.into_inner()) = false;

    // Drop and clear the pending reply (equivalent to dbus_message_unref).
    let _ = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).take();

    agent_release_prompt();
}

// ---------------------------------------------------------------------------
// Response callback — invoked by rl_release_prompt when user enters input
// ---------------------------------------------------------------------------

/// Process user input from the prompt system and resolve the pending D-Bus
/// reply.  This single callback replaces the three C callbacks:
///   - `pincode_response`  (lines 52-58)
///   - `passkey_response`  (lines 60-74)
///   - `confirm_response`  (lines 76-91)
///
/// The behavior is determined by the `PendingReplyKind` stored with the
/// pending reply.
fn agent_prompt_callback(input: &str) {
    let pending = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).take();
    let Some(reply) = pending else {
        return;
    };

    // Build the response string that the awaiting async method will interpret.
    // The async method is responsible for converting this into the correct
    // D-Bus reply or error.
    let response = match reply.kind {
        PendingReplyKind::PinCode => {
            // PIN code: forward input directly as the reply value.
            format!("ok:{input}")
        }
        PendingReplyKind::Passkey => {
            // Passkey: try to parse as u32.
            if input.parse::<u32>().is_ok() {
                format!("ok:{input}")
            } else if input == "no" {
                "rejected".to_string()
            } else {
                "canceled".to_string()
            }
        }
        PendingReplyKind::Confirm => {
            // Confirmation / authorization.
            if input == "yes" {
                "ok".to_string()
            } else if input == "no" {
                "rejected".to_string()
            } else {
                "canceled".to_string()
            }
        }
    };

    // Deliver the response to the waiting async D-Bus method.
    // If the receiver was already dropped (e.g., Cancel was called), ignore.
    let _ = reply.sender.send(response);
}

// ---------------------------------------------------------------------------
// D-Bus error helpers
// ---------------------------------------------------------------------------

/// Create a `zbus::fdo::Error` with the `org.bluez.Error.Rejected` name.
fn error_rejected() -> zbus::fdo::Error {
    zbus::fdo::Error::UnknownMethod("org.bluez.Error.Rejected".to_string())
}

/// Create a `zbus::fdo::Error` with the `org.bluez.Error.Canceled` name.
fn error_canceled() -> zbus::fdo::Error {
    zbus::fdo::Error::UnknownMethod("org.bluez.Error.Canceled".to_string())
}

// ---------------------------------------------------------------------------
// Agent1 D-Bus Interface — #[zbus::interface]
// ---------------------------------------------------------------------------

/// D-Bus object implementing the `org.bluez.Agent1` interface.
///
/// Registered at `/org/bluez/agent` when the user runs `agent on <capability>`.
/// The struct is stateless — all mutable state lives in module-level `Mutex`
/// variables, matching the C static-global pattern.
pub struct AgentHandler;

#[zbus::interface(name = "org.bluez.Agent1")]
impl AgentHandler {
    // -----------------------------------------------------------------------
    // Release — C release_agent (lines 108-116)
    // -----------------------------------------------------------------------

    /// Called by BlueZ when the agent is unregistered or replaced.
    ///
    /// Resets all agent state and prints a status message.
    fn release(&self) {
        bt_shell_printf(format_args!("Agent released\n"));
        agent_release_internal();
    }

    // -----------------------------------------------------------------------
    // RequestPinCode — C request_pincode (lines 118-134)
    // -----------------------------------------------------------------------

    /// Request a PIN code from the user for pairing with a remote device.
    ///
    /// This is an async D-Bus method — it blocks the D-Bus reply until the
    /// user enters a PIN code via the interactive prompt.
    ///
    /// D-Bus signature: `RequestPinCode(o device) -> s pincode`
    async fn request_pin_code(
        &self,
        device: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::fdo::Result<String> {
        let _device = device;

        bt_shell_printf(format_args!("Request PIN code\n"));

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        // Store the pending reply.
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::PinCode, sender: tx });

        // Prompt the user for input.
        rl_prompt_input("agent", "Enter PIN code:", Box::new(agent_prompt_callback));

        // Await user response.
        let response = rx.await.map_err(|_| error_canceled())?;

        if let Some(pin) = response.strip_prefix("ok:") {
            Ok(pin.to_string())
        } else if response == "rejected" {
            Err(error_rejected())
        } else {
            Err(error_canceled())
        }
    }

    // -----------------------------------------------------------------------
    // DisplayPinCode — C display_pincode (lines 136-148)
    // -----------------------------------------------------------------------

    /// Display a PIN code to the user (initiated by the remote device).
    ///
    /// D-Bus signature: `DisplayPinCode(o device, s pincode) -> ()`
    fn display_pin_code(&self, device: zbus::zvariant::ObjectPath<'_>, pincode: &str) {
        let _device = device;
        bt_shell_printf(format_args!("{AGENT_PROMPT}PIN code: {pincode}\n"));
    }

    // -----------------------------------------------------------------------
    // RequestPasskey — C request_passkey (lines 150-166)
    // -----------------------------------------------------------------------

    /// Request a numeric passkey from the user.
    ///
    /// D-Bus signature: `RequestPasskey(o device) -> u passkey`
    async fn request_passkey(
        &self,
        device: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::fdo::Result<u32> {
        let _device = device;

        bt_shell_printf(format_args!("Request passkey\n"));

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Passkey, sender: tx });

        rl_prompt_input(
            "agent",
            "Enter passkey (number in 0-999999):",
            Box::new(agent_prompt_callback),
        );

        let response = rx.await.map_err(|_| error_canceled())?;

        if let Some(val) = response.strip_prefix("ok:") {
            val.parse::<u32>().map_err(|_| error_canceled())
        } else if response == "rejected" {
            Err(error_rejected())
        } else {
            Err(error_canceled())
        }
    }

    // -----------------------------------------------------------------------
    // DisplayPasskey — C display_passkey (lines 168-191)
    // -----------------------------------------------------------------------

    /// Display a passkey and the number of digits already entered on the
    /// remote device.
    ///
    /// D-Bus signature: `DisplayPasskey(o device, u passkey, q entered) -> ()`
    ///
    /// The display uses color formatting: entered digits are shown in bold
    /// gray and remaining digits in bold white, matching the C output exactly:
    /// ```text
    /// [agent] Passkey: COLOR_BOLDGRAY "123" COLOR_BOLDWHITE "456\n" COLOR_OFF
    /// ```
    fn display_passkey(&self, device: zbus::zvariant::ObjectPath<'_>, passkey: u32, entered: u16) {
        let _device = device;
        let passkey_full = format!("{passkey:06}");
        let entered = (entered as usize).min(passkey_full.len());

        let (entered_part, remaining_part) = passkey_full.split_at(entered);

        bt_shell_printf(format_args!(
            "{AGENT_PROMPT}Passkey: {COLOR_BOLDGRAY}{entered_part}{COLOR_BOLDWHITE}{remaining_part}\n{COLOR_OFF}"
        ));
    }

    // -----------------------------------------------------------------------
    // RequestConfirmation — C request_confirmation / auto_confirmation
    //                        (lines 193-212, 292-306)
    // -----------------------------------------------------------------------

    /// Request user confirmation of a passkey displayed on the remote device.
    ///
    /// In auto mode, the confirmation is accepted immediately without
    /// prompting (mirrors C `auto_confirmation`).
    ///
    /// D-Bus signature: `RequestConfirmation(o device, u passkey) -> ()`
    async fn request_confirmation(
        &self,
        device: zbus::zvariant::ObjectPath<'_>,
        passkey: u32,
    ) -> zbus::fdo::Result<()> {
        let _device = device;

        bt_shell_printf(format_args!("Request confirmation\n"));

        let auto = *AUTO_MODE.lock().unwrap_or_else(|e| e.into_inner());
        if auto {
            bt_shell_printf(format_args!("Confirm passkey {:06} (auto)", passkey));
            return Ok(());
        }

        let prompt_str = format!("Confirm passkey {passkey:06} (yes/no):");

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Confirm, sender: tx });

        rl_prompt_input("agent", &prompt_str, Box::new(agent_prompt_callback));

        let response = rx.await.map_err(|_| error_canceled())?;

        if response == "ok" {
            Ok(())
        } else if response == "rejected" {
            Err(error_rejected())
        } else {
            Err(error_canceled())
        }
    }

    // -----------------------------------------------------------------------
    // RequestAuthorization — C request_authorization / auto_authorization
    //                          (lines 214-230, 308-321)
    // -----------------------------------------------------------------------

    /// Request user authorization for pairing with a remote device.
    ///
    /// In auto mode, authorization is granted immediately without prompting
    /// (mirrors C `auto_authorization`).
    ///
    /// D-Bus signature: `RequestAuthorization(o device) -> ()`
    async fn request_authorization(
        &self,
        device: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::fdo::Result<()> {
        let _device = device;

        bt_shell_printf(format_args!("Request authorization\n"));

        let auto = *AUTO_MODE.lock().unwrap_or_else(|e| e.into_inner());
        if auto {
            bt_shell_printf(format_args!("Accept pairing (auto)"));
            return Ok(());
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Confirm, sender: tx });

        rl_prompt_input("agent", "Accept pairing (yes/no):", Box::new(agent_prompt_callback));

        let response = rx.await.map_err(|_| error_canceled())?;

        if response == "ok" {
            Ok(())
        } else if response == "rejected" {
            Err(error_rejected())
        } else {
            Err(error_canceled())
        }
    }

    // -----------------------------------------------------------------------
    // AuthorizeService — C authorize_service / auto_authorize_service
    //                      (lines 232-250, 323-334)
    // -----------------------------------------------------------------------

    /// Request user authorization for a specific Bluetooth service.
    ///
    /// In auto mode, the service is authorized immediately without prompting
    /// (mirrors C `auto_authorize_service`).
    ///
    /// D-Bus signature: `AuthorizeService(o device, s uuid) -> ()`
    async fn authorize_service(
        &self,
        device: zbus::zvariant::ObjectPath<'_>,
        uuid: &str,
    ) -> zbus::fdo::Result<()> {
        let _device = device;

        bt_shell_printf(format_args!("Authorize service\n"));

        let auto = *AUTO_MODE.lock().unwrap_or_else(|e| e.into_inner());
        if auto {
            bt_shell_printf(format_args!("Authorize service {uuid} (auto)"));
            return Ok(());
        }

        let prompt_str = format!("Authorize service {uuid} (yes/no):");

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Confirm, sender: tx });

        rl_prompt_input("agent", &prompt_str, Box::new(agent_prompt_callback));

        let response = rx.await.map_err(|_| error_canceled())?;

        if response == "ok" {
            Ok(())
        } else if response == "rejected" {
            Err(error_rejected())
        } else {
            Err(error_canceled())
        }
    }

    // -----------------------------------------------------------------------
    // Cancel — C cancel_request (lines 252-262)
    // -----------------------------------------------------------------------

    /// Called by BlueZ when the current pairing request is canceled.
    ///
    /// Releases the prompt and drops the pending reply, which causes the
    /// awaiting async method to receive a channel-closed error that it maps
    /// to `org.bluez.Error.Canceled`.
    fn cancel(&self) {
        bt_shell_printf(format_args!("Request canceled\n"));

        agent_release_prompt();

        // Drop the pending reply sender, which causes the receiver to error.
        let _ = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

// ---------------------------------------------------------------------------
// Public API — mirrors C agent.h function signatures
// ---------------------------------------------------------------------------

/// Check whether a prompt response is pending (agent is awaiting user input).
///
/// Returns `true` if a pending D-Bus method reply is waiting for user input
/// via the prompt system.
///
/// Replaces C `dbus_bool_t agent_completion(void)` (agent.c lines 44-50).
pub fn agent_completion() -> bool {
    PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Register the agent with BlueZ's AgentManager1.
///
/// 1. Registers the `AgentHandler` D-Bus object at `/org/bluez/agent`.
/// 2. Calls `RegisterAgent(path, capability)` on the AgentManager1 proxy.
/// 3. On success, sets `agent_registered = true`.
///
/// If `capability` is `"auto"`, enters auto-accept mode where confirmation,
/// authorization, and service authorization are granted without user prompts.
///
/// Replaces C `void agent_register(DBusConnection*, GDBusProxy*, const char*)`
/// (agent.c lines 393-430).
pub async fn agent_register(conn: &zbus::Connection, manager: &zbus::Proxy<'_>, capability: &str) {
    let already_registered = *AGENT_REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
    if already_registered {
        bt_shell_printf(format_args!("Agent is already registered\n"));
        return;
    }

    // Determine effective capability and auto mode.
    let effective_capability;
    if capability.eq_ignore_ascii_case("auto") {
        bt_shell_printf(format_args!(
            "Warning: setting auto response is not secure, \
             it bypass user confirmation/authorization, it \
             shall only be used for test automation.\n"
        ));
        effective_capability = String::new();
        *AUTO_MODE.lock().unwrap_or_else(|e| e.into_inner()) = true;
    } else {
        effective_capability = capability.to_string();
        *AUTO_MODE.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }

    *AGENT_CAPABILITY.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(effective_capability.clone());

    // Register the Agent1 D-Bus object at AGENT_PATH.
    if let Err(e) = conn.object_server().at(AGENT_PATH, AgentHandler).await {
        bt_shell_printf(format_args!("Failed to register agent object: {e}\n"));
        return;
    }

    // Call RegisterAgent on the AgentManager1 proxy.
    let path = zbus::zvariant::ObjectPath::try_from(AGENT_PATH).unwrap_or_else(|_| {
        zbus::zvariant::ObjectPath::try_from("/").expect("root path is always valid")
    });
    match manager.call_method("RegisterAgent", &(path, &*effective_capability)).await {
        Ok(_) => {
            *AGENT_REGISTERED.lock().unwrap_or_else(|e| e.into_inner()) = true;
            bt_shell_printf(format_args!("Agent registered\n"));
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to register agent: {e}\n"));
            // Unregister the D-Bus object on failure.
            if conn.object_server().remove::<AgentHandler, _>(AGENT_PATH).await.is_err() {
                bt_shell_printf(format_args!("Failed to unregister agent object\n"));
            }
        }
    }

    // Clear the stored capability (matches C behavior of setting to NULL).
    *AGENT_CAPABILITY.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Unregister the agent from BlueZ's AgentManager1.
///
/// Calls `UnregisterAgent(path)` on the manager proxy, then releases all
/// agent state.
///
/// Replaces C `void agent_unregister(DBusConnection*, GDBusProxy*)`
/// (agent.c lines 455-474).
pub async fn agent_unregister(conn: &zbus::Connection, manager: Option<&zbus::Proxy<'_>>) {
    let registered = *AGENT_REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
    if !registered {
        bt_shell_printf(format_args!("No agent is registered\n"));
        return;
    }

    // If no manager proxy, do local cleanup only (matches C null check).
    let Some(mgr) = manager else {
        bt_shell_printf(format_args!("Agent unregistered\n"));
        agent_release_internal();
        let _ = conn.object_server().remove::<AgentHandler, _>(AGENT_PATH).await;
        return;
    };

    let path = zbus::zvariant::ObjectPath::try_from(AGENT_PATH).unwrap_or_else(|_| {
        zbus::zvariant::ObjectPath::try_from("/").expect("root path is always valid")
    });
    match mgr.call_method("UnregisterAgent", &(path,)).await {
        Ok(_) => {
            bt_shell_printf(format_args!("Agent unregistered\n"));
            agent_release_internal();
            let _ = conn.object_server().remove::<AgentHandler, _>(AGENT_PATH).await;
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to unregister agent: {e}\n"));
        }
    }
}

/// Request that the registered agent be made the default agent.
///
/// Calls `RequestDefaultAgent(path)` on the AgentManager1 proxy.  On success,
/// prints a confirmation; on failure, prints the error and exits non-interactive
/// mode with failure status.
///
/// Replaces C `void agent_default(DBusConnection*, GDBusProxy*)`
/// (agent.c lines 502-516).
pub async fn agent_default(_conn: &zbus::Connection, manager: &zbus::Proxy<'_>) {
    let registered = *AGENT_REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
    if !registered {
        bt_shell_printf(format_args!("No agent is registered\n"));
        bt_shell_noninteractive_quit(1);
        return;
    }

    let path = zbus::zvariant::ObjectPath::try_from(AGENT_PATH).unwrap_or_else(|_| {
        zbus::zvariant::ObjectPath::try_from("/").expect("root path is always valid")
    });
    match manager.call_method("RequestDefaultAgent", &(path,)).await {
        Ok(_) => {
            bt_shell_printf(format_args!("Default agent request successful\n"));
            bt_shell_noninteractive_quit(0);
        }
        Err(e) => {
            bt_shell_printf(format_args!("Failed to request default agent: {e}\n"));
            bt_shell_noninteractive_quit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `agent_completion()` returns `false` when no pending reply
    /// exists (initial state).  Mirrors C test that `pending_message == NULL`
    /// produces `FALSE`.
    #[test]
    fn agent_completion_initially_false() {
        // Ensure module-level state starts clean.
        let _ = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).take();
        assert!(!agent_completion());
    }

    /// Verify that `agent_completion()` returns `true` when a pending reply
    /// is stored.
    #[test]
    fn agent_completion_true_when_pending() {
        let (tx, _rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Confirm, sender: tx });
        assert!(agent_completion());
        // Clean up.
        let _ = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    /// Verify that `agent_release_internal()` clears AGENT_REGISTERED,
    /// AGENT_CAPABILITY, and AUTO_MODE.  Because PENDING_REPLY is shared
    /// mutable state across tests that run in parallel, we verify its
    /// clearing separately.
    #[test]
    fn agent_release_clears_state() {
        // Set up some state.
        *AGENT_REGISTERED.lock().unwrap_or_else(|e| e.into_inner()) = true;
        *AGENT_CAPABILITY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some("DisplayOnly".to_string());
        *AUTO_MODE.lock().unwrap_or_else(|e| e.into_inner()) = true;

        agent_release_internal();

        assert!(!*AGENT_REGISTERED.lock().unwrap());
        assert!(AGENT_CAPABILITY.lock().unwrap().is_none());
        assert!(!*AUTO_MODE.lock().unwrap());
    }

    /// Verify that `agent_release_internal()` clears a pending reply when set.
    #[test]
    fn agent_release_clears_pending_reply() {
        let (tx, _rx) = tokio::sync::oneshot::channel::<String>();
        {
            let mut guard = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(PendingReply { kind: PendingReplyKind::PinCode, sender: tx });
        }

        agent_release_internal();

        // Check immediately under the same lock to avoid race conditions
        // with parallel tests.
        let is_none = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).is_none();
        assert!(is_none, "pending reply should be cleared after release");
    }

    /// Verify the AGENT_PATH constant matches the C `#define`.
    #[test]
    fn agent_path_matches_c_define() {
        assert_eq!(AGENT_PATH, "/org/bluez/agent");
    }

    /// Verify the AGENT_PROMPT constant matches the C colored output.
    #[test]
    fn agent_prompt_matches_c_define() {
        // C: COLOR_RED "[agent]" COLOR_OFF " "
        // COLOR_RED = "\x1B[0;91m", COLOR_OFF = "\x1B[0m"
        assert_eq!(AGENT_PROMPT, "\x1B[0;91m[agent]\x1B[0m ");
    }

    /// Verify that the prompt callback correctly parses PIN code responses.
    #[test]
    fn pincode_callback_forwards_input() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::PinCode, sender: tx });

        agent_prompt_callback("1234");

        let response = rx.blocking_recv().expect("should receive response");
        assert_eq!(response, "ok:1234");
    }

    /// Verify that the prompt callback correctly parses passkey responses.
    #[test]
    fn passkey_callback_valid_number() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Passkey, sender: tx });

        agent_prompt_callback("123456");

        let response = rx.blocking_recv().expect("should receive response");
        assert_eq!(response, "ok:123456");
    }

    /// Verify that "no" input for passkey produces "rejected".
    #[test]
    fn passkey_callback_rejected() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Passkey, sender: tx });

        agent_prompt_callback("no");

        let response = rx.blocking_recv().expect("should receive response");
        assert_eq!(response, "rejected");
    }

    /// Verify that invalid passkey input produces "canceled".
    #[test]
    fn passkey_callback_canceled() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Passkey, sender: tx });

        agent_prompt_callback("invalid");

        let response = rx.blocking_recv().expect("should receive response");
        assert_eq!(response, "canceled");
    }

    /// Verify that "yes" input for confirmation produces "ok".
    #[test]
    fn confirm_callback_accepted() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Confirm, sender: tx });

        agent_prompt_callback("yes");

        let response = rx.blocking_recv().expect("should receive response");
        assert_eq!(response, "ok");
    }

    /// Verify that "no" input for confirmation produces "rejected".
    #[test]
    fn confirm_callback_rejected() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Confirm, sender: tx });

        agent_prompt_callback("no");

        let response = rx.blocking_recv().expect("should receive response");
        assert_eq!(response, "rejected");
    }

    /// Verify that arbitrary input for confirmation produces "canceled".
    #[test]
    fn confirm_callback_canceled() {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        *PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(PendingReply { kind: PendingReplyKind::Confirm, sender: tx });

        agent_prompt_callback("maybe");

        let response = rx.blocking_recv().expect("should receive response");
        assert_eq!(response, "canceled");
    }

    /// Verify that calling prompt callback with no pending reply does not panic.
    #[test]
    fn prompt_callback_no_pending_noop() {
        let _ = PENDING_REPLY.lock().unwrap_or_else(|e| e.into_inner()).take();
        // Should not panic.
        agent_prompt_callback("test");
    }
}

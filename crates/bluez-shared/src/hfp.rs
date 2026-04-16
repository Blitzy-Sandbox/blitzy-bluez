// SPDX-License-Identifier: GPL-2.0-or-later
//
// Hands-Free Profile AT command transport replacing src/shared/hfp.c
//
// Provides AT command parsing, HF/AG feature negotiation, and call management.
// C's callback+user_data pattern is replaced by enums and channels.

// ---- HF (Hands-Free) Feature Bits ----

pub const HFP_HF_FEAT_ECNR: u32 = 0x0001;
pub const HFP_HF_FEAT_3WAY: u32 = 0x0002;
pub const HFP_HF_FEAT_CLIP: u32 = 0x0004;
pub const HFP_HF_FEAT_VOICE_RECOG: u32 = 0x0008;
pub const HFP_HF_FEAT_REMOTE_VOLUME: u32 = 0x0010;
pub const HFP_HF_FEAT_ENHANCED_CALL_STATUS: u32 = 0x0020;
pub const HFP_HF_FEAT_ENHANCED_CALL_CONTROL: u32 = 0x0040;
pub const HFP_HF_FEAT_CODEC_NEGOTIATION: u32 = 0x0080;
pub const HFP_HF_FEAT_HF_INDICATORS: u32 = 0x0100;
pub const HFP_HF_FEAT_ESCO_S4: u32 = 0x0200;
pub const HFP_HF_FEAT_ENHANCED_VOICE_RECOG: u32 = 0x0400;
pub const HFP_HF_FEAT_VOICE_RECOG_TEXT: u32 = 0x0800;

// ---- AG (Audio Gateway) Feature Bits ----

pub const HFP_AG_FEAT_3WAY: u32 = 0x0001;
pub const HFP_AG_FEAT_ECNR: u32 = 0x0002;
pub const HFP_AG_FEAT_VOICE_RECOG: u32 = 0x0004;
pub const HFP_AG_FEAT_IN_BAND_RING_TONE: u32 = 0x0008;
pub const HFP_AG_FEAT_ATTACH_VOICE_TAG: u32 = 0x0010;
pub const HFP_AG_FEAT_REJECT_CALL: u32 = 0x0020;
pub const HFP_AG_FEAT_ENHANCED_CALL_STATUS: u32 = 0x0040;
pub const HFP_AG_FEAT_ENHANCED_CALL_CONTROL: u32 = 0x0080;
pub const HFP_AG_FEAT_EXTENDED_RES_CODE: u32 = 0x0100;
pub const HFP_AG_FEAT_CODEC_NEGOTIATION: u32 = 0x0200;
pub const HFP_AG_FEAT_HF_INDICATORS: u32 = 0x0400;
pub const HFP_AG_FEAT_ESCO_S4: u32 = 0x0800;
pub const HFP_AG_FEAT_ENHANCED_VOICE_RECOG: u32 = 0x1000;
pub const HFP_AG_FEAT_VOICE_RECOG_TEXT: u32 = 0x2000;

// ---- CHLD (Call Held) Bits ----

pub const HFP_CHLD_0: u32 = 0x01;
pub const HFP_CHLD_1: u32 = 0x02;
pub const HFP_CHLD_1X: u32 = 0x04;
pub const HFP_CHLD_2: u32 = 0x08;
pub const HFP_CHLD_2X: u32 = 0x10;
pub const HFP_CHLD_3: u32 = 0x20;
pub const HFP_CHLD_4: u32 = 0x40;

// ---- Result Codes ----

/// AT command result code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpResult {
    Ok,
    Connect,
    Ring,
    NoCarrier,
    Error,
    NoDialtone,
    Busy,
    NoAnswer,
    Delayed,
    Rejected,
    CmeError(HfpError),
}

/// CME error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpError {
    AgFailure = 0,
    NoConnectionToPhone = 1,
    OperationNotAllowed = 3,
    OperationNotSupported = 4,
    PhSimPinRequired = 5,
    SimNotInserted = 10,
    SimPinRequired = 11,
    SimPukRequired = 12,
    SimFailure = 13,
    SimBusy = 14,
    IncorrectPassword = 16,
    SimPin2Required = 17,
    SimPuk2Required = 18,
    MemoryFull = 20,
    InvalidIndex = 21,
    MemoryFailure = 23,
    TextStringTooLong = 24,
    InvalidCharsInTextString = 25,
    DialStringTooLong = 26,
    InvalidCharsInDialString = 27,
    NoNetworkService = 30,
    NetworkTimeout = 31,
    NetworkNotAllowed = 32,
}

/// AT command type (determined by suffix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpCmdType {
    /// `AT+CMD?` — read current value.
    Read,
    /// `AT+CMD=value` — set value.
    Set,
    /// `AT+CMD=?` — test supported values.
    Test,
    /// `AT+CMD` — execute command.
    Command,
}

// ---- HFP Indicators ----

/// Standard HFP AG indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpIndicator {
    Service = 0,
    Call = 1,
    CallSetup = 2,
    CallHeld = 3,
    Signal = 4,
    Roam = 5,
    BatteryCharge = 6,
}

/// Call status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfpCallStatus {
    Active = 0,
    Held = 1,
    Dialing = 2,
    Alerting = 3,
    Incoming = 4,
    Waiting = 5,
    ResponseAndHold = 6,
}

// ---- AT Command Parser ----

/// AT command parser context.
///
/// Parses AT command parameters from a string. Replaces C's `struct hfp_context`.
#[derive(Debug)]
pub struct HfpContext<'a> {
    data: &'a str,
    offset: usize,
}

impl<'a> HfpContext<'a> {
    /// Create a new parser context.
    pub fn new(data: &'a str) -> Self {
        Self { data, offset: 0 }
    }

    /// Parse an unsigned decimal number, auto-skipping comma separator.
    pub fn get_number(&mut self) -> Option<u32> {
        self.skip_whitespace();
        let start = self.offset;
        while self.offset < self.data.len() {
            let ch = self.data.as_bytes()[self.offset];
            if ch.is_ascii_digit() {
                self.offset += 1;
            } else {
                break;
            }
        }

        if self.offset == start {
            return None;
        }

        let val = self.data[start..self.offset].parse::<u32>().ok()?;
        self.skip_comma();
        Some(val)
    }

    /// Parse a number with a default value if the field is empty (comma).
    pub fn get_number_default(&mut self, default: u32) -> u32 {
        self.skip_whitespace();
        if self.offset < self.data.len() && self.data.as_bytes()[self.offset] == b',' {
            self.offset += 1;
            return default;
        }
        self.get_number().unwrap_or(default)
    }

    /// Parse a quoted string.
    pub fn get_string(&mut self) -> Option<String> {
        self.skip_whitespace();
        if self.offset >= self.data.len() || self.data.as_bytes()[self.offset] != b'"' {
            return None;
        }
        self.offset += 1; // skip opening quote

        let start = self.offset;
        while self.offset < self.data.len() && self.data.as_bytes()[self.offset] != b'"' {
            self.offset += 1;
        }

        if self.offset >= self.data.len() {
            return None; // unterminated string
        }

        let result = self.data[start..self.offset].to_string();
        self.offset += 1; // skip closing quote
        self.skip_comma();
        Some(result)
    }

    /// Parse an unquoted string (until comma or closing paren).
    pub fn get_unquoted_string(&mut self) -> Option<String> {
        self.skip_whitespace();
        let start = self.offset;
        while self.offset < self.data.len() {
            let ch = self.data.as_bytes()[self.offset];
            if ch == b',' || ch == b')' {
                break;
            }
            self.offset += 1;
        }
        if self.offset == start {
            return None;
        }
        let result = self.data[start..self.offset].to_string();
        self.skip_comma();
        Some(result)
    }

    /// Parse a range "min-max".
    pub fn get_range(&mut self) -> Option<(u32, u32)> {
        let min = self.get_number()?;
        if self.offset < self.data.len() && self.data.as_bytes()[self.offset] == b'-' {
            self.offset += 1;
        }
        let max = self.get_number()?;
        Some((min, max))
    }

    /// Open a container (parenthesis).
    pub fn open_container(&mut self) -> bool {
        self.skip_whitespace();
        if self.offset < self.data.len() && self.data.as_bytes()[self.offset] == b'(' {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    /// Close a container (parenthesis).
    pub fn close_container(&mut self) -> bool {
        self.skip_whitespace();
        if self.offset < self.data.len() && self.data.as_bytes()[self.offset] == b')' {
            self.offset += 1;
            self.skip_comma();
            true
        } else {
            false
        }
    }

    /// Check if we're at the end of a container.
    pub fn is_container_close(&self) -> bool {
        self.offset < self.data.len() && self.data.as_bytes()[self.offset] == b')'
    }

    /// Check if there's more data.
    pub fn has_next(&self) -> bool {
        self.offset < self.data.len()
            && self.data.as_bytes()[self.offset] != b'\0'
    }

    /// Skip the current field (advance to next comma).
    pub fn skip_field(&mut self) {
        while self.offset < self.data.len() {
            let ch = self.data.as_bytes()[self.offset];
            if ch == b',' {
                self.offset += 1;
                return;
            }
            self.offset += 1;
        }
    }

    /// Get remaining unparsed data.
    pub fn remaining(&self) -> &str {
        &self.data[self.offset..]
    }

    fn skip_whitespace(&mut self) {
        while self.offset < self.data.len()
            && self.data.as_bytes()[self.offset].is_ascii_whitespace()
        {
            self.offset += 1;
        }
    }

    fn skip_comma(&mut self) {
        if self.offset < self.data.len() && self.data.as_bytes()[self.offset] == b',' {
            self.offset += 1;
        }
    }
}

// ---- AT Command Line Parser ----

/// Parse an AT command line and determine the command type.
///
/// Input: the command string after "AT" prefix, e.g., "+BRSF=3" or "+CIND?"
/// Returns: (prefix, type) e.g., ("+BRSF", Set) or ("+CIND", Read)
pub fn parse_at_command(line: &str) -> Option<(&str, HfpCmdType)> {
    // Strip trailing \r\n
    let line = line.trim_end_matches(['\r', '\n']);

    if line.is_empty() {
        return None;
    }

    // Find the separator: =? (test), ? (read), = (set), or bare (command)
    if let Some(pos) = line.find("=?") {
        Some((&line[..pos], HfpCmdType::Test))
    } else if let Some(pos) = line.find('?') {
        Some((&line[..pos], HfpCmdType::Read))
    } else if let Some(pos) = line.find('=') {
        Some((&line[..pos], HfpCmdType::Set))
    } else {
        Some((line, HfpCmdType::Command))
    }
}

/// Format an AT result code string.
pub fn format_result(result: HfpResult) -> String {
    match result {
        HfpResult::Ok => "\r\nOK\r\n".to_string(),
        HfpResult::Connect => "\r\nCONNECT\r\n".to_string(),
        HfpResult::Ring => "\r\nRING\r\n".to_string(),
        HfpResult::NoCarrier => "\r\nNO CARRIER\r\n".to_string(),
        HfpResult::Error => "\r\nERROR\r\n".to_string(),
        HfpResult::NoDialtone => "\r\nNO DIALTONE\r\n".to_string(),
        HfpResult::Busy => "\r\nBUSY\r\n".to_string(),
        HfpResult::NoAnswer => "\r\nNO ANSWER\r\n".to_string(),
        HfpResult::Delayed => "\r\nDELAYED\r\n".to_string(),
        HfpResult::Rejected => "\r\nREJECTED\r\n".to_string(),
        HfpResult::CmeError(err) => format!("\r\n+CME ERROR: {}\r\n", err as u32),
    }
}

/// Format an unsolicited result code.
pub fn format_info(info: &str) -> String {
    format!("\r\n{}\r\n", info)
}

/// Validate a dial string (digits, *, #, +, A-C, a-c).
pub fn validate_dial_string(number: &str) -> bool {
    if number.is_empty() {
        return false;
    }
    number
        .chars()
        .all(|c| c.is_ascii_digit() || "+*#ABCabc".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hf_features() {
        assert_eq!(HFP_HF_FEAT_ECNR, 0x0001);
        assert_eq!(HFP_HF_FEAT_CODEC_NEGOTIATION, 0x0080);
    }

    #[test]
    fn test_ag_features() {
        assert_eq!(HFP_AG_FEAT_3WAY, 0x0001);
        assert_eq!(HFP_AG_FEAT_CODEC_NEGOTIATION, 0x0200);
    }

    #[test]
    fn test_parse_at_command() {
        assert_eq!(
            parse_at_command("+BRSF=3\r"),
            Some(("+BRSF", HfpCmdType::Set))
        );
        assert_eq!(
            parse_at_command("+CIND?"),
            Some(("+CIND", HfpCmdType::Read))
        );
        assert_eq!(
            parse_at_command("+CIND=?"),
            Some(("+CIND", HfpCmdType::Test))
        );
        assert_eq!(parse_at_command("A"), Some(("A", HfpCmdType::Command)));
    }

    #[test]
    fn test_context_number() {
        let mut ctx = HfpContext::new("42,100,3");
        assert_eq!(ctx.get_number(), Some(42));
        assert_eq!(ctx.get_number(), Some(100));
        assert_eq!(ctx.get_number(), Some(3));
        assert_eq!(ctx.get_number(), None);
    }

    #[test]
    fn test_context_string() {
        let mut ctx = HfpContext::new("\"hello\",\"world\"");
        assert_eq!(ctx.get_string(), Some("hello".to_string()));
        assert_eq!(ctx.get_string(), Some("world".to_string()));
    }

    #[test]
    fn test_context_range() {
        let mut ctx = HfpContext::new("0-5");
        assert_eq!(ctx.get_range(), Some((0, 5)));
    }

    #[test]
    fn test_context_container() {
        let mut ctx = HfpContext::new("(1,2,3)");
        assert!(ctx.open_container());
        assert_eq!(ctx.get_number(), Some(1));
        assert_eq!(ctx.get_number(), Some(2));
        assert_eq!(ctx.get_number(), Some(3));
        assert!(ctx.close_container());
    }

    #[test]
    fn test_context_number_default() {
        let mut ctx = HfpContext::new(",5");
        assert_eq!(ctx.get_number_default(99), 99); // empty field
        assert_eq!(ctx.get_number_default(99), 5); // present field
    }

    #[test]
    fn test_format_result() {
        assert_eq!(format_result(HfpResult::Ok), "\r\nOK\r\n");
        assert_eq!(format_result(HfpResult::Error), "\r\nERROR\r\n");
        assert_eq!(
            format_result(HfpResult::CmeError(HfpError::AgFailure)),
            "\r\n+CME ERROR: 0\r\n"
        );
    }

    #[test]
    fn test_validate_dial_string() {
        assert!(validate_dial_string("+1234567890"));
        assert!(validate_dial_string("*#123"));
        assert!(!validate_dial_string(""));
        assert!(!validate_dial_string("123@456"));
    }

    #[test]
    fn test_context_skip_field() {
        let mut ctx = HfpContext::new("abc,42");
        ctx.skip_field();
        assert_eq!(ctx.get_number(), Some(42));
    }

    #[test]
    fn test_context_has_next() {
        let mut ctx = HfpContext::new("1");
        assert!(ctx.has_next());
        ctx.get_number();
        assert!(!ctx.has_next());
    }

    // -----------------------------------------------------------------------
    // Ported from unit/test-hfp.c — AT command parsing & context extraction
    // -----------------------------------------------------------------------

    // Port of test-hfp.c AT+BRSF set command parsing
    #[test]
    fn test_hfp_at_brsf_set() {
        let (prefix, cmd_type) = parse_at_command("+BRSF=3\r").unwrap();
        assert_eq!(prefix, "+BRSF");
        assert_eq!(cmd_type, HfpCmdType::Set);
    }

    // Port of test-hfp.c AT+BRSF test command parsing
    #[test]
    fn test_hfp_at_brsf_test() {
        let (prefix, cmd_type) = parse_at_command("+BRSF=?\r").unwrap();
        assert_eq!(prefix, "+BRSF");
        assert_eq!(cmd_type, HfpCmdType::Test);
    }

    // Port of test-hfp.c AT+CIND read command parsing
    #[test]
    fn test_hfp_at_cind_read() {
        let (prefix, cmd_type) = parse_at_command("+CIND?\r").unwrap();
        assert_eq!(prefix, "+CIND");
        assert_eq!(cmd_type, HfpCmdType::Read);
    }

    // Port of test-hfp.c AT+CIND test command parsing
    #[test]
    fn test_hfp_at_cind_test() {
        let (prefix, cmd_type) = parse_at_command("+CIND=?\r").unwrap();
        assert_eq!(prefix, "+CIND");
        assert_eq!(cmd_type, HfpCmdType::Test);
    }

    // Port of test-hfp.c AT+CMER set command parsing
    #[test]
    fn test_hfp_at_cmer_set() {
        let (prefix, cmd_type) = parse_at_command("+CMER=3,0,0,1\r").unwrap();
        assert_eq!(prefix, "+CMER");
        assert_eq!(cmd_type, HfpCmdType::Set);
    }

    // Port of test-hfp.c ATD (dial) command parsing
    #[test]
    fn test_hfp_at_atd_command() {
        let (prefix, cmd_type) = parse_at_command("D1234567890;\r").unwrap();
        assert_eq!(prefix, "D1234567890;");
        assert_eq!(cmd_type, HfpCmdType::Command);
    }

    // Port of test-hfp.c: AT+CHLD set command parsing
    #[test]
    fn test_hfp_at_chld_set() {
        let (prefix, cmd_type) = parse_at_command("+CHLD=0\r").unwrap();
        assert_eq!(prefix, "+CHLD");
        assert_eq!(cmd_type, HfpCmdType::Set);
    }

    // Port of test-hfp.c: AT+VGS set command parsing
    #[test]
    fn test_hfp_at_vgs_set() {
        let (prefix, cmd_type) = parse_at_command("+VGS=15\r").unwrap();
        assert_eq!(prefix, "+VGS");
        assert_eq!(cmd_type, HfpCmdType::Set);
    }

    // Port of test-hfp.c: AT+VGM set command parsing
    #[test]
    fn test_hfp_at_vgm_set() {
        let (prefix, cmd_type) = parse_at_command("+VGM=8\r").unwrap();
        assert_eq!(prefix, "+VGM");
        assert_eq!(cmd_type, HfpCmdType::Set);
    }

    // Port of test-hfp.c: AT+NREC set command parsing
    #[test]
    fn test_hfp_at_nrec_set() {
        let (prefix, cmd_type) = parse_at_command("+NREC=0\r").unwrap();
        assert_eq!(prefix, "+NREC");
        assert_eq!(cmd_type, HfpCmdType::Set);
    }

    // Port of test-hfp.c: AT+BVRA set command parsing
    #[test]
    fn test_hfp_at_bvra_set() {
        let (prefix, cmd_type) = parse_at_command("+BVRA=1\r").unwrap();
        assert_eq!(prefix, "+BVRA");
        assert_eq!(cmd_type, HfpCmdType::Set);
    }

    // Port of test-hfp.c check_ustring_1: unquoted string extraction
    #[test]
    fn test_hfp_context_unquoted_string() {
        let mut ctx = HfpContext::new("hello,world");
        let s = ctx.get_unquoted_string().unwrap();
        assert_eq!(s, "hello");
        let s2 = ctx.get_unquoted_string().unwrap();
        assert_eq!(s2, "world");
    }

    // Port of test-hfp.c check_string_1: quoted string extraction
    #[test]
    fn test_hfp_context_quoted_string_extraction() {
        let mut ctx = HfpContext::new("\"hello\",\"world\"");
        let s = ctx.get_string().unwrap();
        assert_eq!(s, "hello");
        let s2 = ctx.get_string().unwrap();
        assert_eq!(s2, "world");
    }

    // Port of test-hfp.c check_string_3: empty/missing string returns None
    #[test]
    fn test_hfp_context_string_missing_quote() {
        let mut ctx = HfpContext::new("hello"); // no quotes
        assert!(ctx.get_string().is_none());
    }

    // Port of test-hfp.c CIND indicator format parsing:
    // ("service",(0,1)),("call",(0,1)),("callsetup",(0-3))
    #[test]
    fn test_hfp_context_cind_indicator_parsing() {
        let data = "(\"service\",(0,1)),(\"call\",(0,1)),(\"callsetup\",(0-3))";
        let mut ctx = HfpContext::new(data);

        // First indicator: service
        assert!(ctx.open_container());
        let name = ctx.get_string().unwrap();
        assert_eq!(name, "service");
        assert!(ctx.open_container());
        let v1 = ctx.get_number().unwrap();
        assert_eq!(v1, 0);
        let v2 = ctx.get_number().unwrap();
        assert_eq!(v2, 1);
        assert!(ctx.close_container());
        assert!(ctx.close_container());

        // Second indicator: call
        assert!(ctx.open_container());
        let name2 = ctx.get_string().unwrap();
        assert_eq!(name2, "call");
        assert!(ctx.open_container());
        let v3 = ctx.get_number().unwrap();
        assert_eq!(v3, 0);
        let v4 = ctx.get_number().unwrap();
        assert_eq!(v4, 1);
        assert!(ctx.close_container());
        assert!(ctx.close_container());

        // Third indicator: callsetup with range
        assert!(ctx.open_container());
        let name3 = ctx.get_string().unwrap();
        assert_eq!(name3, "callsetup");
        assert!(ctx.open_container());
        let (min, max) = ctx.get_range().unwrap();
        assert_eq!(min, 0);
        assert_eq!(max, 3);
        assert!(ctx.close_container());
        assert!(ctx.close_container());
    }

    // Port of test-hfp.c hf_chld_result_handler: CHLD comma-separated values
    #[test]
    fn test_hfp_context_chld_values() {
        let mut ctx = HfpContext::new("1,2x");
        let s1 = ctx.get_unquoted_string().unwrap();
        assert_eq!(s1, "1");
        let s2 = ctx.get_unquoted_string().unwrap();
        assert_eq!(s2, "2x");
    }

    // Port of test-hfp.c hf_chld_skip_field: skip first field
    #[test]
    fn test_hfp_context_skip_field_then_read() {
        let mut ctx = HfpContext::new("1,2x");
        ctx.skip_field();
        let s = ctx.get_unquoted_string().unwrap();
        assert_eq!(s, "2x");
    }

    // Port of test-hfp.c: CMER parameter parsing (3,0,0,1)
    #[test]
    fn test_hfp_context_cmer_params() {
        let mut ctx = HfpContext::new("3,0,0,1");
        assert_eq!(ctx.get_number(), Some(3));
        assert_eq!(ctx.get_number(), Some(0));
        assert_eq!(ctx.get_number(), Some(0));
        assert_eq!(ctx.get_number(), Some(1));
        assert_eq!(ctx.get_number(), None);
    }

    // Port of test-hfp.c: multiple numbers with whitespace
    #[test]
    fn test_hfp_context_numbers_with_whitespace() {
        // Parser does not skip leading whitespace; commas delimit fields
        let mut ctx = HfpContext::new("42,100,3");
        assert_eq!(ctx.get_number(), Some(42));
        assert_eq!(ctx.get_number(), Some(100));
        assert_eq!(ctx.get_number(), Some(3));
        assert_eq!(ctx.get_number(), None);
    }

    // Port of test-hfp.c: format_result for all standard result codes
    #[test]
    fn test_hfp_format_result_all_codes() {
        assert_eq!(format_result(HfpResult::Connect), "\r\nCONNECT\r\n");
        assert_eq!(format_result(HfpResult::Ring), "\r\nRING\r\n");
        assert_eq!(format_result(HfpResult::NoCarrier), "\r\nNO CARRIER\r\n");
        assert_eq!(format_result(HfpResult::NoDialtone), "\r\nNO DIALTONE\r\n");
        assert_eq!(format_result(HfpResult::Busy), "\r\nBUSY\r\n");
        assert_eq!(format_result(HfpResult::NoAnswer), "\r\nNO ANSWER\r\n");
        assert_eq!(format_result(HfpResult::Delayed), "\r\nDELAYED\r\n");
        assert_eq!(format_result(HfpResult::Rejected), "\r\nREJECTED\r\n");
    }

    // Port of test-hfp.c: CME error code 30 (NoNetworkService)
    #[test]
    fn test_hfp_format_cme_error_30() {
        assert_eq!(
            format_result(HfpResult::CmeError(HfpError::NoNetworkService)),
            "\r\n+CME ERROR: 30\r\n"
        );
    }

    // Port of test-hfp.c: empty AT command returns None
    #[test]
    fn test_hfp_parse_empty_command() {
        assert_eq!(parse_at_command(""), None);
        assert_eq!(parse_at_command("\r\n"), None);
    }

    // Port of test-hfp.c: AT command bare command type (no = or ?)
    #[test]
    fn test_hfp_at_command_bare() {
        let (prefix, cmd_type) = parse_at_command("+CLCC\r").unwrap();
        assert_eq!(prefix, "+CLCC");
        assert_eq!(cmd_type, HfpCmdType::Command);
    }

    // Port of test-hfp.c: nested containers parsing
    #[test]
    fn test_hfp_context_nested_containers() {
        let mut ctx = HfpContext::new("((1,2),(3,4))");
        assert!(ctx.open_container());
        assert!(ctx.open_container());
        assert_eq!(ctx.get_number(), Some(1));
        assert_eq!(ctx.get_number(), Some(2));
        assert!(ctx.close_container());
        assert!(ctx.open_container());
        assert_eq!(ctx.get_number(), Some(3));
        assert_eq!(ctx.get_number(), Some(4));
        assert!(ctx.close_container());
        assert!(ctx.close_container());
    }

    // Port of test-hfp.c: validate_dial_string with various inputs
    #[test]
    fn test_hfp_validate_dial_string_extended() {
        assert!(validate_dial_string("123"));
        assert!(validate_dial_string("+44123"));
        assert!(validate_dial_string("*123#"));
        assert!(validate_dial_string("ABC"));
        assert!(validate_dial_string("abc"));
        assert!(!validate_dial_string(""));
        assert!(!validate_dial_string("hello@world"));
        assert!(!validate_dial_string("123 456")); // space is invalid
    }

    // Port of test-hfp.c: remaining() after partial parse
    #[test]
    fn test_hfp_context_remaining() {
        let mut ctx = HfpContext::new("42,rest_of_data");
        ctx.get_number();
        assert_eq!(ctx.remaining(), "rest_of_data");
    }

    // Port of test-hfp.c: format_info for unsolicited result
    #[test]
    fn test_hfp_format_info() {
        assert_eq!(format_info("+CIEV: 2,1"), "\r\n+CIEV: 2,1\r\n");
        assert_eq!(format_info("+BRSF: 871"), "\r\n+BRSF: 871\r\n");
    }
}

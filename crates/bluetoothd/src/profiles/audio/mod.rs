//! Audio profile implementations (A2DP, AVRCP, BAP, etc.)
//!
//! Currently only the media player module is available. Other audio profile
//! modules (avdtp, avctp, transport, media, a2dp, avrcp, bap, bass, vcp, micp,
//! mcp, ccp, csip, tmap, gmap, sink, source, control, asha, hfp, telephony)
//! will be added by their respective implementation agents.

pub mod a2dp;
pub mod avctp;
pub mod avdtp;
pub mod avrcp;
pub mod ccp;
pub mod control;
pub mod csip;
pub mod gmap;
pub mod hfp;
pub mod media;
pub mod micp;
pub mod player;
pub mod sink;
pub mod source;
pub mod telephony;
pub mod tmap;
pub mod vcp;

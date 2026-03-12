// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2011-2014 Intel Corporation
// Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>

//! Protocol dissector submodules for the btmon packet monitor.
//!
//! Each submodule implements a complete protocol dissector that decodes
//! Bluetooth protocol layer packets into human-readable output. The L2CAP
//! dissector serves as the central routing hub, dispatching to other
//! dissectors based on CID and PSM values.

// Dissector sub-modules — uncommented as each implementation is created.
// pub mod l2cap;
// pub mod att;
// pub mod sdp;
pub mod rfcomm;
// pub mod bnep;
pub mod avctp;
// pub mod avdtp;
// pub mod a2dp;
pub mod ll;
// pub mod lmp;

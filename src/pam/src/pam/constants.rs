/*
   MIT License

   Copyright (c) 2015 TOZNY
   Copyright (c) 2020 William Brown <william@blackhats.net.au>
   Copyright (c) 2024 David Mulder <dmulder@samba.org>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
use libc::{c_int, c_uint};

pub type PamFlag = c_uint;
pub type PamItemType = c_int;
pub type PamMessageStyle = c_int;
pub type AlwaysZero = c_int;

// The Linux-PAM flags
// see /usr/include/security/_pam_types.h
pub const _PAM_SILENT: PamFlag = 0x8000;
pub const _PAM_DISALLOW_NULL_AUTHTOK: PamFlag = 0x0001;
pub const _PAM_ESTABLISH_CRED: PamFlag = 0x0002;
pub const _PAM_DELETE_CRED: PamFlag = 0x0004;
pub const _PAM_REINITIALIZE_CRED: PamFlag = 0x0008;
pub const _PAM_REFRESH_CRED: PamFlag = 0x0010;
pub const _PAM_CHANGE_EXPIRED_AUTHTOK: PamFlag = 0x0020;
// see /usr/include/security/pam_modules.h
pub const PAM_PRELIM_CHECK: PamFlag = 0x4000;
pub const PAM_UPDATE_AUTHTOK: PamFlag = 0x2000;

// The Linux-PAM item types
// see /usr/include/security/_pam_types.h
/// The service name
pub const PAM_SERVICE: PamItemType = 1;
/// The user name
pub const PAM_USER: PamItemType = 2;
/// The tty name
pub const PAM_TTY: PamItemType = 3;
/// The remote host name
pub const PAM_RHOST: PamItemType = 4;
/// The pam_conv structure
pub const PAM_CONV: PamItemType = 5;
/// The authentication token (password)
pub const PAM_AUTHTOK: PamItemType = 6;
/// The old authentication token
pub const PAM_OLDAUTHTOK: PamItemType = 7;
/// The remote user name
pub const PAM_RUSER: PamItemType = 8;
/// the prompt for getting a username
pub const PAM_USER_PROMPT: PamItemType = 9;
/* Linux-PAM :extensionsPamItemType = */
/// app supplied function to override failure delays
pub const _PAM_FAIL_DELAY: PamItemType = 10;
/// X :display name
pub const _PAM_XDISPLAY: PamItemType = 11;
/// X :server authentication data
pub const _PAM_XAUTHDATA: PamItemType = 12;
/// The type for pam_get_authtok
pub const _PAM_AUTHTOK_TYPE: PamItemType = 13;

// Message styles
pub const PAM_PROMPT_ECHO_OFF: PamMessageStyle = 1;
pub const PAM_PROMPT_ECHO_ON: PamMessageStyle = 2;
pub const PAM_ERROR_MSG: PamMessageStyle = 3;
pub const PAM_TEXT_INFO: PamMessageStyle = 4;
/// yes/no/maybe conditionals
pub const _PAM_RADIO_TYPE: PamMessageStyle = 5;
pub const _PAM_BINARY_PROMPT: PamMessageStyle = 7;

pub use himmelblau_unix_common::pam::PamResultCode;

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
//! Functions for use in pam modules.

use std::ffi::{CStr, CString};
use std::{mem, ptr};

use libc::c_char;

use crate::pam::constants::{PamFlag, PamItemType, PamResultCode};
use crate::pam::items::{PamAuthTok, PamRHost, PamService, PamTty};

/// Opaque type, used as a pointer when making pam API calls.
///
/// A module is invoked via an external function such as `pam_sm_authenticate`.
/// Such a call provides a pam handle pointer.  The same pointer should be given
/// as an argument when making API calls.
#[allow(missing_copy_implementations)]
pub enum PamHandle {}

#[allow(missing_copy_implementations)]
enum PamItemT {}

#[allow(missing_copy_implementations)]
pub enum PamDataT {}

#[link(name = "pam")]
extern "C" {
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: &mut *const PamDataT,
    ) -> PamResultCode;

    fn pam_set_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut PamDataT,
        cleanup: unsafe extern "C" fn(
            pamh: *const PamHandle,
            data: *mut PamDataT,
            error_status: PamResultCode,
        ),
    ) -> PamResultCode;

    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: PamItemType,
        item: &mut *const PamItemT,
    ) -> PamResultCode;

    fn pam_set_item(pamh: *mut PamHandle, item_type: PamItemType, item: &PamItemT)
        -> PamResultCode;

    fn pam_get_user(
        pamh: *const PamHandle,
        user: &mut *const c_char,
        prompt: *const c_char,
    ) -> PamResultCode;
}

/// # Safety
///
/// We're doing what we can for this one, but it's FFI.
pub unsafe extern "C" fn cleanup<T>(_: *const PamHandle, c_data: *mut PamDataT, _: PamResultCode) {
    let c_data = Box::from_raw(c_data);
    let data: Box<T> = mem::transmute(c_data);
    mem::drop(data);
}

pub type PamResult<T> = Result<T, PamResultCode>;

/// # Safety
///
/// Type-level mapping for safely retrieving values with `get_item`.
///
/// See `pam_get_item` in
/// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
pub trait PamItem {
    /// Maps a Rust type to a pam constant.
    ///
    /// For example, the type PamConv maps to the constant PAM_CONV.  The pam
    /// API contract specifies that when the API function `pam_get_item` is
    /// called with the constant PAM_CONV, it will return a value of type
    /// `PamConv`.
    fn item_type() -> PamItemType;
}

impl PamHandle {
    /// # Safety
    ///
    /// Gets some value, identified by `key`, that has been set by the module
    /// previously.
    ///
    /// See `pam_get_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    pub unsafe fn get_data<'a, T>(&'a self, key: &str) -> PamResult<&'a T> {
        let c_key = CString::new(key).unwrap();
        let mut ptr: *const PamDataT = ptr::null();
        let res = pam_get_data(self, c_key.as_ptr(), &mut ptr);
        if PamResultCode::PAM_SUCCESS == res && !ptr.is_null() {
            let typed_ptr: *const T = ptr as *const T;
            let data: &T = &*typed_ptr;
            Ok(data)
        } else {
            Err(res)
        }
    }

    /// Stores a value that can be retrieved later with `get_data`.  The value lives
    /// as long as the current pam cycle.
    ///
    /// See `pam_set_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    pub fn set_data<T>(&self, key: &str, data: Box<T>) -> PamResult<()> {
        let c_key = CString::new(key).unwrap();
        let res = unsafe {
            let c_data: Box<PamDataT> = mem::transmute(data);
            let c_data = Box::into_raw(c_data);
            pam_set_data(self, c_key.as_ptr(), c_data, cleanup::<T>)
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            Err(res)
        }
    }

    /// Retrieves a value that has been set, possibly by the pam client.  This is
    /// particularly useful for getting a `PamConv` reference.
    ///
    /// See `pam_get_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    pub fn get_item<'a, T: PamItem>(&self) -> PamResult<&'a T> {
        let mut ptr: *const PamItemT = ptr::null();
        let (res, item) = unsafe {
            let r = pam_get_item(self, T::item_type(), &mut ptr);
            let typed_ptr: *const T = ptr as *const T;
            let t: &T = &*typed_ptr;
            (r, t)
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(item)
        } else {
            Err(res)
        }
    }

    pub fn get_item_string<T: PamItem>(&self) -> PamResult<Option<String>> {
        let mut ptr: *const PamItemT = ptr::null();
        let (res, item) = unsafe {
            let r = pam_get_item(self, T::item_type(), &mut ptr);
            let t = if PamResultCode::PAM_SUCCESS == r && !ptr.is_null() {
                let typed_ptr: *const c_char = ptr as *const c_char;
                Some(CStr::from_ptr(typed_ptr).to_string_lossy().into_owned())
            } else {
                None
            };
            (r, t)
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(item)
        } else {
            Err(res)
        }
    }

    /// Sets a value in the pam context. The value can be retrieved using
    /// `get_item`.
    ///
    /// Note that all items are strings, except `PAM_CONV` and `PAM_FAIL_DELAY`.
    ///
    /// See `pam_set_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    pub fn set_item_str<T: PamItem>(&mut self, item: &str) -> PamResult<()> {
        let c_item = CString::new(item).unwrap();

        let res = unsafe {
            pam_set_item(
                self,
                T::item_type(),
                // unwrapping is okay here, as c_item will not be a NULL
                // pointer
                (c_item.as_ptr() as *const PamItemT).as_ref().unwrap(),
            )
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            Err(res)
        }
    }

    /// Retrieves the name of the user who is authenticating or logging in.
    ///
    /// This is really a specialization of `get_item`.
    ///
    /// See `pam_get_user` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    pub fn get_user(&self, prompt: Option<&str>) -> PamResult<String> {
        let mut ptr: *const c_char = ptr::null_mut();
        let res = match prompt {
            Some(p) => {
                let c_prompt = CString::new(p).unwrap();
                unsafe { pam_get_user(self, &mut ptr, c_prompt.as_ptr()) }
            }
            None => unsafe { pam_get_user(self, &mut ptr, ptr::null()) },
        };

        if PamResultCode::PAM_SUCCESS == res {
            if ptr.is_null() {
                Err(PamResultCode::PAM_AUTHINFO_UNAVAIL)
            } else {
                let bytes = unsafe { CStr::from_ptr(ptr).to_bytes() };
                String::from_utf8(bytes.to_vec()).map_err(|_| PamResultCode::PAM_CONV_ERR)
            }
        } else {
            Err(res)
        }
    }

    pub fn get_authtok(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamAuthTok>()
    }

    pub fn get_tty(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamTty>()
    }

    pub fn get_rhost(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamRHost>()
    }

    pub fn get_service(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamService>()
    }
}

/// Provides functions that are invoked by the entrypoints generated by the
/// [`pam_hooks!` macro](../macro.pam_hooks.html).
///
/// All of hooks are ignored by PAM dispatch by default given the default return value of `PAM_IGNORE`.
/// Override any functions that you want to handle with your module. See `man pam(3)`.
#[allow(unused_variables)]
pub trait PamHooks {
    /// This function performs the task of establishing whether the user is permitted to gain access at
    /// this time. It should be understood that the user has previously been validated by an
    /// authentication module. This function checks for other things. Such things might be: the time of
    /// day or the date, the terminal line, remote hostname, etc. This function may also determine
    /// things like the expiration on passwords, and respond that the user change it before continuing.
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is used to (re-)set the authentication token of the user.
    ///
    /// The PAM library calls this function twice in succession. The first time with
    /// PAM_PRELIM_CHECK and then, if the module does not return PAM_TRY_AGAIN, subsequently with
    /// PAM_UPDATE_AUTHTOK. It is only on the second call that the authorization token is
    /// (possibly) changed.
    fn sm_chauthtok(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to terminate a session.
    fn sm_close_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to commence a session.
    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of altering the credentials of the user with respect to the
    /// corresponding authorization scheme. Generally, an authentication module may have access to more
    /// information about a user than their authentication token. This function is used to make such
    /// information available to the application. It should only be called after the user has been
    /// authenticated but before a session has been established.
    fn sm_setcred(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}

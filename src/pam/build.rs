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
fn main() {
    // ignore errors here since older versions of pam do not ship the pkg-config `pam.pc` file.
    // Not setting anything here will fall back on just blindly linking with `-lpam`,
    // which will work on environments with libpam.so, but no pkg-config file.
    let _ = pkg_config::Config::new()
        .atleast_version("1.3.0")
        .probe("pam");
}

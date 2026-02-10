/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    fn qr_selection_js_test() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("src");
        test_path.push("qr-greeter@himmelblau-idm.org");
        test_path.push("qrselection.test.js");

        let status = Command::new("node")
            .arg(test_path)
            .status()
            .expect("failed to launch node");

        assert!(status.success(), "qrselection.test.js failed");
    }
}

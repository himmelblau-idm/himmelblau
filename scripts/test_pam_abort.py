"""Exercise shipped auth controls with real libpam and a private module/config.

Run on Linux with libpam headers and a C compiler. No host PAM files change.
"""
import ctypes
import ctypes.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PamAbortTests(unittest.TestCase):
    def test_shipped_controls_stop_abort_and_preserve_fallback(self):
        controls = []
        for path, pattern in [
            ("platform/debian/pam-config", r"\[success=end[^\]]+\]"),
            ("platform/opensuse/pam-config", r"Auth: auth\s+(\[[^\]]+\])"),
            ("nix/modules/himmelblau.nix", r"auth\.himmelblau = \{.*?control = \"([^\"]+)\""),
            ("src/cli/src/main.rs", r'"auth\\t(\[[^\]]+\])\\tpam_himmelblau'),
            ("platform/arch/himmelblau.install", r"print \"auth\s+(\[[^\]]+\]) pam_himmelblau"),
        ]:
            match = re.search(pattern, (ROOT / path).read_text(), re.S)
            self.assertIsNotNone(match, path)
            control = match[1] if match.lastindex else match[0]
            self.assertIn("abort=die", control, path)
            # pam-auth-update expands its special 'end' action when installing.
            controls.append((path, control.replace("success=end", "success=done")))

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "module.c"
            module = directory / "module.so"
            source.write_text('''
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
int pam_sm_authenticate(pam_handle_t *p, int flags, int argc, const char **argv) {
    if (argc > 1) { FILE *f = fopen(argv[1], "w"); if (f) fclose(f); }
    return argc ? atoi(argv[0]) : PAM_SUCCESS;
}
int pam_sm_setcred(pam_handle_t *p, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
''')
            subprocess.run(["cc", "-shared", "-fPIC", str(source), "-o", str(module)], check=True)
            pam = ctypes.CDLL(ctypes.util.find_library("pam"))
            class Conversation(ctypes.Structure):
                _fields_ = [("conv", ctypes.c_void_p), ("data", ctypes.c_void_p)]
            pam.pam_start_confdir.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                ctypes.POINTER(Conversation), ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
            pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
            pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
            marker = directory / "fallback"
            for path, control in controls:
                for result in [26, 25, 0]:  # PAM_ABORT, PAM_IGNORE, PAM_SUCCESS
                    with self.subTest(path=path, result=result):
                        marker.unlink(missing_ok=True)
                        if "default=2" in control:
                            # Arch's prelude skips keyring and return on ignore.
                            tail = f"auth optional {module} 0\nauth [default=done] {module} 0\n"
                        else:
                            tail = ""
                        (directory / "fixture").write_text(
                            f"auth {control} {module} {result}\n" + tail +
                            f"auth required {module} 0 {marker}\n")
                        handle = ctypes.c_void_p()
                        conv = Conversation()
                        self.assertEqual(pam.pam_start_confdir(b"fixture", b"test",
                            ctypes.byref(conv), str(directory).encode(), ctypes.byref(handle)), 0)
                        try:
                            status = pam.pam_authenticate(handle, 0)
                            self.assertEqual(status, 26 if result == 26 else 0)
                            self.assertEqual(marker.exists(), result == 25)
                        finally:
                            pam.pam_end(handle, 0)


if __name__ == "__main__":
    unittest.main()

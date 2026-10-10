"""Run HSM PIN initialization with fake credentials and isolated filesystem paths."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "src/daemon/scripts/himmelblau-init-hsm-pin"


class HsmPinInitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "private"
        self.data.mkdir()
        self.credential = self.data / "hsm-pin-nopcr.enc"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(mode=0o700)
        self.script = self.root / "init.sh"
        self.script.write_text(
            SCRIPT.read_text()
            .replace("/var/lib/private/himmelblaud", str(self.data))
            .replace("/run/himmelblau-hsm-pin", str(self.tmp))
            .replace("/dev/tpmrm0", str(self.root / "tpm"))
            .replace("/dev/tpm0", str(self.root / "tpm"))
        )
        self.helper("systemd-creds", """#!/usr/bin/python3
import os, pathlib, sys
mode = sys.argv[1]
source, dest = sys.argv[-2:]
if mode == 'decrypt' and os.environ.get('FAIL_DECRYPT'):
    sys.exit(1)
data = sys.stdin.buffer.read() if source == '-' else pathlib.Path(source).read_bytes()
if dest == '-':
    sys.stdout.buffer.write(data)
else:
    pathlib.Path(dest).write_bytes(data)
""")
        self.helper("stat", '''#!/bin/sh
if [ "$1" = -f ]; then
    if [ "${HSM_TEST_REAL_FS:-}" = 1 ]; then
        exec /usr/bin/stat "$@"
    fi
    printf '%s\n' "${HSM_TEST_FS:-tmpfs}"
elif [ "$1" = -c ] && [ "$2" = '%u:%g:%a' ]; then
    printf '%s\n' "${HSM_TEST_OWNER:-0:0:700}"
else
    exec /usr/bin/stat "$@"
fi
''')
        self.helper("tpm2_getcap", "#!/bin/sh\necho 0x81000001\n")
        self.helper("openssl", "#!/bin/sh\nprintf '%048d' 0\n")

    def helper(self, name, contents):
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)

    def run_init(self, **environment):
        result = subprocess.run(
            ["/bin/sh", str(self.script)],
            env={**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin",
                 "TMPDIR": str(self.tmp), **environment},
            capture_output=True,
        )
        self.assertEqual(list(self.tmp.iterdir()), [], "plaintext temporary file leaked")
        return result

    def test_binary_pin_survives_validation_and_tpm_upgrade(self):
        for tpm in [False, True]:
            with self.subTest(tpm=tpm):
                if tpm:
                    (self.root / "tpm").touch()
                value = b"\0" * 12 + b"\n" + b"\0" * 11 + b"\n\n"
                self.credential.write_bytes(value)
                result = self.run_init()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.credential.read_bytes(), value)

    def test_trailing_newline_padding_does_not_make_short_pin_valid(self):
        for tpm in [False, True]:
            for value in [b"x" * 23 + b"\n", b"\0" * 22 + b"\n\n", b"\n" * 24]:
                with self.subTest(tpm=tpm, value=value):
                    if tpm:
                        (self.root / "tpm").touch()
                    self.credential.write_bytes(value)
                    result = self.run_init()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.credential.read_bytes(), b"0" * 48)

    def test_decryption_failure_preserves_credential_and_aborts(self):
        self.credential.write_bytes(b"original credential")
        result = self.run_init(FAIL_DECRYPT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.credential.read_bytes(), b"original credential")

    def test_short_pin_is_replaced_and_generation_works_in_sh(self):
        self.credential.write_bytes(b"x" * 23)
        result = self.run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.credential.read_bytes(), b"0" * 48)

    def test_legacy_binary_pin_is_migrated_without_modification(self):
        value = b"\0" * 24 + b"\n"
        legacy = self.data / "hsm-pin"
        legacy.write_bytes(value)
        result = self.run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.credential.read_bytes(), value)
        self.assertFalse(legacy.exists())

    def test_inspection_failure_preserves_credential_and_aborts(self):
        for failure in ["exit 127", "printf '120 120 120\\n'; exit 1"]:
            with self.subTest(failure=failure):
                self.credential.write_bytes(b"x" * 24)
                self.helper("od", "#!/bin/sh\n" + failure + "\n")
                result = self.run_init()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.credential.read_bytes(), b"x" * 24)

    def test_term_exits_before_credential_replacement(self):
        self.credential.write_bytes(b"x" * 24)
        self.helper("systemd-creds", "#!/bin/sh\nkill -TERM \"$PPID\"\nprintf '%024d' 0\n")
        result = self.run_init()
        self.assertEqual(result.returncode, 143)
        self.assertEqual(self.credential.read_bytes(), b"x" * 24)

    @unittest.skipUnless(Path("/dev/shm").is_dir(), "requires a mounted runtime tmpfs")
    def test_actual_tmpfs_runtime_is_used_and_cleaned(self):
        with tempfile.TemporaryDirectory(dir="/dev/shm") as directory:
            runtime = Path(directory)
            self.script.write_text(self.script.read_text().replace(str(self.tmp), str(runtime)))
            self.credential.write_bytes(b"x" * 24)
            result = self.run_init(HSM_TEST_REAL_FS="1")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.credential.read_bytes(), b"x" * 24)
            self.assertEqual(list(runtime.iterdir()), [])

    def test_unsafe_runtime_ownership_or_mode_is_rejected(self):
        for owner in ["1000:1000:700", "0:0:755"]:
            with self.subTest(owner=owner):
                self.credential.write_bytes(b"x" * 24)
                result = self.run_init(HSM_TEST_OWNER=owner)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.credential.read_bytes(), b"x" * 24)

    def test_short_legacy_inputs_are_replaced(self):
        for filename in ["hsm-pin", "hsm-pin.enc"]:
            for value in [b"x" * 23, b"x" * 23 + b"\n", b"\n" * 24]:
                with self.subTest(filename=filename, value=value):
                    self.credential.write_bytes(b"short")
                    legacy = self.data / filename
                    legacy.write_bytes(value)
                    result = self.run_init()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.credential.read_bytes(), b"0" * 48)
                    self.assertFalse(legacy.exists())

    def test_valid_encrypted_legacy_pin_is_preserved(self):
        value = b"\0" * 24 + b"\n"
        legacy = self.data / "hsm-pin.enc"
        legacy.write_bytes(value)
        result = self.run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.credential.read_bytes(), value)
        self.assertFalse(legacy.exists())

    def test_persistent_runtime_filesystem_is_rejected(self):
        self.credential.write_bytes(b"x" * 24)
        result = self.run_init(HSM_TEST_FS="ext2/ext3")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.credential.read_bytes(), b"x" * 24)

    def test_short_encrypted_pin_uses_valid_legacy_pin(self):
        value = b"\0" * 24 + b"\n"
        legacy = self.data / "hsm-pin"
        legacy.write_bytes(value)
        self.credential.write_bytes(b"short")
        result = self.run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.credential.read_bytes(), value)
        self.assertFalse(legacy.exists())

    def test_generation_failure_aborts_without_creating_credential(self):
        self.helper("openssl", "#!/bin/sh\nexit 1\n")
        result = self.run_init()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.credential.exists())


if __name__ == "__main__":
    unittest.main()

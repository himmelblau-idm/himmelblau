"""Check that both extension formats and both package manifests retain the consumer QR."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest


CRATE = Path(__file__).resolve().parents[1]
EXT = "qr-greeter@himmelblau-idm.org"
IMAGE = "ms-consumer-dag.png"


class ConsumerQrAssetTests(unittest.TestCase):
    def test_build_outputs_and_package_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = root / "src/qr-greeter"
            shutil.copytree(CRATE, crate)
            executable = root / "build-script"
            prebuilt = os.environ.get("QR_BUILD_SCRIPT")
            if prebuilt:
                shutil.copy(prebuilt, executable)
            elif shutil.which("rustc"):
                subprocess.run(["rustc", "--edition=2021", str(crate / "build.rs"), "-o", str(executable)], check=True)
            else:
                self.skipTest("rustc or QR_BUILD_SCRIPT is required")
            original = (crate / "src" / IMAGE).read_bytes()
            for gnome in ("44", "45"):
                for cross in (False, True):
                    with self.subTest(gnome=gnome, cross=cross):
                        target = "aarch64-unknown-linux-gnu" if cross else "x86_64-unknown-linux-gnu"
                        env = {**os.environ, "CARGO_MANIFEST_DIR": str(crate), "GNOME_VERSION": gnome,
                               "HOST": "x86_64-unknown-linux-gnu", "TARGET": target}
                        subprocess.run([str(executable)], cwd=root, env=env, check=True, capture_output=True)
                        prefix = root / "target" / target / "release" if cross else root / "target/release"
                        output = prefix / "qr-greeter-build" / EXT
                        self.assertEqual((output / IMAGE).read_bytes(), original)
                        self.assertIn(IMAGE, (output / "extension.js").read_text())

            manifest = tomllib.loads((crate / "Cargo.toml").read_text())
            meta = manifest["package"]["metadata"]
            source = f"target/release/qr-greeter-build/{EXT}/{IMAGE}"
            dest = f"usr/share/gnome-shell/extensions/{EXT}/{IMAGE}"
            self.assertIn([source, dest, "644"], meta["deb"]["assets"])
            self.assertIn({"source": source, "dest": "/" + dest, "mode": "644"},
                          meta["generate-rpm"]["assets"])


if __name__ == "__main__":
    unittest.main()

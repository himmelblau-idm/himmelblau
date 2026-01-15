#!/usr/bin/env python3
"""
Transpile GNOME 45+ ESM extension.js to GNOME 40-44 legacy format.

This script converts modern ES module syntax to the legacy GJS import system
used in GNOME Shell 44 and earlier.
"""

import re
from pathlib import Path


def transpile_extension(source: str) -> str:
    """Convert extension.js from ESM to legacy format."""

    # Replace console.log/error with log() for legacy GJS compatibility
    source = re.sub(r'console\.log\(', 'log(', source)
    source = re.sub(r'console\.error\(', 'log(', source)

    lines = source.split('\n')
    output_lines = []

    # Track imports we need to add at the top
    gi_imports = []
    shell_imports = []
    local_imports = []

    skip_next_lines = 0
    in_class = False
    class_indent = 0
    enable_body = []
    disable_body = []
    current_method = None
    method_indent = 0
    brace_depth = 0

    for i, line in enumerate(lines):
        if skip_next_lines > 0:
            skip_next_lines -= 1
            continue

        # Convert GI imports: import X from 'gi://X' -> const X = imports.gi.X;
        gi_match = re.match(r"import\s+(\w+)\s+from\s+'gi://(\w+)';?", line)
        if gi_match:
            var_name, module_name = gi_match.groups()
            gi_imports.append(f"const {var_name} = imports.gi.{module_name};")
            continue

        # Skip Extension import (not needed in legacy)
        if "from 'resource:///org/gnome/shell/extensions/extension.js'" in line:
            continue

        # Convert shell imports: import * as X from 'resource:///org/gnome/shell/...'
        shell_match = re.match(
            r"import\s+\*\s+as\s+(\w+)\s+from\s+'resource:///org/gnome/shell/(.+?)\.js';?",
            line
        )
        if shell_match:
            var_name, path = shell_match.groups()
            # Convert path: gdm/authPrompt -> gdm.authPrompt
            import_path = path.replace('/', '.')
            shell_imports.append(f"const {var_name} = imports.{import_path};")
            continue

        # Convert local imports: import { X, Y } from './module.js'
        local_match = re.match(
            r"import\s+\{\s*(.+?)\s*\}\s+from\s+'\.\/(\w+)\.js';?",
            line
        )
        if local_match:
            imports, module_name = local_match.groups()
            import_vars = [v.strip() for v in imports.split(',')]
            # We'll handle this specially - qrcodegen exports to a global
            local_imports.append(
                f"const Me = imports.misc.extensionUtils.getCurrentExtension();"
            )
            for var in import_vars:
                local_imports.append(f"const {var} = Me.imports.{module_name}.{var};")
            continue

        # Detect class definition
        if re.match(r'export\s+default\s+class\s+\w+\s+extends\s+Extension\s*\{', line):
            in_class = True
            class_indent = len(line) - len(line.lstrip())
            continue

        if in_class:
            # Detect enable() method
            enable_match = re.match(r'(\s*)enable\s*\(\s*\)\s*\{', line)
            if enable_match:
                current_method = 'enable'
                method_indent = len(enable_match.group(1))
                brace_depth = 1
                continue

            # Detect disable() method
            disable_match = re.match(r'(\s*)disable\s*\(\s*\)\s*\{', line)
            if disable_match:
                current_method = 'disable'
                method_indent = len(disable_match.group(1))
                brace_depth = 1
                continue

            # Track method body
            if current_method:
                # Count braces to track method end
                brace_depth += line.count('{') - line.count('}')

                if brace_depth <= 0:
                    current_method = None
                    continue

                # Add line to appropriate method body
                # Remove one level of indentation
                stripped = line
                if len(line) > method_indent + 4:
                    stripped = line[4:]  # Remove 4 spaces of indentation

                if current_method == 'enable':
                    enable_body.append(stripped)
                elif current_method == 'disable':
                    disable_body.append(stripped)
                continue

            # End of class
            if line.strip() == '}' and not current_method:
                in_class = False
                continue

            continue

        # Keep other lines as-is
        output_lines.append(line)

    # Build the output file
    result = []

    # Add legacy imports at the top
    result.append("// GNOME 40-44 Legacy Format (auto-generated)")
    result.append("// Do not edit - modify extension.js and run transpile-legacy.py")
    result.append("")

    for imp in gi_imports:
        result.append(imp)

    if shell_imports:
        result.append("")
        for imp in shell_imports:
            result.append(imp)

    if local_imports:
        result.append("")
        # Deduplicate Me import
        seen = set()
        for imp in local_imports:
            if imp not in seen:
                result.append(imp)
                seen.add(imp)

    result.append("")

    # Add the rest of the module-level code
    for line in output_lines:
        result.append(line)

    # Add state variable for the extension
    result.append("")
    result.append("// Extension state")
    result.append("let _originalSetMessage = null;")
    result.append("")

    # Add enable function
    result.append("function enable() {")
    for line in enable_body:
        # Replace this._originalSetMessage with _originalSetMessage
        line = line.replace('this._originalSetMessage', '_originalSetMessage')
        result.append(line)
    result.append("}")
    result.append("")

    # Add disable function
    result.append("function disable() {")
    for line in disable_body:
        line = line.replace('this._originalSetMessage', '_originalSetMessage')
        result.append(line)
    result.append("}")

    return '\n'.join(result)


def main():
    script_dir = Path(__file__).parent
    src_dir = script_dir.parent / "src" / "qr-greeter@himmelblau-idm.org"

    # Output to ./target/release/qr-greeter-legacy/ to avoid polluting source tree
    # and to match cargo-deb expected paths
    project_root = script_dir.parent.parent.parent
    legacy_dir = project_root / "target" / "release" / "qr-greeter-legacy" / "qr-greeter@himmelblau-idm.org"

    # Create legacy directory if it doesn't exist
    legacy_dir.mkdir(parents=True, exist_ok=True)

    # Transpile extension.js
    extension_src = src_dir / "extension.js"
    extension_dst = legacy_dir / "extension.js"

    print(f"Transpiling {extension_src} -> {extension_dst}")
    with open(extension_src, 'r') as f:
        source = f.read()

    transpiled = transpile_extension(source)
    with open(extension_dst, 'w') as f:
        f.write(transpiled)

    # Copy stylesheet.css (no changes needed)
    import shutil
    css_src = src_dir / "stylesheet.css"
    css_dst = legacy_dir / "stylesheet.css"
    print(f"Copying {css_src} -> {css_dst}")
    shutil.copy(css_src, css_dst)

    # Copy PNG assets from the src directory (sibling to extension dir)
    png_src_dir = src_dir.parent
    for png_file in ["msdag.png", "ms-consumer-dag.png"]:
        png_src = png_src_dir / png_file
        png_dst = legacy_dir / png_file
        if png_src.exists():
            print(f"Copying {png_src} -> {png_dst}")
            shutil.copy(png_src, png_dst)

    # Create legacy metadata.json
    metadata_dst = legacy_dir / "metadata.json"
    print(f"Creating {metadata_dst}")
    metadata = """{
  "uuid": "qr-greeter@himmelblau-idm.org",
  "name": "Himmelblau QR Greeter",
  "description": "Adds a QR code to authentication prompts when a URL is detected.",
  "version": 1,
  "shell-version": ["40", "41", "42", "43", "44"],
  "session-modes": ["gdm"],
  "donations": { "opencollective" : "himmelblau" }
}
"""
    with open(metadata_dst, 'w') as f:
        f.write(metadata)

    print("Done!")
    print(f"Legacy extension created in: {legacy_dir}")


if __name__ == "__main__":
    main()

import St from 'gi://St';
import Clutter from 'gi://Clutter';
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import * as AuthPromptModule from 'resource:///org/gnome/shell/gdm/authPrompt.js';
import { QrCode, Ecc } from './qrcodegen.js';

const GdmAuthPrompt = AuthPromptModule.AuthPrompt;

// Track active temp files for cleanup
let activeTotpTempFiles = new Set();

// Regex to match TOTP setup messages
const TOTP_SETUP_RE = /Enter the setup key '([^']+)'.*Use '([^']+)'.*'([^']+)' as the label\/name\./s;

// Generate SVG content from a QR code
function qrCodeToSvg(qr, border, lightColor, darkColor) {
    const size = qr.size + border * 2;
    let svg = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    svg += `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size * 4}" height="${size * 4}">`;
    svg += `<rect width="100%" height="100%" fill="${lightColor}"/>`;
    svg += `<path d="`;
    for (let y = 0; y < qr.size; y++) {
        for (let x = 0; x < qr.size; x++) {
            if (qr.getModule(x, y)) {
                svg += `M${x + border},${y + border}h1v1h-1z`;
            }
        }
    }
    svg += `" fill="${darkColor}"/>`;
    svg += `</svg>`;
    return svg;
}

// Write SVG to a temporary file with restrictive permissions and return the file path
function writeSvgToTempFile(svgContent) {
    const tempDir = GLib.get_tmp_dir();
    const tempPath = GLib.build_filenamev([tempDir, `himmelblau-totp-qr-${GLib.get_monotonic_time()}.svg`]);
    const file = Gio.File.new_for_path(tempPath);
    // Create file with restrictive permissions (0600 - owner read/write only)
    const outputStream = file.replace(null, false, Gio.FileCreateFlags.PRIVATE, null);
    const bytes = new TextEncoder().encode(svgContent);
    outputStream.write_all(bytes, null);
    outputStream.close(null);
    return tempPath;
}

// Delete a temporary file if it exists
function deleteTempFile(filePath) {
    if (!filePath) return;
    try {
        const file = Gio.File.new_for_path(filePath);
        if (file.query_exists(null)) {
            file.delete(null);
        }
        activeTotpTempFiles.delete(filePath);
    } catch (e) {
        console.error("Himmelblau QR Greeter: Failed to delete temp file:", e);
    }
}

// Clean up all tracked temp files
function cleanupAllTempFiles() {
    for (const filePath of activeTotpTempFiles) {
        deleteTempFile(filePath);
    }
    activeTotpTempFiles.clear();
}

// Build a TOTP URI for authenticator apps
function buildTotpUri(secret, issuer, label) {
    const encodedIssuer = encodeURIComponent(issuer);
    const encodedLabel = encodeURIComponent(label);
    return `otpauth://totp/${encodedIssuer}:${encodedLabel}?secret=${secret}&issuer=${encodedIssuer}`;
}

export default class QrGreeterExtension extends Extension {
    enable() {
        console.log("Himmelblau QR Greeter: enabled...");

        if (!GdmAuthPrompt) {
            console.error("Himmelblau QR Greeter: GdmAuthPrompt is unavailable.");
            return;
        }

        this._originalSetMessage = GdmAuthPrompt.prototype.setMessage;
        const origSetMessage = this._originalSetMessage;

        GdmAuthPrompt.prototype.setMessage = function(message, styleClass) {
            origSetMessage.call(this, message, styleClass);

            if (this._message) {
                this._message.clutter_text.line_wrap = true;
                this._message.set_width(350);
                this._message.set_x_expand(false);
                this._message.set_x_align(Clutter.ActorAlign.CENTER);
            }

            if (!this._qrVBox) {
                const parent = this._message.get_parent();
                parent.remove_child(this._message);

                const vbox = new St.BoxLayout({
                    vertical: true,
                    x_expand: false,
                    y_expand: false,
                    x_align: Clutter.ActorAlign.CENTER,
                    style_class: 'qr-vbox'
                });
                this._qrVBox = vbox;

                vbox.add_child(this._message);

                const qrContainer = new St.Widget({
                    style_class: 'qr-code-container',
                    x_expand: false,
                    y_expand: false,
                    x_align: Clutter.ActorAlign.CENTER
                });
                this._qrContainer = qrContainer;
                vbox.add_child(qrContainer);

                const qrLabel = new St.Label({
                    text: "Scan with your phone",
                    style_class: 'qr-instruction-label'
                });
                this._qrLabel = qrLabel;
                vbox.add_child(qrLabel);

                parent.add_child(vbox);
            }

            // Clean up any previous TOTP temp file
            if (this._totpTempFile) {
                deleteTempFile(this._totpTempFile);
                this._totpTempFile = null;
            }

            const targetUrl = "https://microsoft.com/devicelogin";
            const consumerTargetUrl = "https://www.microsoft.com/link";
            const totpMatch = message ? TOTP_SETUP_RE.exec(message) : null;

            if (totpMatch) {
                // Extract TOTP setup information
                const secretB32 = totpMatch[1];
                const issuer = totpMatch[2];
                const label = totpMatch[3];

                // Build TOTP URI and generate QR code
                const totpUri = buildTotpUri(secretB32, issuer, label);

                try {
                    const qr = QrCode.encodeText(totpUri, Ecc.MEDIUM);
                    const svgContent = qrCodeToSvg(qr, 2, '#ffffff', '#000000');
                    const tempFilePath = writeSvgToTempFile(svgContent);
                    this._totpTempFile = tempFilePath; // Track for cleanup on this instance
                    activeTotpTempFiles.add(tempFilePath); // Track globally for extension disable
                    const fileUri = `file://${tempFilePath}`;
                    this._qrContainer.set_style(`background-image: url('${fileUri}'); background-size: contain; background-repeat: no-repeat; background-position: center;`);
                    this._qrContainer.show();
                    this._qrLabel.set_text("Scan to set up Hello TOTP");
                    this._qrLabel.show();
                    // Replace the verbose message with a simple instruction
                    if (this._message) {
                        this._message.set_text("Open your Authenticator app and scan this QR code to enroll. Then enter the code below.");
                    }
                } catch (e) {
                    console.error("Himmelblau QR Greeter: Failed to generate TOTP QR code:", e);
                    if (this._qrContainer) this._qrContainer.hide();
                    if (this._qrLabel) this._qrLabel.hide();
                }
            } else if (message && message.includes(targetUrl)) {
                const fileUri = "file:///usr/share/gnome-shell/extensions/qr-greeter@himmelblau-idm.org/msdag.png";
                this._qrContainer.set_style(`background-image: url('${fileUri}');`);
                this._qrContainer.show();
                this._qrLabel.set_text("Scan with your phone");
                this._qrLabel.show();
            } else if (message && message.includes(consumerTargetUrl)) {
                const fileUri = "file:///usr/share/gnome-shell/extensions/qr-greeter@himmelblau-idm.org/ms-consumer-dag.png";
                this._qrContainer.set_style(`background-image: url('${fileUri}');`);
                this._qrContainer.show();
                this._qrLabel.set_text("Scan with your phone");
                this._qrLabel.show();
            } else {
                if (this._qrContainer) this._qrContainer.hide();
                if (this._qrLabel) this._qrLabel.hide();
            }
        };

        console.log("Himmelblau QR Greeter: GdmAuthPrompt.setMessage patched.");
    }

    disable() {
        console.log("Himmelblau QR Greeter: disabled...");
        // Clean up any remaining temp files
        cleanupAllTempFiles();
        if (GdmAuthPrompt && this._originalSetMessage) {
            GdmAuthPrompt.prototype.setMessage = this._originalSetMessage;
        }
    }
}

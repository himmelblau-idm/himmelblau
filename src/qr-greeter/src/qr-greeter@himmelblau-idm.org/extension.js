import St from 'gi://St';
import Clutter from 'gi://Clutter';
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import * as AuthPromptModule from 'resource:///org/gnome/shell/gdm/authPrompt.js';
import { QrCode, Ecc } from './qrcodegen.js';
import { selectDeviceFlowUrl, URL_RE } from './qrselection.js';

const GdmAuthPrompt = AuthPromptModule.AuthPrompt;

// Track active temp files for cleanup
let activeTotpTempFiles = new Set();

// Regex to match TOTP setup messages
const TOTP_SETUP_RE = /Enter the setup key '([^']+)'.*Use '([^']+)'.*'([^']+)' as the label\/name\./s;

// Known URLs that have static QR code images
const STATIC_QR_URLS = {
    'https://microsoft.com/devicelogin': 'msdag.png',
    'https://www.microsoft.com/link': 'ms-consumer-dag.png',
};

// Maximum URL length for QR code generation (longer URLs create denser, harder to scan codes)
const MAX_URL_LENGTH = 500;

// Validate and normalize a URL for QR code generation
function validateUrl(urlString) {
    if (!urlString || urlString.length > MAX_URL_LENGTH) {
        return null;
    }

    try {
        // Use GLib.Uri for proper URL parsing and validation
        const uri = GLib.Uri.parse(urlString, GLib.UriFlags.NONE);

        // Ensure we have a valid scheme and host
        const scheme = uri.get_scheme();
        const host = uri.get_host();

        if (!scheme || !host || (scheme !== 'http' && scheme !== 'https')) {
            return null;
        }

        // Return the normalized URL string
        return uri.to_string();
    } catch (e) {
        console.error("Himmelblau QR Greeter: Invalid URL:", e);
        return null;
    }
}

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
    let outputStream = null;
    try {
        // Create file with restrictive permissions (0600 - owner read/write only)
        outputStream = file.replace(null, false, Gio.FileCreateFlags.PRIVATE, null);
        const bytes = new TextEncoder().encode(svgContent);
        outputStream.write_all(bytes, null);
        outputStream.close(null);
        return tempPath;
    } catch (e) {
        console.error("Himmelblau QR Greeter: Failed to write SVG to temp file:", e);
        // Best-effort close of the stream if it was opened
        if (outputStream) {
            try {
                outputStream.close(null);
            } catch (closeError) {
                console.error("Himmelblau QR Greeter: Additionally failed to close output stream:", closeError);
            }
        }
        // Best-effort cleanup of any partially created file
        try {
            if (file.query_exists(null)) {
                file.delete(null);
            }
        } catch (deleteError) {
            console.error("Himmelblau QR Greeter: Additionally failed to delete incomplete temp file:", deleteError);
        }
        throw e;
    }
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
    return `otpauth://totp/${encodedIssuer}:${encodedLabel}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
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
            } else {
                // Check for URLs in the message
                let qrDisplayed = false;

                if (message) {
                    // First check for known URLs with static QR codes
                    for (const [url, pngFile] of Object.entries(STATIC_QR_URLS)) {
                        if (message.includes(url)) {
                            const fileUri = `file:///usr/share/gnome-shell/extensions/qr-greeter@himmelblau-idm.org/${pngFile}`;
                            this._qrContainer.set_style(`background-image: url('${fileUri}');`);
                            this._qrContainer.show();
                            this._qrLabel.set_text("Scan with your phone");
                            this._qrLabel.show();
                            qrDisplayed = true;
                            break;
                        }
                    }

                    // If no static QR was displayed, check for any other URLs
                    if (!qrDisplayed) {
                        // Reset the regex lastIndex to ensure fresh matching
                        URL_RE.lastIndex = 0;
                        const urlMatches = message.match(URL_RE) || [];
                        const dynamicUrls = urlMatches.filter(url => {
                            for (const staticUrl of Object.keys(STATIC_QR_URLS)) {
                                if (url.startsWith(staticUrl)) {
                                    return false;
                                }
                            }
                            return true;
                        });
                        const selection = selectDeviceFlowUrl('', {
                            urls: dynamicUrls,
                            validateUrl,
                        });

                        if (dynamicUrls.length > 0 && selection.url) {
                            try {
                                const qr = QrCode.encodeText(selection.url, Ecc.MEDIUM);
                                const svgContent = qrCodeToSvg(qr, 2, '#ffffff', '#000000');
                                const tempFilePath = writeSvgToTempFile(svgContent);
                                this._totpTempFile = tempFilePath;
                                activeTotpTempFiles.add(tempFilePath);
                                const fileUri = `file://${tempFilePath}`;
                                this._qrContainer.set_style(`background-image: url('${fileUri}'); background-size: contain; background-repeat: no-repeat; background-position: center;`);
                                this._qrContainer.show();
                                if (selection.usedComplete) {
                                    this._qrLabel.set_text("Scan to continue sign-in");
                                } else {
                                    this._qrLabel.set_text("Scan with your phone");
                                }
                                this._qrLabel.show();
                                qrDisplayed = true;
                            } catch (e) {
                                console.error("Himmelblau QR Greeter: Failed to generate QR code for URL:", e);
                            }
                        }
                    }
                }

                if (!qrDisplayed) {
                    if (this._qrContainer) this._qrContainer.hide();
                    if (this._qrLabel) this._qrLabel.hide();
                }
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

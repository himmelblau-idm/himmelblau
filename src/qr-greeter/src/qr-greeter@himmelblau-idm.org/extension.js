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

// Must match the prefix used in src/common/src/auth.rs fido_status_check()
const FIDO_TOUCH_PREFIX = "[FIDO_TOUCH] ";

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

// Extract user_code from a device flow message.
// Handles: bare 9-char codes (e.g. "E9Y6JX8J7"), hyphenated codes (e.g. "ABCD-EFGH"),
// and URL query params (?user_code=...).
// Returns null if not found.
function extractUserCode(message) {
    if (!message) return null;
    // Match user_code parameter in URL query string
    const urlMatch = message.match(/[?&]user_code=([A-Z0-9-]+)/i);
    if (urlMatch) return urlMatch[1].toUpperCase();
    // Match "enter the code XXXXXXXXX" sentence format (Microsoft typically sends
    // 9-char codes with no hyphen, e.g. "enter the code E9Y6JX8J7 to authenticate";
    // range 6-12 is intentionally broader for forward compatibility)
    const sentenceMatch = message.match(/enter the code\s+([A-Z0-9-]{6,12})/i);
    if (sentenceMatch) return sentenceMatch[1].toUpperCase();
    // Match hyphenated code pattern (e.g. "ABCD-EFGH") - other providers
    const hyphenMatch = message.match(/\b([A-Z0-9]{4,5}-[A-Z0-9]{4,5})\b/i);
    if (hyphenMatch) return hyphenMatch[1].toUpperCase();
    // Fallback: bare 8-9 char alphanumeric word
    // userCode only contains [A-Z0-9-] so it is safe to embed directly in SVG
    // text nodes (no XML special characters can appear from this regex)
    const bareMatch = message.match(/\b([A-Z0-9]{8,9})\b/i);
    if (bareMatch) return bareMatch[1].toUpperCase();
    return null;
}

// Generate SVG content from a QR code, with an optional user code overlay
// rendered as a dark strip appended below the QR code (including its border /
// quiet-zone), so the QR modules and their quiet-zone remain unchanged for scanning.
function qrCodeToSvg(qr, border, lightColor, darkColor, userCode = null) {
    const qrSize = qr.size + border * 2;
    // 6 extra SVG units give ~15 rendered px at typical scale - comfortably readable.
    // 0 when no user code is needed (TOTP enrollment QR).
    const labelRows = userCode ? 6 : 0;
    const totalHeight = qrSize + labelRows;
    let svg = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    svg += `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${qrSize} ${totalHeight}" width="${qrSize * 4}" height="${totalHeight * 4}">`;
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
    if (userCode) {
        const stripY = qrSize;
        const stripH = labelRows;
        // Dark background strip appended below the QR code
        svg += `<rect x="0" y="${stripY}" width="${qrSize}" height="${stripH}" fill="${darkColor}"/>`;
        // Centered white monospace text.
        // 0.65: font-size as fraction of strip height - fills ~65% leaving breathing room.
        // 0.72: text baseline position within the strip - visually centered with descender space.
        const fontSize = stripH * 0.65;
        svg += `<text x="${qrSize / 2}" y="${stripY + stripH * 0.72}" `;
        svg += `font-family="monospace" font-size="${fontSize}" font-weight="bold" `;
        svg += `fill="${lightColor}" text-anchor="middle">`;
        // userCode only contains [A-Z0-9-] (guaranteed by extractUserCode regex),
        // so no XML entity escaping is needed here.
        svg += userCode;
        svg += `</text>`;
    }
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

export default class QrGreeterExtension extends Extension {
    enable() {
        console.log("Himmelblau QR Greeter: enabled...");

        if (!GdmAuthPrompt) {
            console.error("Himmelblau QR Greeter: GdmAuthPrompt is unavailable.");
            return;
        }

        this._originalSetMessage = GdmAuthPrompt.prototype.setMessage;
        const origSetMessage = this._originalSetMessage;
        const extensionPath = this.path;

        GdmAuthPrompt.prototype.setMessage = function(message, styleClass) {
            origSetMessage.call(this, message, styleClass);

            if (this._message) {
                this._message.clutter_text.line_wrap = true;
                this._message.clutter_text.set_line_alignment(1);
                this._message.set_width(500);
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

            if (message && message.startsWith(FIDO_TOUCH_PREFIX)) {
                if (this._message) {
                    this._message.set_text(message.substring(FIDO_TOUCH_PREFIX.length));
                    this._message.set_width(-1);
                    this._message.set_x_expand(true);
                    this._message.set_x_align(Clutter.ActorAlign.CENTER);
                }
                if (!this._fidoIcon) {
                    const svgPath = GLib.build_filenamev([extensionPath, 'security-key.svg']);
                    const touchSvgPath = GLib.build_filenamev([extensionPath, 'security-key-touch.svg']);

                    const container = new St.Widget({
                        width: 160,
                        height: 80,
                        x_align: Clutter.ActorAlign.CENTER,
                    });

                    const baseLayer = new St.Widget({
                        width: 160,
                        height: 80,
                        style: `background-image: url('file://${svgPath}'); background-size: contain; background-repeat: no-repeat; background-position: center;`,
                    });

                    const touchLayer = new St.Widget({
                        width: 160,
                        height: 80,
                        opacity: 0,
                        style: `background-image: url('file://${touchSvgPath}'); background-size: contain; background-repeat: no-repeat; background-position: center;`,
                    });

                    container.add_child(baseLayer);
                    container.add_child(touchLayer);
                    this._fidoIcon = container;
                    this._fidoTouchLayer = touchLayer;
                    this._qrVBox.insert_child_below(this._fidoIcon, this._message);

                }
                if (this._fidoPulseTimer) {
                    GLib.source_remove(this._fidoPulseTimer);
                    this._fidoPulseTimer = null;
                }
                this._fidoTouchLayer.opacity = 0;
                this._fidoPulseUp = true;
                this._fidoPulseTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 300, () => {
                    if (!this._fidoTouchLayer) return GLib.SOURCE_REMOVE;
                    const current = this._fidoTouchLayer.opacity;
                    if (this._fidoPulseUp) {
                        this._fidoTouchLayer.opacity = Math.min(current + 32, 255);
                        if (this._fidoTouchLayer.opacity >= 255) this._fidoPulseUp = false;
                    } else {
                        this._fidoTouchLayer.opacity = Math.max(current - 32, 0);
                        if (this._fidoTouchLayer.opacity <= 0) this._fidoPulseUp = true;
                    }
                    return GLib.SOURCE_CONTINUE;
                });
                this._fidoIcon.show();
                if (this._qrContainer) this._qrContainer.hide();
                if (this._qrLabel) this._qrLabel.hide();
                return;
            }

            if (this._fidoIcon) {
                this._fidoIcon.hide();
                if (this._fidoPulseTimer) {
                    GLib.source_remove(this._fidoPulseTimer);
                    this._fidoPulseTimer = null;
                }
            }

            const totpMatch = message ? message.startsWith("otpauth://") : null;
            if (totpMatch) {
                try {
                    const qr = QrCode.encodeText(message, Ecc.MEDIUM);
                    const svgContent = qrCodeToSvg(qr, 2, '#ffffff', '#000000');
                    const tempFilePath = writeSvgToTempFile(svgContent);
                    this._totpTempFile = tempFilePath; // Track for cleanup on this instance
                    activeTotpTempFiles.add(tempFilePath); // Track globally for extension disable
                    const fileUri = `file://${tempFilePath}`;
                    this._qrContainer.set_style(`background-image: url('${fileUri}'); background-size: contain; background-repeat: no-repeat; background-position: center;`);
                    this._qrContainer.show();
                    this._qrLabel.set_text("Scan with your phone to set up Hello TOTP");
                    this._qrLabel.show();
                    // Replace the verbose message with a simple instruction
                    if (this._message) {
                        this._message.set_text("Open your authenticator app and scan this QR code to enroll. Then enter the generated code.");
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
                    // Reset the regex lastIndex to ensure fresh matching
                    URL_RE.lastIndex = 0;
                    const urls = message.match(URL_RE) || [];
                    const selection = selectDeviceFlowUrl('', {
                        urls,
                        validateUrl,
                    });

                    if (urls.length > 0 && selection.url) {
                        try {
                            const userCode = extractUserCode(message);
                            const qr = QrCode.encodeText(selection.url, Ecc.MEDIUM);
                            const svgContent = qrCodeToSvg(qr, 2, '#ffffff', '#000000', userCode);
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
        if (this._fidoPulseTimer) {
            GLib.source_remove(this._fidoPulseTimer);
            this._fidoPulseTimer = null;
        }
        this._fidoIcon = null;
        this._fidoTouchLayer = null;
        if (GdmAuthPrompt && this._originalSetMessage) {
            GdmAuthPrompt.prototype.setMessage = this._originalSetMessage;
        }
    }
}

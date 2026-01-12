import St from 'gi://St';
import Clutter from 'gi://Clutter';
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import * as AuthPromptModule from 'resource:///org/gnome/shell/gdm/authPrompt.js';
import { QrCode, Ecc } from './qrcodegen.js';
import { getBrowserService } from './browser-service.js';
import { VncWidget } from './vnc-widget.js';

const GdmAuthPrompt = AuthPromptModule.AuthPrompt;

// Track active temp files for cleanup
let activeTotpTempFiles = new Set();

// Cached browser service availability (checked once at startup)
let browserServiceAvailable = null;
let browserServiceChecked = false;

// Regex to match TOTP setup messages
const TOTP_SETUP_RE = /Enter the setup key '([^']+)'.*Use '([^']+)'.*'([^']+)' as the label\/name\./s;

// Regex to match URLs in messages (excluding known static-QR URLs)
const URL_RE = /https?:\/\/[^\s<>"')\]]+/g;

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

// Check if embedded browser service is available (cached)
async function checkBrowserServiceAvailable() {
    if (browserServiceChecked) {
        return browserServiceAvailable;
    }

    try {
        const service = getBrowserService();
        browserServiceAvailable = await service.isAvailable();
    } catch (e) {
        console.log("Himmelblau QR Greeter: Browser service check failed:", e.message);
        browserServiceAvailable = false;
    }

    browserServiceChecked = true;
    return browserServiceAvailable;
}

// Show embedded browser for URL authentication
async function showEmbeddedBrowser(authPrompt, url) {
    try {
        const service = getBrowserService();
        const session = await service.startSession(url);

        // Create VNC widget if it doesn't exist
        if (!authPrompt._vncWidget) {
            authPrompt._vncWidget = new VncWidget({
                x_expand: false,
                y_expand: false,
                x_align: Clutter.ActorAlign.CENTER
            });

            // Handle session completion
            authPrompt._vncWidget.connect('session-completed', () => {
                console.log("Himmelblau QR Greeter: Browser session completed");
                hideEmbeddedBrowser(authPrompt);
            });

            authPrompt._vncWidget.connect('session-failed', (widget, reason) => {
                console.log(`Himmelblau QR Greeter: Browser session failed: ${reason}`);
                hideEmbeddedBrowser(authPrompt);
                // Fall back to QR code
                showQrCode(authPrompt, url);
            });

            authPrompt._vncWidget.connect('session-error', (widget, error) => {
                console.error(`Himmelblau QR Greeter: Browser session error: ${error}`);
                hideEmbeddedBrowser(authPrompt);
                // Fall back to QR code
                showQrCode(authPrompt, url);
            });

            authPrompt._qrVBox.add_child(authPrompt._vncWidget);
        }

        // Hide QR elements, show browser
        if (authPrompt._qrContainer) authPrompt._qrContainer.hide();
        if (authPrompt._qrLabel) authPrompt._qrLabel.hide();
        authPrompt._vncWidget.show();
        authPrompt._vncWidget.startSession(session);

        // Update message
        if (authPrompt._message) {
            authPrompt._message.set_text("Complete authentication in the browser below");
        }

        return true;
    } catch (e) {
        console.error("Himmelblau QR Greeter: Failed to start embedded browser:", e.message);
        return false;
    }
}

// Hide embedded browser
function hideEmbeddedBrowser(authPrompt) {
    if (authPrompt._vncWidget) {
        authPrompt._vncWidget.stopSession();
        authPrompt._vncWidget.hide();
    }
}

// Show QR code for URL (fallback or primary method)
function showQrCode(authPrompt, url) {
    // Check for known static QR codes first
    for (const [staticUrl, pngFile] of Object.entries(STATIC_QR_URLS)) {
        if (url.includes(staticUrl)) {
            const fileUri = `file:///usr/share/gnome-shell/extensions/qr-greeter@himmelblau-idm.org/${pngFile}`;
            authPrompt._qrContainer.set_style(`background-image: url('${fileUri}');`);
            authPrompt._qrContainer.show();
            authPrompt._qrLabel.set_text("Scan with your phone");
            authPrompt._qrLabel.show();
            return true;
        }
    }

    // Generate dynamic QR code
    const validated = validateUrl(url);
    if (validated) {
        try {
            const qr = QrCode.encodeText(validated, Ecc.MEDIUM);
            const svgContent = qrCodeToSvg(qr, 2, '#ffffff', '#000000');
            const tempFilePath = writeSvgToTempFile(svgContent);
            authPrompt._totpTempFile = tempFilePath;
            activeTotpTempFiles.add(tempFilePath);
            const fileUri = `file://${tempFilePath}`;
            authPrompt._qrContainer.set_style(`background-image: url('${fileUri}'); background-size: contain; background-repeat: no-repeat; background-position: center;`);
            authPrompt._qrContainer.show();
            authPrompt._qrLabel.set_text("Scan with your phone");
            authPrompt._qrLabel.show();
            return true;
        } catch (e) {
            console.error("Himmelblau QR Greeter: Failed to generate QR code:", e);
        }
    }

    return false;
}

// Handle URL detection - try embedded browser first, fall back to QR
async function handleUrlDetection(authPrompt, url) {
    // Hide any existing embedded browser
    hideEmbeddedBrowser(authPrompt);

    // Check if embedded browser service is available
    const browserAvailable = await checkBrowserServiceAvailable();

    if (browserAvailable) {
        const service = getBrowserService();

        // Check if service is ready (container image built)
        const status = await service.isReady();

        if (status.initializing) {
            // Service is still initializing (building container image)
            console.log("Himmelblau QR Greeter: Service initializing:", status.message);

            // Show initializing message and QR code as fallback
            if (authPrompt._message) {
                authPrompt._message.set_text(`Browser service is preparing (${status.message}). Use QR code for now.`);
            }
            showQrCode(authPrompt, url);

            // Wait for service to become ready in background, then switch to browser
            service.waitForReady(120000, 2000, (msg) => {
                console.log("Himmelblau QR Greeter: Still initializing:", msg);
            }).then((ready) => {
                if (ready) {
                    console.log("Himmelblau QR Greeter: Service now ready, switching to browser");
                    showEmbeddedBrowser(authPrompt, url);
                }
            }).catch((e) => {
                console.log("Himmelblau QR Greeter: Wait for ready failed:", e.message);
            });

            return true;
        }

        if (!status.ready) {
            // Service failed to initialize
            console.log("Himmelblau QR Greeter: Service not ready, falling back to QR code");
            return showQrCode(authPrompt, url);
        }

        console.log("Himmelblau QR Greeter: Attempting embedded browser for URL:", url);
        const success = await showEmbeddedBrowser(authPrompt, url);
        if (success) {
            return true;
        }
        console.log("Himmelblau QR Greeter: Embedded browser failed, falling back to QR code");
    }

    // Fall back to QR code
    return showQrCode(authPrompt, url);
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
                let urlFound = false;
                let targetUrl = null;

                if (message) {
                    // Check for known URLs with static QR codes first
                    for (const [url, _pngFile] of Object.entries(STATIC_QR_URLS)) {
                        if (message.includes(url)) {
                            targetUrl = url;
                            urlFound = true;
                            break;
                        }
                    }

                    // If no static URL found, check for any other URLs
                    if (!urlFound) {
                        URL_RE.lastIndex = 0;
                        const urlMatches = message.match(URL_RE);

                        if (urlMatches) {
                            for (const url of urlMatches) {
                                const validated = validateUrl(url);
                                if (validated) {
                                    targetUrl = validated;
                                    urlFound = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if (urlFound && targetUrl) {
                    // Use handleUrlDetection which will try embedded browser first,
                    // then fall back to QR code
                    const authPromptRef = this;
                    handleUrlDetection(authPromptRef, targetUrl).catch(e => {
                        console.error("Himmelblau QR Greeter: URL detection error:", e);
                        // Ensure QR elements are hidden on error
                        if (authPromptRef._qrContainer) authPromptRef._qrContainer.hide();
                        if (authPromptRef._qrLabel) authPromptRef._qrLabel.hide();
                    });
                } else {
                    // No URL found, hide QR elements and any embedded browser
                    hideEmbeddedBrowser(this);
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
        // Reset browser service cache state
        browserServiceAvailable = null;
        browserServiceChecked = false;
        if (GdmAuthPrompt && this._originalSetMessage) {
            GdmAuthPrompt.prototype.setMessage = this._originalSetMessage;
        }
    }
}

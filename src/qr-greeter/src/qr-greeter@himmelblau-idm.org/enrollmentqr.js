import { QrCode, Ecc } from './qrcodegen.js';

// This payload comes from the bounded PNG decoder in the PAM client. Keep the
// same bounds here because PAM messages are also a presentation boundary.
export function enrollmentQr(encoded, decodeBase64) {
    if (!encoded || encoded.length > 2732 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded))
        throw new Error('Invalid enrollment QR');
    const bytes = decodeBase64(encoded);
    if (bytes.length === 0 || bytes.length > 2048)
        throw new Error('Invalid enrollment QR');
    // Strict UTF-8 decoding also works in legacy GJS without TextDecoder.
    const payload = decodeURIComponent(Array.from(bytes, byte =>
        '%' + byte.toString(16).padStart(2, '0')).join(''));
    if (/[\u0000-\u001f\u007f-\u009f]/.test(payload))
        throw new Error('Invalid enrollment QR');
    return QrCode.encodeText(payload, Ecc.MEDIUM);
}

export function paintEnrollmentQr(cr, width, height, qr) {
    const border = 4;
    const scale = Math.floor(Math.min(width, height) / (qr.size + border * 2));
    if (scale < 1) throw new Error('Enrollment QR area is too small');
    const left = Math.floor((width - qr.size * scale) / 2);
    const top = Math.floor((height - qr.size * scale) / 2);
    cr.setSourceRGB(1, 1, 1);
    cr.paint();
    cr.setSourceRGB(0, 0, 0);
    for (let y = 0; y < qr.size; y++) {
        for (let x = 0; x < qr.size; x++) {
            if (qr.getModule(x, y))
                cr.rectangle(left + x * scale, top + y * scale, scale, scale);
        }
    }
    cr.fill();
}

// The prompt is reused between attempts; its extra children are not reset by GDM.
export function bindEnrollmentQrLifetime(prompt, area) {
    const connections = [];
    const connect = (object, signal, callback) => {
        connections.push([object, object.connect(signal, callback)]);
    };
    const clear = () => area.destroy();
    for (const signal of ['reset', 'cancelled', 'failed', 'destroy'])
        connect(prompt, signal, clear);
    connect(prompt, 'notify::visible', () => {
        if (!prompt.visible) clear();
    });
    connect(prompt._userVerifier, 'verification-failed', (_verifier, service) => {
        if (service === 'gdm-password') clear();
    });
    connect(prompt._userVerifier, 'verification-complete', clear);
    area.connect('destroy', () => {
        for (const [object, id] of connections) {
            // GDM may have already disposed the verifier during prompt destruction.
            try { object.disconnect(id); } catch (_) { }
        }
        connections.length = 0;
    });
}

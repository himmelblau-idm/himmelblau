import assert from 'node:assert/strict';
import test from 'node:test';
import { enrollmentQr, paintEnrollmentQr, bindEnrollmentQrLifetime } from './enrollmentqr.js';

const encode = text => Buffer.from(text).toString('base64');
const decode = text => new Uint8Array(Buffer.from(text, 'base64'));

test('enrollment QR accepts UTF-8 payloads and draws an opaque quiet border', () => {
    const qr = enrollmentQr(encode('otpauth://totp/Exemple:élise?secret=JBSWY3DPEHPK3PXP'), decode);
    const rectangles = [];
    const colors = [];
    let painted = false;
    let filled = false;
    paintEnrollmentQr({
        setSourceRGB: (...rgb) => colors.push(rgb),
        paint: () => { painted = true; },
        rectangle: (...rect) => rectangles.push(rect),
        fill: () => { filled = true; },
    }, 256, 256, qr);
    assert.equal(painted && filled, true);
    assert.deepEqual(colors, [[1, 1, 1], [0, 0, 0]]);
    assert.ok(rectangles.length > 0);
    for (const [x, y, w, h] of rectangles) {
        assert.ok(Number.isInteger(x) && Number.isInteger(y));
        assert.ok(x >= w * 4 && y >= h * 4);
        assert.ok(x + w <= 256 - w * 4 && y + h <= 256 - h * 4);
    }
});

test('enrollment QR rejects malformed, control-bearing, and oversized data', () => {
    for (const encoded of ['', '!!!!', encode('hello\nworld'), encode('x'.repeat(2049)), '/w=='])
        assert.throws(() => enrollmentQr(encoded, decode));
});

class Signals {
    constructor() { this.handlers = new Map(); this.nextId = 0; this.visible = true; }
    connect(signal, callback) { this.handlers.set(++this.nextId, [signal, callback]); return this.nextId; }
    disconnect(id) { this.handlers.delete(id); }
    emit(signal, ...args) {
        for (const [id, [name, callback]] of [...this.handlers]) {
            if (name === signal && this.handlers.has(id)) callback(this, ...args);
        }
    }
    destroy() { this.destroyed = true; this.emit('destroy'); this.handlers.clear(); }
}

test('enrollment QR is removed on every auth teardown and disconnects its handlers', () => {
    for (const signal of ['reset', 'cancelled', 'failed', 'destroy', 'notify::visible',
        'verification-failed', 'verification-complete', 'replacement', 'disable']) {
        const prompt = new Signals();
        prompt._userVerifier = new Signals();
        const area = new Signals();
        bindEnrollmentQrLifetime(prompt, area);
        if (signal.startsWith('verification-')) prompt._userVerifier.emit(signal, 'gdm-password');
        else if (['replacement', 'disable'].includes(signal)) area.destroy();
        else {
            prompt.visible = false;
            prompt.emit(signal);
        }
        assert.equal(area.destroyed, true, signal);
        assert.equal(prompt.handlers.size, 0, signal);
        assert.equal(prompt._userVerifier.handlers.size, 0, signal);
        prompt.emit('reset');
    }
});

test('QR survives prompts and polling, and a reused prompt cleans up the next QR', () => {
    const prompt = new Signals();
    prompt._userVerifier = new Signals();
    for (let attempt = 0; attempt < 2; attempt++) {
        const area = new Signals();
        bindEnrollmentQrLifetime(prompt, area);
        for (const signal of ['prompted', 'next', 'notify::visible']) prompt.emit(signal);
        prompt._userVerifier.emit('show-message');
        prompt._userVerifier.emit('verification-failed', 'gdm-fingerprint');
        assert.equal(area.destroyed, undefined);
        prompt.emit('reset');
        assert.equal(area.destroyed, true);
        assert.equal(prompt.handlers.size, 0);
    }
});

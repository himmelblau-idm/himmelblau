import { selectDeviceFlowUrl } from './qrselection.js';

function assertEqual(actual, expected, label) {
    if (actual !== expected) {
        throw new Error(`${label}: expected '${expected}', got '${actual}'`);
    }
}

function assertTrue(value, label) {
    if (!value) {
        throw new Error(`${label}: expected true, got ${value}`);
    }
}

function assertFalse(value, label) {
    if (value) {
        throw new Error(`${label}: expected false, got ${value}`);
    }
}

function run() {
    const completeUrl = 'https://login.example/device?user_code=ABCD-EFGH';
    const baseUrl = 'https://login.example/device';
    const selectionComplete = selectDeviceFlowUrl('', {
        urls: [completeUrl, baseUrl],
        validateUrl: url => url,
    });
    assertEqual(selectionComplete.url, completeUrl, 'prefers complete url');
    assertTrue(selectionComplete.usedComplete, 'marks complete url used');

    const selectionBase = selectDeviceFlowUrl('', {
        urls: [baseUrl],
        validateUrl: url => url,
    });
    assertEqual(selectionBase.url, baseUrl, 'falls back to base url');
    assertFalse(selectionBase.usedComplete, 'marks base url used');
}

run();

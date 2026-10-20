// Run with gjs -m devicecode.test.js (no GNOME Shell session needed).
import { extractUserCode } from './qrselection.js';
const cases = [
    ['Using a browser on another device, visit:\nhttps://microsoft.com/devicelogin\nAnd enter the code:\nE9Y6JX8J7', 'E9Y6JX8J7'],
    ['enter the code ABCDEFGHI to authenticate', 'ABCDEFGHI'],
    ['And enter the code: ABCD-EFGH', 'ABCD-EFGH'],
    ['https://example.com/?user_code=abcd12345', 'ABCD12345'],
    ['E9Y6JX8J7', 'E9Y6JX8J7'],
    ['Continue authentication at https://example.com', null],
    ['https://microsoft.com/devicelogin', null],
    ['continue', null],
    ['enter the code ABCDEFGHIJKLMNO', null],
    ['', null],
];
for (const [message, expected] of cases) {
    const actual = extractUserCode(message);
    if (actual !== expected) throw new Error(`${message}: ${actual} !== ${expected}`);
}
print(`${cases.length} device-code cases passed`);

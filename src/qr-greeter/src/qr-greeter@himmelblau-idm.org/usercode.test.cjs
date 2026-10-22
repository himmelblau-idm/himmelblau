// Exercise the actual extension parser without importing GNOME Shell in Node.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(`${__dirname}/extension.js`, 'utf8');
const parser = source.match(/function extractUserCode\(message\) \{[\s\S]*?\n\}/)[0];
const context = vm.createContext({});
vm.runInContext(parser, context);
for (const [message, expected] of [
    ['And enter the code:\nABCD-EFGH', 'ABCD-EFGH'],
    ['And enter the code:\nABCDEFGHJ', 'ABCDEFGHJ'],
    ['enter the code E9Y6JX8J7 to authenticate', 'E9Y6JX8J7'],
    ['https://example.com?user_code=abcd-efgh', 'ABCD-EFGH'],
    ['E9Y6JX8J7', 'E9Y6JX8J7'],
    ['ABCDEFGHJ', 'ABCDEFGHJ'],
    ['ABCDEFGH', 'ABCDEFGH'],
    ['ABCDEFGHJ\nhttps://idp.example/x', 'ABCDEFGHJ'],
    ['https://idp.example/x\nABCDEFGHJ', 'ABCDEFGHJ'],
    ['Öffnen Sie https://idp.example/x\nGeben Sie diesen Code ein:\nABCDEFGHJ', 'ABCDEFGHJ'],
    ['Continuer sur https://idp.example/x\r\n\t ABCDEFGHJ \t\r\n', 'ABCDEFGHJ'],
    ['Continue authentication at https://example.com', null],
    ['Continue\nAuthentication\nhttps://example.com', null],
    ['CONTINUE AUTHENTICATION AT https://example.com', null],
    ['https://idp.example/ABCDEFGHJ', null],
    ['ABCDEFG\nhttps://idp.example/x', null],
    ['ABCDEFGHIJ\nhttps://idp.example/x', null],
    ['https://microsoft.com/devicelogin', null],
    ['', null],
]) assert.equal(context.extractUserCode(message), expected, message);
console.log('19 device-code parsing regressions passed');

'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../js/release.js'), 'utf8');

async function boot({failOptional = false, baseEvaluates = true} = {}) {
    const appended = [];
    const notice = {textContent: '', style: {display: 'none'}};
    const context = {
        console: {error() {}}, URL,
        location: {href: 'https://example.test/not_messenger/index.html'},
        document: {
            readyState: 'complete',
            // This script belongs to ui_logic but has not evaluated yet.
            scripts: [{src: 'https://example.test/not_messenger/js/call_session.js?v=in-flight'}],
            createElement(tagName) { return {tagName}; },
            getElementById(id) { return id === 'dmash-release-notice' ? notice : null; },
            head: {appendChild(element) {
                if (element.tagName !== 'script') return;
                appended.push(element.src);
                if (element.src.startsWith('js/call_session.js?')) {
                    if (baseEvaluates) context.window.DmashCallSession = {CallSignalingSession: class {}};
                    queueMicrotask(() => element.onload());
                } else if (failOptional && element.src.startsWith('js/secure_session.js?')) {
                    queueMicrotask(() => element.onerror());
                } else queueMicrotask(() => element.onload());
            }}
        }
    };
    context.window = context;
    vm.runInNewContext(source, context, {filename: 'release.js'});
    await new Promise(resolve => setImmediate(resolve));
    return {context, appended, notice};
}

(async () => {
    const ready = await boot({failOptional: true});
    assert.ok(ready.appended[0].startsWith('js/call_session.js?'), 'critical base loads before optional modules');
    assert.equal(typeof ready.context.DmashCallSession.CallSignalingSession, 'function');
    assert.ok(!ready.appended.some(src => src.startsWith('js/call_runtime.js?')),
        'optional failure halts only after base is ready');
    const absent = await boot({baseEvaluates: false});
    assert.match(absent.notice.textContent, /failed to load/);
    assert.ok(!absent.appended.some(src => src.startsWith('js/secure_session.js?')),
        'a loaded script without the required global is not readiness');
    const media = {DmashFileChannel: {validate() {}}};
    media.window = media;
    vm.runInNewContext(fs.readFileSync(require.resolve('../js/file_session.js'), 'utf8'), media);
    assert.throws(() => media.DmashFileSession.create({manifest: {}}), /MEDIA_RUNTIME_UNAVAILABLE/,
        'a genuinely missing base is a retryable media error, not a TypeError');
    console.log('media_release_loader.test.js: critical base order, in-flight script and failure readiness passed');
})().catch(error => {console.error(error); process.exitCode = 1;});

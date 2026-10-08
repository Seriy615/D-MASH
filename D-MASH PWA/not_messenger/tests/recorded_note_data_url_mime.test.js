'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
require('../js/recorded_note_turn.js');

(async () => {
    global.DeviceRoot = {state: {}, onLock() {}};
    const peer = 'a'.repeat(64), bytes = Buffer.from('synthetic recorded bytes'), base64 = bytes.toString('base64');
    const core = {keys: {sign: {}}, blindSalt: new Uint8Array(32), activeIdentity: 'synthetic', activePeerId: null};
    const runtime = new DmashRecordedNoteTurn(core, {});
    let saved;
    runtime.capture = () => ({check() {}, current: () => true});
    runtime.exclusive = async (_, fn) => fn();
    runtime.rows = async () => [];
    runtime.write = async (_, row) => {saved = row;};
    runtime.history = async () => {};
    runtime.flush = async () => {};
    runtime.view = () => {};

    const accepted = [
        ['voice', 'audio/webm;codecs=opus', 'audio/webm'],
        ['voice', 'audio/mp4; codecs="mp4a.40.2"', 'audio/mp4'],
        ['voice', 'audio/webm;codecs=opus;profiles=1', 'audio/webm'],
        ['voice', 'audio/ogg; codecs=opus', 'audio/ogg'],
        ['voice', 'audio/3gpp', 'audio/3gpp'],
        ['voice', 'audio/x-unknown', 'audio/x-unknown'],
        ['video_note', 'video/webm;codecs="vp8,opus"', 'video/webm'],
        ['video_note', 'video/mp4;codecs=avc1.42E01E,mp4a.40.2', 'video/mp4'],
        ['video_note', 'video/x-matroska', 'video/x-matroska']
    ];
    for (const [type, media, normalized] of accepted) {
        saved = null;
        assert.equal(await runtime.queue(peer, {type, mime: media, data: `data:${media};base64,${base64}`}), true, media);
        assert(saved, `No durable intent for ${media}`);
        assert.equal(saved.content.mime, normalized, media);
        assert.equal(saved.content.data, `data:${normalized};base64,${base64}`, media);
        assert.equal(saved.size, bytes.length);
        assert.equal(saved.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
    }

    const rejected = [
        ['voice', 'video/webm', base64],
        ['video_note', 'audio/webm', base64],
        ['voice', 'application/octet-stream', base64],
        ['voice', 'audio/webm;codecs=opus\r\nX-Test=1', base64],
        ['voice', 'audio/webm;codecs=opus;codecs=vorbis', base64],
        ['voice', 'audio/webm;foo', base64],
        ['voice', 'audio/webm', 'YQ'],
        ['voice', 'audio/webm', '!!!'],
        ['voice', 'audio/webm;base64;extra', base64]
    ];
    for (const [type, media, encoded] of rejected) {
        saved = null;
        await assert.rejects(runtime.queue(peer, {type, data: `data:${media};base64,${encoded}`}));
        assert.equal(saved, null, `Rejected data persisted: ${media}`);
    }
    await assert.rejects(runtime.queue(peer, {type: 'voice', data: 'data:' + 'audio/webm;base64,' + 'A'.repeat(Math.ceil(16 * 1024 * 1024 / 3) * 4 + 4)}), /16 МиБ/);
    await assert.rejects(runtime.queue(peer, {type: 'voice', mime: 'video/mp4', data: `data:audio/webm;base64,${base64}`}));
    await assert.rejects(runtime.queue(peer, {type: 'voice', data: 'data:audio/webm;base64,YR=='}), /Формат записи/);
    await assert.rejects(runtime.queue(peer, {type: 'voice', data: 'data:audio/webm;base64,YWF='}), /Формат записи/);
    console.log('PASS known recorder MIME parameters, normalized content/hash, strict type/size/base64 rejection');
})().catch(error => {console.error(error); process.exitCode = 1;});

// Real RTCPeerConnections in isolated Chrome contexts, with synthetic audio.
const assert = require('node:assert/strict');
const {chromium} = require(process.env.DMASH_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
    const browser = await chromium.launch({headless: true,
        ...(process.env.DMASH_CHROME ? {executablePath: process.env.DMASH_CHROME} : {channel: 'chrome'}),
        args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream',
            '--allow-loopback-in-peer-connection', '--disable-features=WebRtcHideLocalIpsWithMdns',
            '--autoplay-policy=no-user-gesture-required']});
    try {
        const pages = [];
        for (let i = 0; i < 2; i++) {
            const context = await browser.newContext({permissions: ['microphone']});
            const page = await context.newPage(); pages.push(page);
            await page.goto(process.argv[2]);
            await page.addScriptTag({url: '/js/call_signaling.js'});
            await page.addScriptTag({url: '/js/call_session.js'});
            await page.evaluate(() => {
                window.callEvents = [];
                window.makePeer = config => {
                    const pc = new RTCPeerConnection(config);
                    pc.addEventListener('connectionstatechange', () => callEvents.push('rtc:' + pc.connectionState));
                    pc.addEventListener('iceconnectionstatechange', () => callEvents.push('ice:' + pc.iceConnectionState));
                    return pc;
                };
                const Class = DmashCallSignaling.WebSocketSignaling;
                const send = Class.prototype.send;
                Class.prototype.send = function(message) {
                    callEvents.push('send:' + message.type); return send.call(this, message);
                };
                const receive = DmashCallSession.CallSignalingSession.prototype.receive;
                DmashCallSession.CallSignalingSession.prototype.receive = function(message) {
                    callEvents.push('receive:' + message.type);
                    this.onerror = error => callEvents.push('error:' + error.name);
                    return receive.call(this, message);
                };
            });
        }
        if (process.env.DMASH_CALL_BASELINE === '1') {
            // Diagnostic: bypass every D-MASH signaling component.
            await pages[0].evaluate(async () => {
                window.baseline = [new RTCPeerConnection(), new RTCPeerConnection()];
                const [a, b] = baseline;
                for (const [pc, remote] of [[a, b], [b, a]]) {
                    pc.onicecandidate = async event => {
                        if (!event.candidate) return;
                        while (!remote.remoteDescription) await new Promise(resolve => setTimeout(resolve, 10));
                        await remote.addIceCandidate(event.candidate);
                    };
                    const stream = await navigator.mediaDevices.getUserMedia({audio: true});
                    stream.getTracks().forEach(track => pc.addTrack(track, stream));
                    pc.ontrack = event => {
                        const audio = document.createElement('audio'); audio.autoplay = true;
                        audio.srcObject = event.streams[0]; document.body.append(audio);
                    };
                }
                await a.setLocalDescription(await a.createOffer());
                await b.setRemoteDescription(a.localDescription);
                await b.setLocalDescription(await b.createAnswer());
                await a.setRemoteDescription(b.localDescription);
            });
            await pages[0].waitForFunction(() => baseline.every(pc => pc.connectionState === 'connected'), null, {timeout: 20000});
            console.log('Direct RTC baseline connected without D-MASH signaling');
            return;
        }
        const invite = await pages[0].evaluate(async () => {
            const signaling = await DmashCallSignaling.WebSocketSignaling.create(location.origin.replace('http:', 'ws:') + '/signal/v1');
            window.call = new DmashCallSession.CallSignalingSession({signaling,
                rtcFactory: makePeer, mediaDevices: navigator.mediaDevices, useRemoteIceServers: false});
            call.ontrack = event => {
                const audio = document.createElement('audio'); audio.autoplay = true;
                audio.srcObject = event.streams[0]; document.body.append(audio);
            };
            await call.startOffer(signaling.invitation.call_id);
            return signaling.invitation;
        });
        await pages[1].evaluate(async invite => {
            const signaling = new DmashCallSignaling.WebSocketSignaling({endpoint: invite.signaling.wss_endpoint,
                sessionId: invite.signaling.session_id, ticket: invite.signaling.one_time_key});
            window.call = new DmashCallSession.CallSignalingSession({signaling,
                rtcFactory: makePeer, mediaDevices: navigator.mediaDevices, useRemoteIceServers: false});
            call.ontrack = event => {
                const audio = document.createElement('audio'); audio.autoplay = true;
                audio.srcObject = event.streams[0]; document.body.append(audio);
            };
            await call.accept(invite.call_id);
        }, invite);
        const results = [];
        for (const page of pages) {
            const deadline = Date.now() + 20000;
            let result;
            do {
                result = await page.evaluate(async () => {
                    if (!call.pc) return {connection: 'closed', audioPacketsReceived: 0};
                    const stats = [...(await call.pc.getStats()).values()];
                    const audio = stats.find(s => s.type === 'inbound-rtp' && s.kind === 'audio');
                    window.tracks = call.stream.getTracks();
                    return {connection: call.pc.connectionState, audioPacketsReceived: audio?.packetsReceived || 0};
                });
                if (result.connection === 'connected' && result.audioPacketsReceived > 5) break;
                await new Promise(resolve => setTimeout(resolve, 100));
            } while (Date.now() < deadline);
            assert.equal(result.connection, 'connected', JSON.stringify(await Promise.all(pages.map(p => p.evaluate(() => callEvents)))));
            assert(result.audioPacketsReceived > 5, 'Real inbound audio packets required');
            results.push(result);
        }
        await pages[0].evaluate(() => call.hangup());
        for (const page of pages) {
            await page.waitForFunction(() => call.closed && tracks.every(t => t.readyState === 'ended'));
            assert(await page.evaluate(() => call.signaling.closed));
        }
        console.log(JSON.stringify({passed: true, mode: 'local Chrome direct audio; synthetic microphones; no TURN relay', peers: results}));
    } finally {await browser.close();}
})().catch(error => {console.error(error); process.exitCode = 1;});

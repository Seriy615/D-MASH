"use strict";
(function (global) {
    function validate(request) {
        if (!request || request.version !== 2 || !/^[0-9a-f]{64}$/.test(request.call_id || '') ||
            !Number.isInteger(request.expires_at) || request.expires_at <= Date.now() / 1000 ||
            request.expires_at > Date.now() / 1000 + 3600 ||
            !/^[A-Za-z0-9_-]{43}$/.test(request.signaling?.session_id || '') ||
            !/^[A-Za-z0-9_-]{43}$/.test(request.signaling?.one_time_key || '')) throw new Error('Недействительное приглашение звонка');
        global.DmashCallSignaling.validEndpoint(request.signaling.wss_endpoint);
        return request;
    }
    function attach(core, signaling, attempt) {
        const session = new global.DmashCallSession.CallSignalingSession({signaling,
            rtcFactory: config => new global.RTCPeerConnection(config), mediaDevices: global.navigator.mediaDevices});
        core.attachCallSignaling(session);
        session.onclose = () => { if (core._callAttempt === attempt) core.endCall(false); };
        session.ontrack = event => {
            if (core._callAttempt !== attempt) return;
            const element = global.document.getElementById('remoteVideo');
            if (element) { element.srcObject = event.streams[0]; void element.play?.().catch(() => {}); }
            core.remoteStream = event.streams[0];
            if (core.callState !== 'connected') {
                core.callState = 'connected'; core.updateCallUI('connected'); core.startTimer();
            }
        };
        return session;
    }
    function bindMedia(core, session) {
        core.peerConnection = session.pc; core.localStream = session.stream;
        const local = global.document.getElementById('localVideo');
        if (local) local.srcObject = session.stream;
    }
    function begin(core, peer, state) {
        const attempt = {}; core._callAttempt = attempt; core.callPeerId = peer; core.callState = state;
        core._callExpiry = setTimeout(() => { if (core._callAttempt === attempt) core.endCall(); }, 60000);
        return attempt;
    }
    function expiry(core, request, attempt) {
        clearTimeout(core._callExpiry);
        core._callExpiry = setTimeout(() => { if (core._callAttempt === attempt) core.endCall(); },
            Math.max(0, request.expires_at * 1000 - Date.now()));
    }
    async function start(core) {
        if (core.callState !== 'idle' || !core.activePeerId) return false;
        const peer = core.activePeerId, attempt = begin(core, peer, 'calling');
        core.updateCallUI('calling');
        let signaling;
        try {
            const endpoint = await global.NodeManager.selectCallService();
            if (core._callAttempt !== attempt) return false;
            signaling = await global.DmashCallSignaling.WebSocketSignaling.create(endpoint);
            if (core._callAttempt !== attempt) { signaling.close(); return false; }
            const session = attach(core, signaling, attempt);
            const request = validate({...signaling.invitation, caller_display_name: 'D-MASH',
                ringtone: null, media_capabilities: {audio: true, video: false}});
            core.activeCallId = request.call_id;
            await session.startOffer(request.call_id);
            if (core._callAttempt !== attempt) return false;
            bindMedia(core, session);
            // The authenticated Account seals this invitation, then Device
            // seals its CALL_REQUEST type. SDP and ICE never enter this path.
            if (!await core.sendMessage({type: 'voip_call_request', request}, false, peer, null, true))
                throw new Error('Не удалось доставить приглашение звонка');
            if (core._callAttempt !== attempt) return false;
            expiry(core, request, attempt);
            return true;
        } catch (error) {
            signaling?.close();
            if (core._callAttempt === attempt) { core.shmon('ERR', error.message); core.endCall(false); }
            return false;
        }
    }
    async function incoming(core, value, peer) {
        if (core.callState !== 'idle') return false;
        let request;
        try { request = validate(value); } catch (_) { return false; }
        const attempt = begin(core, peer, 'receiving');
        const signaling = new global.DmashCallSignaling.WebSocketSignaling({endpoint: request.signaling.wss_endpoint,
            sessionId: request.signaling.session_id, ticket: request.signaling.one_time_key});
        const session = attach(core, signaling, attempt);
        try {
            core.activeCallId = request.call_id;
            await session.prepareIncoming(request.call_id);
            if (core._callAttempt !== attempt) return false;
            expiry(core, request, attempt);
            await core.showIncomingCall(peer, async () => {
                if (core._callAttempt !== attempt) return;
                core.callState = 'connecting'; core.updateCallUI('connecting');
                try {
                    await session.accept(request.call_id);
                    if (core._callAttempt === attempt) bindMedia(core, session);
                } catch (_) { if (core._callAttempt === attempt) core.endCall(false); }
            });
            return true;
        } catch (_) { if (core._callAttempt === attempt) core.endCall(false); return false; }
    }
    global.DmashCallRuntime = {start, incoming, validate};
})(typeof window !== 'undefined' ? window : globalThis);

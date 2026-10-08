"use strict";

/*
 * WebRTC call signaling adapter.  Device Envelope delivery creates the call
 * request; this object carries only offer/answer/ICE/hangup over the ephemeral
 * S-TURN signaling ticket and never sends those messages through chat MSG.
 */
(function (global) {
    const TYPES = new Set(["offer", "answer", "ice", "hangup"]);
    const fail = message => { throw new Error(message); };
    const callId = value => {
        if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) fail("invalid call id");
        return value;
    };
    const fingerprint = sdp => {
        const values = [...String(sdp || "").matchAll(/^a=fingerprint:([^\r\n]+)$/gm)]
            .map(match => match[1].trim().toUpperCase());
        if (!values.length || new Set(values).size !== 1) return null;
        return values[0];
    };

    class CallSignalingSession {
        constructor({ signaling, rtcFactory, mediaDevices, iceServers = [], useRemoteIceServers = true,
            renegotiationTimeoutMs = 15000 } = {}) {
            if (!signaling || typeof signaling.open !== "function" || typeof signaling.send !== "function" ||
                typeof signaling.close !== "function") fail("signaling transport is required");
            if (typeof rtcFactory !== "function") fail("RTCPeerConnection factory is required");
            if (!mediaDevices || typeof mediaDevices.getUserMedia !== "function") fail("mediaDevices is required");
            this.signaling = signaling;
            this.rtcFactory = rtcFactory;
            this.mediaDevices = mediaDevices;
            this.iceServers = Array.isArray(iceServers) ? iceServers : [];
            this.useRemoteIceServers = useRemoteIceServers !== false;
            this.renegotiationTimeoutMs = Number.isInteger(renegotiationTimeoutMs) &&
                renegotiationTimeoutMs >= 10 && renegotiationTimeoutMs <= 15000 ? renegotiationTimeoutMs : 15000;
            this.pc = null;
            this.stream = null;
            this.callId = null;
            this.role = null;
            this.remoteDescription = false;
            this.queuedIce = [];
            this.closed = false;
            this.signalChain = Promise.resolve();
            this.renegotiations = 0;
            this.remoteRenegotiations = 0;
            this.videoSender = null;
            this.videoTrack = null;
            this.signaling.onmessage = message => {
                this.signalChain = this.signalChain.then(async () => {
                    await this.mediaReady;
                    return this.receive(message);
                }).catch(error => { this.onerror?.(error); return this.close(); });
                return this.signalChain;
            };
            this.signaling.onclose = () => this.close();
        }

        async _open(callIdValue, role) {
            callIdValue = callId(callIdValue);
            if (this.callId || this.closed) fail("call session already used");
            this.callId = callIdValue;
            this.role = role;
            await this.signaling.open(callIdValue, role);
            if (this.closed) fail("call closed during join");
            if (this.useRemoteIceServers && this.signaling.iceServers?.length) this.iceServers = this.signaling.iceServers;
        }

        async _setupMedia({ video = false } = {}) {
            const stream = await this.mediaDevices.getUserMedia({ audio: true, video });
            if (this.closed) { stream.getTracks().forEach(track => track.stop()); fail("call cancelled"); }
            this.stream = stream;
            this._createPeer();
            this.stream.getTracks().forEach(track => this.pc.addTrack(track, this.stream));
        }

        async _remote(description, subsequent = false) {
            const next = fingerprint(description.sdp);
            if (subsequent && (!this.remoteFingerprint || !next || next !== this.remoteFingerprint))
                fail("Call fingerprint changed during renegotiation");
            await this.pc.setRemoteDescription(description);
            if (!this.remoteDescription) this.remoteFingerprint = next;
            this.remoteDescription = true;
        }

        async enableVideo(video = true) {
            if (this.closed || !this.pc || !this.stream || this.pc.connectionState !== "connected") fail("Call is not connected");
            if (this.videoTrack?.readyState === "live") return this.videoTrack;
            const camera = await this.mediaDevices.getUserMedia({audio: false, video});
            const tracks = camera.getVideoTracks();
            const track = tracks[0];
            if (!track || this.closed || !this.pc || this.pc.connectionState !== "connected") {
                camera.getTracks().forEach(value => value.stop());
                fail("Call closed before camera was ready");
            }
            for (const extra of tracks.slice(1)) extra.stop();
            let added = false;
            try {
                this.stream.addTrack(track);
                this.videoTrack = track;
                if (this.videoSender) await this.videoSender.replaceTrack(track);
                else {
                    this.videoSender = this.pc.addTrack(track, this.stream);
                    added = true;
                    await this._renegotiate();
                }
                if (this.closed) fail("Call closed while enabling camera");
                this.onvideochange?.(true);
                return track;
            } catch (error) {
                if (added && this.pc?.signalingState === "have-local-offer") {
                    try { await this.pc.setLocalDescription({type: "rollback"}); } catch (_) {}
                }
                if (added) { try { this.pc?.removeTrack(this.videoSender); } catch (_) {} this.videoSender = null; }
                this.stream?.removeTrack(track);
                track.stop();
                this.videoTrack = null;
                throw error;
            }
        }

        async disableVideo() {
            if (this.closed) return false;
            const track = this.videoTrack;
            if (!track) return true;
            track.enabled = false;
            let failure;
            try { if (this.videoSender) await this.videoSender.replaceTrack(null); }
            catch (error) { failure = error; }
            this.stream?.removeTrack(track);
            track.stop();
            this.videoTrack = null;
            this.onvideochange?.(false);
            if (failure) throw failure;
            return true;
        }

        async switchVideoCamera(video) {
            if (this.closed || !this.videoTrack || !this.videoSender || !this.stream) fail("Camera is not active");
            const camera = await this.mediaDevices.getUserMedia({audio: false, video});
            const next = camera.getVideoTracks()[0];
            if (!next || this.closed || !this.videoTrack) {
                camera.getTracks().forEach(track => track.stop());
                fail("Call closed before camera was ready");
            }
            for (const extra of camera.getVideoTracks().slice(1)) extra.stop();
            try { await this.videoSender.replaceTrack(next); }
            catch (error) { next.stop(); throw error; }
            const previous = this.videoTrack;
            this.stream.removeTrack(previous);
            this.stream.addTrack(next);
            this.videoTrack = next;
            previous.stop();
            this.onvideochange?.(true);
            return next;
        }

        async _renegotiate() {
            if (this.closed || !this.pc || !this.remoteDescription || this.pc.signalingState !== "stable" || this.renegotiation)
                fail("Call renegotiation unavailable");
            if (++this.renegotiations > 8) fail("Call renegotiation limit");
            const pc = this.pc;
            const outcome = new Promise((resolve, reject) => {
                const timer = setTimeout(() => { if (this.renegotiation?.pc === pc) {
                    this.renegotiation = null; reject(new Error("Call renegotiation timeout"));
                } }, this.renegotiationTimeoutMs);
                this.renegotiation = {pc, resolve: () => {clearTimeout(timer); this.renegotiation = null; resolve();},
                    reject: error => {clearTimeout(timer); this.renegotiation = null; reject(error);}};
            });
            try {
                await pc.setLocalDescription(await pc.createOffer());
                await this._send({type: "offer", payload: JSON.stringify(pc.localDescription)});
                await outcome;
            } catch (error) {
                this.renegotiation?.reject(error);
                // A pending rejection belongs to this awaited operation.
                await outcome.catch(() => {});
                throw error;
            }
        }

        _createPeer() {
            this.pc = this.rtcFactory({ iceServers: this.iceServers,iceTransportPolicy:this.useRemoteIceServers?'relay':'all' });
            this.pc.onicecandidate = event => {
                if (event.candidate) void this._send({ type: "ice", payload: JSON.stringify(event.candidate) }).catch(() => this.close());
            };
            this.pc.ontrack = event => { if (typeof this.ontrack === "function") this.ontrack(event); };
            this.pc.onconnectionstatechange = () => {
                if(this.pc?.connectionState==='connected')this.onconnected?.();
                if (this.pc && ["failed", "closed"].includes(this.pc.connectionState)) void this.close();
            };
        }

        async startOffer(callIdValue, options = {}) {
            try {
            await this._open(callIdValue, "caller");
            await this._setupMedia(options);
            const offer = await this.pc.createOffer();
            await this.pc.setLocalDescription(offer);
            await this._send({ type: "offer", payload: JSON.stringify(this.pc.localDescription) });
            return this.pc.localDescription;
            } catch (error) { this.failure=error; await this.close(); throw error; }
        }

        async prepareIncoming(callIdValue) {
            if (this.callId || this.closed) fail('call session already used');
            this.mediaReady = new Promise(resolve => { this.releaseMedia = resolve; });
            try { await this._open(callIdValue, 'callee'); }
            catch (error) { await this.close(); throw error; }
        }

        async accept(callIdValue, options = {}) {
            try {
                // The bounded transport queue holds the offer while permission
                // is pending. One consumer preserves order across media setup.
                if (!this.callId) await this.prepareIncoming(callIdValue);
                if (this.callId !== callIdValue || this.role !== 'callee' || this.accepting || this.closed) fail('invalid call acceptance');
                this.accepting = true;
                await this._setupMedia(options);
            } catch (error) { await this.close(); throw error; }
            finally { this.releaseMedia?.(); }
        }

        async acceptOffer(callIdValue, offer, options = {}) {
            await this._open(callIdValue, "callee");
            if (!offer || typeof offer !== "object" || !offer.type || !offer.sdp) fail("invalid offer");
            await this._setupMedia(options);
            await this.pc.setRemoteDescription(offer);
            this.remoteFingerprint = fingerprint(offer.sdp);
            this.remoteDescription = true;
            await this._flushIce();
            const answer = await this.pc.createAnswer();
            await this.pc.setLocalDescription(answer);
            await this._send({ type: "answer", payload: JSON.stringify(this.pc.localDescription) });
            return this.pc.localDescription;
        }

        async _send(message) {
            if (this.closed || !TYPES.has(message.type) || typeof message.payload !== "string") fail("invalid signaling message");
            await this.signaling.send({ call_id: this.callId, type: message.type, payload: message.payload });
        }

        async sendSignal(data) {
            if (!data || typeof data !== "object") fail("invalid signaling data");
            const map = { voip_offer: "offer", voip_answer: "answer", voip_ice: "ice", voip_hangup: "hangup" };
            const type = map[data.type];
            if (!type) fail("unsupported signaling data");
            const payload = type === "hangup" ? "" : JSON.stringify(data.sdp || data.candidate || data);
            await this._send({ type, payload });
        }

        async receive(message) {
            if (this.closed || !message || message.call_id !== this.callId || !TYPES.has(message.type)) return false;
            if (typeof message.payload !== "string") return false;
            if (message.payload.length > 256 * 1024) { await this.close(); return false; }
            if (message.type === "offer") {
                if (!this.pc) return false;
                const offer = JSON.parse(message.payload);
                if (offer.type !== "offer" || typeof offer.sdp !== "string") fail("invalid offer");
                const subsequent = this.remoteDescription;
                if (!subsequent && this.role !== "callee") return false;
                if (subsequent && this.pc.signalingState !== "stable") {
                    if (this.role !== "callee" || this.pc.signalingState !== "have-local-offer") return false;
                    await this.pc.setLocalDescription({type: "rollback"});
                }
                if (subsequent && ++this.remoteRenegotiations > 8) fail("Call renegotiation limit");
                await this._remote(offer, subsequent);
                await this._flushIce();
                await this.pc.setLocalDescription(await this.pc.createAnswer());
                await this._send({type: "answer", payload: JSON.stringify(this.pc.localDescription)});
                if (subsequent) this.renegotiation?.resolve();
            } else if (message.type === "answer") {
                if (!this.pc || this.pc.signalingState !== "have-local-offer" || (this.remoteDescription && !this.renegotiation)) return false;
                const answer = JSON.parse(message.payload);
                if (answer.type !== "answer" || typeof answer.sdp !== "string") fail("invalid answer");
                await this._remote(answer, this.remoteDescription);
                await this._flushIce();
                this.renegotiation?.resolve();
            } else if (message.type === "ice") {
                const candidate = JSON.parse(message.payload);
                if (this.pc && this.remoteDescription) await this.pc.addIceCandidate(candidate);
                else { if (this.queuedIce.length >= 128) fail("ICE queue limit"); this.queuedIce.push(candidate); }
            } else if (message.type === "hangup") {
                await this.close(false);
            }
            return true;
        }

        async _flushIce() {
            while (this.queuedIce.length) await this.pc.addIceCandidate(this.queuedIce.shift());
        }

        async hangup() {
            this.cancelled=true;
            try { if (!this.closed && this.callId) await this._send({ type: "hangup", payload: "" }); }
            finally { await this.close(false); }
        }

        async close(notify = true) {
            if (this.closed) return;
            this.closed = true;
            this.renegotiation?.reject(new Error("Call closed"));
            this.releaseMedia?.();
            if (this.pc) { this.pc.onconnectionstatechange = null; this.pc.close(); }
            if (this.stream) this.stream.getTracks().forEach(track => track.stop());
            this.pc = this.stream = null;
            this.queuedIce = [];
            try { await this.signaling.close(this.callId); } catch (_) {}
            this.onclose?.();
        }
    }

    global.DmashCallSession = Object.freeze({ CallSignalingSession });
})(typeof window !== "undefined" ? window : globalThis);

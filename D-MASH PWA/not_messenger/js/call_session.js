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

    class CallSignalingSession {
        constructor({ signaling, rtcFactory, mediaDevices, iceServers = [] } = {}) {
            if (!signaling || typeof signaling.open !== "function" || typeof signaling.send !== "function" ||
                typeof signaling.close !== "function") fail("signaling transport is required");
            if (typeof rtcFactory !== "function") fail("RTCPeerConnection factory is required");
            if (!mediaDevices || typeof mediaDevices.getUserMedia !== "function") fail("mediaDevices is required");
            this.signaling = signaling;
            this.rtcFactory = rtcFactory;
            this.mediaDevices = mediaDevices;
            this.iceServers = Array.isArray(iceServers) ? iceServers : [];
            this.pc = null;
            this.stream = null;
            this.callId = null;
            this.role = null;
            this.remoteDescription = false;
            this.queuedIce = [];
            this.closed = false;
        }

        async _open(callIdValue, role) {
            callIdValue = callId(callIdValue);
            if (this.callId || this.closed) fail("call session already used");
            this.callId = callIdValue;
            this.role = role;
            await this.signaling.open(callIdValue, role);
        }

        async _setupMedia({ video = false } = {}) {
            this.stream = await this.mediaDevices.getUserMedia({ audio: true, video });
            this.pc = this.rtcFactory({ iceServers: this.iceServers });
            this.stream.getTracks().forEach(track => this.pc.addTrack(track, this.stream));
            this.pc.onicecandidate = event => {
                if (event.candidate) void this._send({ type: "ice", payload: JSON.stringify(event.candidate) });
            };
            this.pc.ontrack = event => { if (typeof this.ontrack === "function") this.ontrack(event); };
            this.pc.onconnectionstatechange = () => {
                if (["failed", "closed"].includes(this.pc.connectionState)) void this.close();
            };
        }

        async startOffer(callIdValue, options = {}) {
            await this._open(callIdValue, "caller");
            await this._setupMedia(options);
            const offer = await this.pc.createOffer();
            await this.pc.setLocalDescription(offer);
            await this._send({ type: "offer", payload: JSON.stringify(this.pc.localDescription) });
            return this.pc.localDescription;
        }

        async acceptOffer(callIdValue, offer, options = {}) {
            await this._open(callIdValue, "callee");
            if (!offer || typeof offer !== "object" || !offer.type || !offer.sdp) fail("invalid offer");
            await this._setupMedia(options);
            await this.pc.setRemoteDescription(offer);
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
            if (message.type === "answer") {
                if (!this.pc || this.role !== "caller") return false;
                await this.pc.setRemoteDescription(JSON.parse(message.payload));
                this.remoteDescription = true;
                await this._flushIce();
            } else if (message.type === "ice") {
                const candidate = JSON.parse(message.payload);
                if (this.pc && this.remoteDescription) await this.pc.addIceCandidate(candidate);
                else this.queuedIce.push(candidate);
            } else if (message.type === "hangup") {
                await this.close(false);
            }
            return true;
        }

        async _flushIce() {
            while (this.queuedIce.length) await this.pc.addIceCandidate(this.queuedIce.shift());
        }

        async hangup() {
            if (!this.closed && this.callId) await this._send({ type: "hangup", payload: "" });
            await this.close(false);
        }

        async close(notify = true) {
            if (this.closed) return;
            this.closed = true;
            if (notify && this.callId) {
                try { await this.signaling.close(this.callId); } catch (_) {}
            } else {
                try { await this.signaling.close(this.callId); } catch (_) {}
            }
            if (this.pc) this.pc.close();
            if (this.stream) this.stream.getTracks().forEach(track => track.stop());
            this.pc = this.stream = null;
        }
    }

    global.DmashCallSession = Object.freeze({ CallSignalingSession });
})(typeof window !== "undefined" ? window : globalThis);

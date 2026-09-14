"use strict";
(function (global) {
    function create({signaling, manifest, file, rtcFactory = config => new global.RTCPeerConnection(config), useRemoteIceServers = true,
        onProgress, onComplete, onError}) {
        global.DmashFileChannel.validate(manifest);
        class FileSession extends global.DmashCallSession.CallSignalingSession {
            async _setupMedia() {
                if (this.closed) throw Error('File session cancelled');
                this._createPeer();
                this.pc.ondatachannel = event => this.bindChannel(event.channel);
                if (this.role === 'caller') this.bindChannel(this.pc.createDataChannel('dmash-file-v1', {ordered: true}));
            }
            bindChannel(channel) {
                if (this.pipe || channel.label !== 'dmash-file-v1' || channel.ordered !== true ||
                    channel.maxRetransmits !== null || channel.maxPacketLifeTime !== null) {
                    onError?.(Error('Invalid file DataChannel configuration'));
                    channel.close(); void this.close(); return;
                }
                this.pipe = new global.DmashFileChannel.FileChannel({channel, manifest, file: this.file,
                    onProgress, onComplete: blob => {
                        this.finished = true; onComplete?.(blob);
                        if (this.role === 'caller') void this.close();
                    }, onError: error => {onError?.(error); void this.close();}});
            }
            async close() {
                this.file = null;
                this.pipe?.close();
                return super.close();
            }
        }
        const session = new FileSession({signaling, rtcFactory, useRemoteIceServers,
            mediaDevices: {getUserMedia() {throw Error('File transfer never requests microphone');}}});
        session.file = file;
        return session;
    }
    global.DmashFileSession = {create};
})(typeof window !== 'undefined' ? window : globalThis);

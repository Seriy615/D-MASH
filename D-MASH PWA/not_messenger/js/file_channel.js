"use strict";
(function (global) {
    const MAX_SIZE = 64 * 1024 * 1024, CHUNK = 32 * 1024;
    const encode = text => new TextEncoder().encode(text);
    const hex = bytes => Array.from(bytes, v => v.toString(16).padStart(2, '0')).join('');
    const hash = async bytes => hex(new Uint8Array(await global.crypto.subtle.digest('SHA-256', bytes)));
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    function unb64(value, length) {
        if (typeof value !== 'string' || value.length > 64) throw Error('Invalid file key');
        const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
        if (bytes.length !== length || b64(bytes) !== value) throw Error('Invalid file key');
        return bytes;
    }
    function validate(manifest) {
        if (!manifest || manifest.version !== 1 || !/^[0-9a-f]{64}$/.test(manifest.id || '') ||
            !Number.isSafeInteger(manifest.size) || manifest.size < 1 || manifest.size > MAX_SIZE ||
            manifest.chunk_bytes !== CHUNK || !/^[0-9a-f]{64}$/.test(manifest.sha256 || '') ||
            typeof manifest.name !== 'string' || !manifest.name.length || manifest.name.length > 255 ||
            typeof manifest.mime !== 'string' || manifest.mime.length > 128) throw Error('Invalid file manifest');
        unb64(manifest.key, 32).fill(0); unb64(manifest.nonce, 8).fill(0);
        return manifest;
    }
    async function describe(file, id) {
        if (!file || file.size < 1 || file.size > MAX_SIZE) throw Error('Файл должен быть от 1 байта до 64 МиБ');
        return validate({version: 1, id, size: file.size, name: file.name.slice(0, 255), mime: file.type.slice(0, 128),
            chunk_bytes: CHUNK, sha256: await hash(await file.arrayBuffer()),
            key: b64(global.crypto.getRandomValues(new Uint8Array(32))), nonce: b64(global.crypto.getRandomValues(new Uint8Array(8)))});
    }
    class FileChannel {
        constructor({channel, manifest, file, onProgress = () => {}, onComplete = () => {}, onError = () => {}}) {
            this.manifest = structuredClone(validate(manifest)); this.channel = channel; this.file = file;
            if (file && file.size !== manifest.size) throw Error('File size mismatch');
            this.onProgress = onProgress; this.onComplete = onComplete; this.onError = onError;
            this.closed = false; this.complete = false; this.index = 0; this.parts = []; this.pending = null;
            this.queued = 0; this.chain = Promise.resolve(); this.count = Math.ceil(manifest.size / CHUNK);
            const raw = unb64(manifest.key, 32);
            this.key = global.crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); raw.fill(0);
            channel.binaryType = 'arraybuffer';
            channel.onmessage = event => {
                if (this.closed) return;
                if (++this.queued > 4) {this.fail(Error('File receive window exceeded')); return;}
                this.chain = this.chain.then(() => this.receive(event.data)).catch(error => this.fail(error))
                    .finally(() => {this.queued--;});
            };
            channel.onclose = () => { if (!this.complete) this.fail(Error('File channel disconnected')); else this.close(); };
            channel.onerror = () => this.fail(Error('File channel failed'));
            if (file) {
                channel.onopen = () => {void this.sendFile().catch(error => this.fail(error));};
                if (channel.readyState === 'open') channel.onopen();
            }
        }
        params(index, direction) {
            const iv = new Uint8Array(12); iv.set(unb64(this.manifest.nonce, 8)); iv[0] ^= direction * 128;
            new DataView(iv.buffer).setUint32(8, index);
            return {name: 'AES-GCM', iv, additionalData: encode(`D-MASH|FILE|1|${this.manifest.id}|${direction}|${index}|${this.manifest.size}|${this.manifest.sha256}`)};
        }
        async seal(index, bytes, direction) {
            const ciphertext = new Uint8Array(await global.crypto.subtle.encrypt(this.params(index, direction), await this.key, bytes));
            const frame = new Uint8Array(ciphertext.length + 4); new DataView(frame.buffer).setUint32(0, index); frame.set(ciphertext, 4);
            return frame.buffer;
        }
        send(frame) {
            if (this.closed || this.channel.readyState !== 'open' || this.channel.bufferedAmount > 128 * 1024) throw Error('File transport unavailable');
            this.channel.send(frame);
        }
        async sendAndWait(index, bytes) {
            const frame = await this.seal(index, bytes, 0);
            if (this.closed) throw Error('File transfer cancelled');
            await new Promise((resolve, reject) => {
                const timer = setTimeout(() => {this.pending = null; reject(Error('File acknowledgement timeout'));}, 20000);
                this.pending = {index, resolve: () => {clearTimeout(timer); this.pending = null; resolve();},
                    reject: error => {clearTimeout(timer); this.pending = null; reject(error);}};
                try {this.send(frame);} catch (error) {this.pending.reject(error);}
            });
        }
        async sendFile() {
            for (let index = 0; index < this.count; index++) {
                const bytes = await this.file.slice(index * CHUNK, Math.min(this.manifest.size, (index + 1) * CHUNK)).arrayBuffer();
                await this.sendAndWait(index, bytes);
                this.onProgress(Math.min((index + 1) * CHUNK, this.manifest.size), this.manifest.size);
            }
            await this.sendAndWait(this.count, encode('END'));
            this.complete = true; this.file = null; this.onComplete();
        }
        async receive(frame) {
            if (this.closed) return;
            if (!(frame instanceof ArrayBuffer) || frame.byteLength < 20 || frame.byteLength > CHUNK + 20) throw Error('Invalid file frame');
            const index = new DataView(frame).getUint32(0), direction = this.file ? 1 : 0;
            const expected = this.file ? this.pending?.index : this.index;
            if (index !== expected || this.complete) throw Error('File chunk order mismatch');
            const bytes = new Uint8Array(await global.crypto.subtle.decrypt(this.params(index, direction), await this.key, frame.slice(4)));
            if (this.closed) return;
            if (this.file) {
                if (new TextDecoder().decode(bytes) !== 'ACK') throw Error('Invalid file acknowledgement');
                this.pending.resolve(); return;
            }
            if (index === this.count) {
                if (new TextDecoder().decode(bytes) !== 'END') throw Error('Invalid file completion');
                const blob = new Blob(this.parts, {type: 'application/octet-stream'});
                if (blob.size !== this.manifest.size || await hash(await blob.arrayBuffer()) !== this.manifest.sha256) throw Error('File integrity mismatch');
                if (this.closed) return;
                this.send(await this.seal(index, encode('ACK'), 1));
                this.complete = true; this.parts = []; this.onComplete(blob); return;
            }
            const length = Math.min(CHUNK, this.manifest.size - index * CHUNK);
            if (bytes.length !== length) throw Error('File chunk length mismatch');
            this.parts.push(bytes); this.index++;
            this.onProgress(Math.min(this.index * CHUNK, this.manifest.size), this.manifest.size);
            this.send(await this.seal(index, encode('ACK'), 1));
        }
        fail(error) {if (this.closed) return; this.close(); this.onError(error);}
        close() {
            if (this.closed) return; this.closed = true;
            this.pending?.reject(Error('File transfer cancelled')); this.parts = []; this.file = null; this.key = null;
            this.manifest.key = null; this.channel.close();
        }
    }
    global.DmashFileChannel = {FileChannel, describe, validate, MAX_SIZE, CHUNK};
})(typeof window !== 'undefined' ? window : globalThis);

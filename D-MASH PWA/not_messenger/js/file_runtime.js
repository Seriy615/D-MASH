"use strict";
(function (global) {
    const textEncoder = new TextEncoder(), textDecoder = new TextDecoder();
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const bytesB64 = value => {
        if (typeof value !== 'string' || value.length > 64 * 1024) throw Error('Повреждены метаданные файла');
        const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
        if (!bytes.length) throw Error('Повреждены метаданные файла');
        return bytes;
    };
    function requestFor(manifest, invitation) {
        // Core.sendMessage encrypts this whole Account payload before it is
        // wrapped in FILE_SESSION_REQUEST.  Keep the file manifest opaque to
        // the Device/Node layer while retaining the strict wire shape.
        const metadata = b64(textEncoder.encode(JSON.stringify(manifest)));
        return {version: 1, session_id: manifest.id, expires_at: invitation.expires_at,
            signaling: invitation.signaling, encrypted_metadata: metadata,
            size_bytes: manifest.size, chunk_bytes: manifest.chunk_bytes,
            sha256: manifest.sha256, resumable: false};
    }
    function parseRequest(request) {
        const required = ['version', 'session_id', 'expires_at', 'signaling', 'encrypted_metadata',
            'size_bytes', 'chunk_bytes', 'sha256', 'resumable'];
        if (!request || Object.keys(request).length !== required.length ||
            !required.every(key => Object.prototype.hasOwnProperty.call(request, key)) || request.version !== 1 ||
            !/^[0-9a-f]{64}$/.test(request.session_id || '') || !Number.isInteger(request.expires_at) ||
            request.expires_at <= Date.now() / 1000 || request.expires_at > Date.now() / 1000 + 3600 ||
            !Number.isInteger(request.size_bytes) || !Number.isInteger(request.chunk_bytes) ||
            !/^[0-9a-f]{64}$/.test(request.sha256 || '') || request.resumable !== false ||
            typeof request.signaling !== 'object') throw Error('Недействительное приглашение файла');
        global.DmashCallSignaling.validEndpoint(request.signaling.wss_endpoint);
        if (!/^[A-Za-z0-9_-]{43}$/.test(request.signaling.session_id || '') ||
            !/^[A-Za-z0-9_-]{43}$/.test(request.signaling.one_time_key || '')) throw Error('Недействительный канал файла');
        const manifest = JSON.parse(textDecoder.decode(bytesB64(request.encrypted_metadata)));
        global.DmashFileChannel.validate(manifest);
        if (manifest.id !== request.session_id || manifest.size !== request.size_bytes ||
            manifest.chunk_bytes !== request.chunk_bytes || manifest.sha256 !== request.sha256) {
            throw Error('Метаданные файла не совпадают');
        }
        return {request, manifest};
    }
    function panel(core, name) {
        const box = document.createElement('section'); box.className = 'dmash-file-transfer';
        box.setAttribute('role', 'status');
        const title = document.createElement('div'); title.textContent = name;
        const status = document.createElement('div'); status.textContent = 'Подготовка передачи…';
        const progress = document.createElement('progress'); progress.max = 1; progress.value = 0;
        const cancel = document.createElement('button'); cancel.textContent = 'Отмена';
        box.append(title, status, progress, cancel); document.body.append(box);
        const task = {box, status, cancel, closed: false,
            current: () => core._fileTransfer === task && !task.closed,
            progress(done, size) {if (!task.current()) return; progress.value = done / size; status.textContent = `${Math.floor(done / size * 100)}%`;},
            complete(blob) {
                if (!task.current()) return;
                task.finished = true; status.textContent = 'Передано и проверено'; progress.value = 1; cancel.textContent = 'Закрыть';
                if (blob) {
                    task.url = URL.createObjectURL(blob);
                    const link = document.createElement('a'); link.href = task.url; link.download = name; link.textContent = 'Сохранить файл';
                    box.append(link);
                }
            },
            error(error) {if (!task.current()) return; task.failed = true; status.textContent = error.message; cancel.textContent = 'Закрыть';},
            close() {
                if (task.closed) return; task.closed = true;
                clearTimeout(task.timer); task.signaling?.close(); void task.session?.close();
                if (task.url) URL.revokeObjectURL(task.url);
                box.remove(); if (core._fileTransfer === task) core._fileTransfer = null;
            }};
        cancel.onclick = () => {void task.decline?.(); task.close();}; core._fileTransfer = task;
        task.timer = setTimeout(() => {task.error(Error('Время передачи истекло')); task.signaling?.close(); void task.session?.close();}, 15 * 60 * 1000);
        return task;
    }
    function bind(task, manifest, file) {
        const session = global.DmashFileSession.create({signaling: task.signaling, manifest, file,
            onProgress: (done, size) => task.progress(done, size),
            onComplete: blob => task.complete(blob), onError: error => task.error(error)});
        task.session = session;
        session.onerror = error => task.error(error);
        session.onclose = () => {
            clearTimeout(task.timer);
            if (!task.finished && !task.failed) task.error(Error('Передача прервана'));
        };
        return session;
    }
    async function send(core, file) {
        if (!core.activePeerId || core._fileTransfer) return false;
        const peer = core.activePeerId;
        if (file.size < 1 || file.size > global.DmashFileChannel.MAX_SIZE) {core.customAlert('ФАЙЛ', 'Поддерживаются файлы от 1 байта до 64 МиБ'); return false;}
        const task = panel(core, file.name);
        try {
            const endpoint = await global.NodeManager.selectCallService({file: true});
            if (!task.current()) return false;
            const signaling = await global.DmashCallSignaling.WebSocketSignaling.create(endpoint);
            if (!task.current()) {signaling.close(); return false;}
            task.signaling = signaling;
            const manifest = await global.DmashFileChannel.describe(file, signaling.invitation.call_id);
            if (!task.current()) return false;
            const session = bind(task, manifest, file);
            await session.startOffer(manifest.id);
            if (!task.current()) return false;
            const request = requestFor(manifest, signaling.invitation);
            if (!await core.sendMessage({type: 'voip_file_request', request}, false, peer, null, true)) throw Error('Не удалось доставить предложение файла');
            if (task.current()) task.status.textContent = 'Ожидаем принятия файла';
            return true;
        } catch (error) {task.error(error); task.signaling?.close(); void task.session?.close(); return false;}
    }
    async function incoming(core, request, peer) {
        if (core._fileTransfer) return false;
        let parsed;
        try {
            parsed = parseRequest(request);
        } catch (_) {return false;}
        const task = panel(core, parsed.manifest.name);
        task.decline = async () => {
            if (task.session || request.expires_at * 1000 <= Date.now()) return;
            const transport = new global.DmashCallSignaling.WebSocketSignaling({endpoint: request.signaling.wss_endpoint,
                sessionId: request.signaling.session_id, ticket: request.signaling.one_time_key});
            try {
                await transport.open(request.session_id, 'callee');
                await transport.send({call_id: request.session_id, type:'hangup', payload:''});
            } catch (_) {} finally {transport.close();}
        };
        task.status.textContent = `Входящий файл: ${parsed.manifest.size} байт`;
        const accept = document.createElement('button'); accept.textContent = 'Принять'; task.box.append(accept);
        accept.onclick = async () => {
            accept.disabled = true;
            try {
                if (!task.current()) return;
                if (request.expires_at * 1000 <= Date.now()) throw Error('Предложение файла истекло');
                task.signaling = new global.DmashCallSignaling.WebSocketSignaling({endpoint: request.signaling.wss_endpoint,
                    sessionId: request.signaling.session_id, ticket: request.signaling.one_time_key});
                const session = bind(task, parsed.manifest);
                await session.accept(request.session_id);
            } catch (error) {task.error(error); void task.session?.close();}
        };
        return true;
    }
    global.DmashFileRuntime = {send, incoming, cancel: core => core._fileTransfer?.close()};
})(typeof window !== 'undefined' ? window : globalThis);

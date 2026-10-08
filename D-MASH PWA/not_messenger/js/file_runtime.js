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
    function requestFor(manifest, invitation, fileId = manifest.id) {
        // Core.sendMessage encrypts this whole Account payload before it is
        // wrapped in FILE_SESSION_REQUEST.  Keep the file manifest opaque to
        // the Device/Node layer while retaining the strict wire shape.
        const metadata = b64(textEncoder.encode(JSON.stringify(manifest)));
        return {version: 2, file_id: fileId, session_id: manifest.id, expires_at: invitation.expires_at,
            signaling: invitation.signaling, encrypted_metadata: metadata,
            size_bytes: manifest.size, chunk_bytes: manifest.chunk_bytes,
            sha256: manifest.sha256, resumable: false};
    }
    function parseRequest(request) {
        const required = ['version', 'session_id', 'expires_at', 'signaling', 'encrypted_metadata',
            'size_bytes', 'chunk_bytes', 'sha256', 'resumable'];
        if (!request || ![1,2].includes(request.version) ||
            Object.keys(request).length !== required.length + (request.version === 2 ? 1 : 0) ||
            !required.every(key => Object.prototype.hasOwnProperty.call(request, key)) ||
            (request.version === 2 && (!Object.prototype.hasOwnProperty.call(request,'file_id') ||
                !/^[0-9a-f]{64}$/.test(request.file_id || ''))) ||
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
        return {request, manifest, fileId: request.version === 2 ? request.file_id : manifest.id};
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
            progress(done, size) {if (!task.current() || task.finished || task.failed) return; progress.value = done / size; status.textContent = `${Math.floor(done / size * 100)}%`;},
            complete(blob) {
                if (!task.current() || task.finished || task.failed) return;
                clearTimeout(task.timer);
                task.finished = true; status.textContent = 'Передано и проверено'; progress.value = 1; cancel.textContent = 'Закрыть';
                if (blob) {
                    task.url = URL.createObjectURL(blob);
                    const link = document.createElement('a'); link.href = task.url; link.download = name; link.textContent = 'Сохранить файл';
                    box.append(link);
                }
            },
            error(error) {if (!task.current() || task.finished || task.failed) return; task.failed = true; status.textContent = error.message; cancel.textContent = 'Закрыть';},
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
    const isId = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
    const fileRef = meta => ({type:'file_ref', fileId:meta.fileId, name:meta.name,
        mime:meta.mime, size:meta.size, sha256:meta.sha256});
    const vaultFor = core => {
        if (!global.DmashFileVault || !global.DMashStorage) throw Error('FILE_VAULT_UNAVAILABLE: Обновите страницу.');
        return new global.DmashFileVault(core, global.DMashStorage);
    };
    let active = null, retryTimer = null, flushing = null;
    const locallyCancelled = new Set();
    async function history(core, vault, meta, inbound) {
        const storage = global.DMashStorage;
        const account = vault.capture();
        const present = await storage.hasMessageWireId(meta.peer, meta.fileId);
        account.check();
        if (!present) {
            // saveMessageGamma captures its Account synchronously when called.
            // Check after the async lookup so a late sender/receiver callback
            // cannot append this file card to a different unlocked Account.
            await storage.saveMessageGamma(meta.peer, fileRef(meta), inbound,
                core.activePeerId === meta.peer, inbound ? null : (meta.status === 'delivered' ? 'DELIVERED' : 'WAITING'), meta.fileId);
            account.check();
            if (core.activePeerId === meta.peer) await core.loadChat();
            else await core.renderPeers();
        }
    }
    async function send(core, file) {
        if (!core.activePeerId) return false;
        if (typeof global.DmashCallSession?.CallSignalingSession !== 'function' ||
            !global.DmashFileVault) {
            core.customAlert?.('ФАЙЛ НЕ ОТПРАВЛЕН', 'MEDIA_RUNTIME_UNAVAILABLE: Обновите страницу и повторите передачу.');
            return false;
        }
        if (!file || file.size < 1 || file.size > global.DmashFileChannel.MAX_SIZE) {
            core.customAlert?.('ФАЙЛ', 'Поддерживаются файлы от 1 байта до 64 МиБ'); return false;
        }
        const peer = core.activePeerId;
        let persisted = false;
        try {
            const vault = vaultFor(core), captured = vault.capture();
            if (!await trusted(core, peer)) {
                core.customAlert?.('ФАЙЛ', 'Сначала подтвердите контакт и обменяйтесь ключами.'); return false;
            }
            captured.check();
            const fileId = Array.from(global.crypto.getRandomValues(new Uint8Array(32)),
                b => b.toString(16).padStart(2,'0')).join('');
            const digest = Array.from(new Uint8Array(await global.crypto.subtle.digest('SHA-256', await file.arrayBuffer())),
                b => b.toString(16).padStart(2,'0')).join('');
            captured.check();
            const meta = await vault.put(peer, fileId, file, {name:file.name, mime:file.type || '',
                size:file.size, sha256:digest, inbound:false});
            persisted = true;
            captured.check();
            await history(core, vault, meta, false);
            void flush(core);
            return true;
        } catch (error) {
            core.customAlert?.(persisted ? 'ФАЙЛ СОХРАНЁН ЛОКАЛЬНО' : 'ФАЙЛ НЕ СОХРАНЁН',
                persisted ? 'Файл остался на этом устройстве. Карточка чата пока не создана; передача возобновится после восстановления истории.' :
                    (error.message || 'Не удалось сохранить файл.'));
            return false;
        }
    }

    function stopActive(task) {
        if (!task || task.closed) return;
        task.closed = true;
        task.signal?.close(); void task.session?.close();
        if (active === task) active = null;
    }
    function wake(core, delay) {
        clearTimeout(retryTimer);
        retryTimer = setTimeout(() => {retryTimer = null; void flush(core);}, Math.max(1000, Math.min(60000, delay)));
    }
    async function runOutbound(core) {
        const vault = vaultFor(core), captured = vault.capture();
        if (active && !active.closed) return;
        const pending = (await vault.list(null, ['waiting','connecting','sending']))
            .filter(row => !row.inbound).sort((a,b) => a.createdAt - b.createdAt);
        captured.check();
        for (const row of pending) await history(core, vault, row, false);
        const row = pending.find(item => item.nextAttempt <= Date.now());
        if (!row) {
            if (pending.length) wake(core, Math.min(...pending.map(item => item.nextAttempt)) - Date.now());
            return;
        }
        const task = {core, peer:row.peer, fileId:row.fileId, closed:false, settled:false};
        active = task;
        const current = () => {try {
            captured.check();
            return active === task && !task.closed && !locallyCancelled.has(row.fileId);
        } catch (_) {return false;}};
        const defer = async (error, permanent = false) => {
            if (!current() || task.settled) return;
            task.settled = true; stopActive(task);
            const delay = Math.min(60000, 15000 * 2 ** Math.min(row.attempts, 2));
            try {
                const saved = await vault.update(row.peer, row.fileId, permanent ? 'failed' : 'waiting',
                    {nextAttempt: permanent ? 0 : Date.now() + delay});
                if (saved.status === 'delivered') {
                    core.refreshMessageTransportState?.(row.peer, row.fileId, 'DELIVERED');
                    return;
                }
                if (saved.status === 'cancelled') return;
                if (permanent) await global.DMashStorage.markMessageSendFailure(
                    row.peer, row.fileId, error.message || 'File transfer failed');
                if (core.activePeerId === row.peer) core.refreshMessageTransportState?.(row.peer, row.fileId,
                    permanent ? 'FAILED' : 'WAITING');
                if (permanent) core.customAlert?.('ФАЙЛ НЕ ОТПРАВЛЕН', error.message);
                else wake(core, delay);
            } catch (_) { /* Old Account state remains durable for its next login. */ }
        };
        try {
            await vault.update(row.peer, row.fileId, 'connecting', {attempts:row.attempts + 1,
                nextAttempt:Date.now() + 30000});
            const endpoint = await global.NodeManager.selectCallService({file:true});
            if (!current()) return;
            task.signal = await global.DmashCallSignaling.WebSocketSignaling.create(endpoint);
            if (!current()) {task.signal.close();return;}
            const saved = await vault.get(row.peer, row.fileId);
            if (!saved || saved.meta.sha256 !== row.sha256 || !current()) throw Error('Локальный файл повреждён.');
            const file = new File([saved.blob], row.name, {type:row.mime});
            const manifest = await global.DmashFileChannel.describe(file, task.signal.invitation.call_id);
            if (!current()) return;
            task.sessionId = manifest.id;
            task.session = global.DmashFileSession.create({signaling:task.signal, manifest, file,
                onProgress:(done,total) => {
                    if (current() && !task.settled) {
                        if (!task.progressStarted) {
                            task.progressStarted = true;
                            void vault.update(row.peer,row.fileId,'sending').catch(() => {});
                        }
                        core.refreshFileProgress?.(row.peer,row.fileId,done,total);
                    }
                },
                onComplete:() => {if (current() && !task.settled) void (async()=>{
                    task.settled = true;
                    try {
                        await vault.update(row.peer,row.fileId,'delivered');
                        await global.DMashStorage.updateMessageTransportState(row.peer,row.fileId,'DELIVERED');
                        core.refreshMessageTransportState?.(row.peer,row.fileId,'DELIVERED');
                    } catch (error) {core.shmon?.('WARN', 'File receipt repair deferred: '+error.message);}
                    finally {stopActive(task); void flush(core);}
                })();},
                onError:error=>{void defer(error);}});
            task.session.onclose = () => {if (!task.settled) void defer(Error('File channel disconnected'));};
            await task.session.startOffer(manifest.id);
            if (!current()) return;
            const request = requestFor(manifest, task.signal.invitation, row.fileId);
            if (!await core.sendMessage({type:'voip_file_request',request},false,row.peer,null,true))
                throw Error('Приглашение файла пока не доставлено');
        } catch (error) {
            await defer(error, /повреждён|integrity|owner/i.test(error.message || ''));
        }
    }
    function flush(core) {
        if (flushing) return flushing;
        flushing = runOutbound(core).catch(error => {core.shmon?.('WARN', 'File retry deferred: '+error.message);})
            .finally(() => {flushing = null;});
        return flushing;
    }
    async function trusted(core, peer) {
        const storage = global.DMashStorage, vault = vaultFor(core), captured = vault.capture();
        if (!isId(peer)) return false;
        const alias = await storage.getAlias(peer, 'L1'); captured.check();
        const known = await storage.getBox('blind_peers', alias); captured.check();
        if (!known || known.id !== peer) return false;
        const secretAlias = global.DmashChatPassword ?
            await global.DmashChatPassword.location(storage, alias, 'L2', known.chatLock) : alias;
        captured.check();
        const secret = await storage.getBox('blind_secrets', secretAlias); captured.check();
        return typeof secret?.staticShared === 'string' && /^[0-9a-f]{64}$/.test(secret.staticShared);
    }
    async function notify(core, peer, type, fileId, sha256, reason = undefined, sessionId = undefined) {
        if (!isId(fileId) || !isId(sha256) || (sessionId !== undefined && !isId(sessionId))) return false;
        return core.sendMessage({type, file_id:fileId, sha256, ...(reason ? {reason} : {}),
            ...(sessionId ? {session_id:sessionId} : {})},
            false, peer, null, true);
    }
    async function incoming(core, request, peer) {
        const vault = vaultFor(core), captured = vault.capture();
        if (!await trusted(core, peer)) {
            core.customAlert?.('ВХОДЯЩИЙ ФАЙЛ', 'Автоматический приём доступен только подтверждённому контакту.');
            return false;
        }
        captured.check();
        let parsed;
        try { parsed = parseRequest(request); }
        catch (_) {
            core.customAlert?.('ВХОДЯЩИЙ ФАЙЛ', 'Неверный формат или размер файла. Допустимый размер — до 64 МиБ.');
            return false;
        }
        const {manifest, fileId} = parsed;
        captured.check();
        const previous = await vault.meta(peer, fileId);
        if (previous) {
            if (!previous.inbound || previous.sha256 !== manifest.sha256 || previous.size !== manifest.size ||
                previous.name !== manifest.name || previous.mime !== manifest.mime) throw Error('File identity collision');
            await history(core, vault, previous, true);
            await notify(core, peer, 'voip_file_complete', fileId, manifest.sha256);
            return true;
        }
        // The completed file already has an inline chat card. Release its
        // short-lived panel immediately if another invitation arrives.
        if (core._fileTransfer?.finished) core._fileTransfer.close();
        if (core._fileTransfer) {
            const busy = core._fileTransfer;
            if (!busy.busyNotice) {
                busy.busyNotice = document.createElement('div');
                busy.busyNotice.setAttribute('role', 'status');
                busy.busyNotice.textContent = 'Ещё один файл ожидает повторной попытки отправителя.';
                busy.box.append(busy.busyNotice);
            }
            // A new S-TURN attempt is required after this active panel closes.
            // Bind the transient answer to this attempt so a late BUSY cannot
            // stop a newer session for the same durable file_id.
            await notify(core, peer, 'voip_file_reject', fileId, manifest.sha256,
                'RECEIVER_BUSY', manifest.id);
            return true;
        }
        const task = panel(core, manifest.name);
        task.peer = peer;
        task.decline = async () => {
            if (!task.finished && !task.failed)
                await notify(core,peer,'voip_file_reject',fileId,manifest.sha256,'RECEIVER_DECLINED');
        };
        task.status.textContent = 'АВТОПРИЁМ ФАЙЛА: 0%';
        try {
            const estimate = await global.navigator?.storage?.estimate?.(); captured.check();
            if (estimate && Number.isSafeInteger(estimate.quota) && Number.isSafeInteger(estimate.usage) &&
                estimate.quota - estimate.usage < manifest.size + Math.ceil(manifest.size / 100) + 1024 * 1024) {
                await notify(core, peer, 'voip_file_reject', fileId, manifest.sha256, 'RECEIVER_STORAGE_FULL');
                throw Error('Недостаточно места для автоматического сохранения файла.');
            }
            task.signaling = new global.DmashCallSignaling.WebSocketSignaling({endpoint:request.signaling.wss_endpoint,
                sessionId:request.signaling.session_id, ticket:request.signaling.one_time_key});
            task.session = global.DmashFileSession.create({signaling:task.signaling, manifest,
                onProgress:(done,total)=>{
                    if (task.current()) {
                        task.progress(done,total);
                        task.status.textContent = `АВТОПРИЁМ ФАЙЛА: ${Math.floor(done / total * 100)}%`;
                    }
                },
                onCommit:async blob=>{
                    captured.check();
                    const meta = await vault.put(peer, fileId, blob, {name:manifest.name,mime:manifest.mime,
                        size:manifest.size,sha256:manifest.sha256,inbound:true});
                    captured.check();
                    await history(core, vault, meta, true);
                },
                onComplete:()=>{
                    if (!task.current()) return;
                    task.finished = true;
                    task.decline = null;
                    task.status.textContent = 'ПОЛУЧЕН И СОХРАНЁН В ЧАТЕ';
                    task.cancel.textContent = 'Закрыть';
                    setTimeout(()=>task.close(),800);
                },
                onError:error=>{
                    task.decline = null;
                    task.error(error);
                    if (error.name === 'QuotaExceededError' || /Недостаточно места/.test(error.message || ''))
                        void notify(core, peer, 'voip_file_reject', fileId, manifest.sha256, 'RECEIVER_STORAGE_FULL');
                }});
            task.session.onclose = () => {if (!task.session.finished) task.error(Error('Передача прервана'));};
            await task.session.accept(manifest.id);
            return true;
        } catch (error) {
            task.decline = null; task.error(error); task.signaling?.close(); void task.session?.close();
            return false;
        }
    }
    async function outcome(core, message, peer) {
        if (!isId(message?.file_id) || !isId(message?.sha256)) return false;
        const vault = vaultFor(core), meta = await vault.meta(peer, message.file_id);
        if (!meta || meta.inbound || meta.sha256 !== message.sha256) return false;
        if (message.type === 'voip_file_reject') {
            if (message.reason === 'RECEIVER_BUSY') {
                if (!isId(message.session_id)) return false;
                const task = active;
                // An old attempt may answer after a new S-TURN invitation was
                // sent. The durable file_id is stable, but the session is not.
                if (!task || task.core !== core || task.peer !== peer ||
                    task.fileId !== message.file_id || task.sessionId !== message.session_id ||
                    task.settled || meta.status === 'delivered' || meta.status === 'cancelled') return true;
                task.settled = true;
                stopActive(task);
                const delay = Math.min(30000, 5000 * 2 ** Math.min(Math.max(meta.attempts - 1, 0), 3));
                try {
                    const saved = await vault.update(peer, message.file_id, 'waiting',
                        {nextAttempt:Date.now() + delay});
                    if (saved.status === 'waiting') {
                        core.refreshMessageTransportState?.(peer, message.file_id, 'WAITING');
                        if (core.activePeerId === peer)
                            for (const card of document.querySelectorAll?.('#log .msg.out .dmash-file-card') || [])
                                if (card.dataset.fileId === message.file_id) {
                                    const progress = card.querySelector('.dmash-file-progress');
                                    if (progress) progress.textContent = 'ПОЛУЧАТЕЛЬ ЗАНЯТ · ПОВТОРИМ';
                                }
                    }
                } catch (error) {core.shmon?.('WARN', 'File busy retry deferred: '+error.message);}
                wake(core, delay);
                return true;
            }
            if (!['RECEIVER_STORAGE_FULL','RECEIVER_DECLINED'].includes(message.reason)) return false;
            const saved = await vault.update(peer, message.file_id, 'failed');
            if (saved.status === 'delivered') return true;
            if (saved.status === 'cancelled') return true;
            await global.DMashStorage.markMessageSendFailure(peer,message.file_id,'RECEIVER_STORAGE_FULL');
            core.refreshMessageTransportState?.(peer,message.file_id,'FAILED');
            if (active?.fileId === message.file_id) stopActive(active);
            core.customAlert?.('ФАЙЛ НЕ ДОСТАВЛЕН',message.reason === 'RECEIVER_STORAGE_FULL' ?
                'У получателя недостаточно места для файла. Он сохранён на вашем устройстве.' :
                'Получатель отменил приём. Файл сохранён на вашем устройстве.');
            return true;
        }
        if (message.type !== 'voip_file_complete') return false;
        await vault.update(peer, message.file_id, 'delivered');
        await global.DMashStorage.updateMessageTransportState(peer,message.file_id,'DELIVERED');
        core.refreshMessageTransportState?.(peer,message.file_id,'DELIVERED');
        if (active?.fileId === message.file_id) stopActive(active);
        void flush(core);
        return true;
    }
    async function cancelFile(core, peer, fileId) {
        if (core.activePeerId !== peer || !isId(peer) || !isId(fileId)) return false;
        const vault = vaultFor(core), captured = vault.capture();
        const existing = await vault.meta(peer,fileId); captured.check();
        if (!existing || existing.inbound) return false;
        if (existing.status === 'delivered') {
            core.customAlert?.('ФАЙЛ УЖЕ ДОСТАВЛЕН','Получатель уже подтвердил сохранение файла.');
            return false;
        }
        locallyCancelled.add(fileId);
        if (active?.core === core && active.fileId === fileId) stopActive(active);
        let persisted = false;
        try {
            const saved = await vault.update(peer,fileId,'cancelled'); captured.check();
            if (saved.status === 'delivered') {
                locallyCancelled.delete(fileId);
                core.refreshMessageTransportState?.(peer,fileId,'DELIVERED');
                return false;
            }
            persisted = true;
            await global.DMashStorage.markMessageSendFailure(peer,fileId,'FILE_CANCELLED');
            captured.check();
            core.refreshMessageTransportState?.(peer,fileId,'CANCELLED');
            core.customAlert?.('ОТПРАВКА ОТМЕНЕНА','Файл сохранён на этом устройстве. Если передача уже завершилась, получатель мог его получить.');
            return true;
        } catch (error) {
            if (!persisted) locallyCancelled.delete(fileId);
            core.customAlert?.(persisted ? 'ОТПРАВКА ОСТАНОВЛЕНА' : 'ОТМЕНА НЕ ВЫПОЛНЕНА',
                persisted ? 'Файл сохранён на устройстве; статус чата пока не обновился.' :
                    'Передача и локальный файл сохранены. Повторите действие.');
            throw error;
        }
    }
    const previewType = mime => {
        const type = String(mime || '').toLowerCase();
        if (/^image\/(?:png|jpeg|webp|gif)$/.test(type)) return 'image';
        if (/^video\/(?:mp4|webm)$/.test(type)) return 'video';
        if (/^audio\/(?:mpeg|mp4|ogg|webm|wav|x-wav)$/.test(type)) return 'audio';
        return 'file';
    };
    async function openInline(core, peer, ref, id) {
        if (core.activePeerId !== peer || !/^[0-9a-f]{64}$/.test(ref?.fileId || '') ||
            !/^[0-9a-f]{64}$/.test(ref?.sha256 || '')) throw Error('Недействительная карточка файла.');
        const card = [...document.querySelectorAll('#log .dmash-file-card')].find(node =>
            node.dataset.fileId === ref.fileId && node.closest('.msg')?.id === `msg-box-${id}`);
        if (!card) return false;
        if (card.dataset.loaded === 'true') return true;
        if (card.dataset.loading === 'true') return false;
        card.dataset.loading = 'true';
        const target = card.querySelector('.dmash-file-preview');
        if (target) target.textContent = 'РАСШИФРОВКА ФАЙЛА…';
        let url;
        try {
            if (!global.DmashFileVault || !global.DMashStorage) throw Error('Хранилище файлов недоступно. Обновите страницу.');
            const result = await new global.DmashFileVault(core, global.DMashStorage).get(peer, ref.fileId);
            if (core.activePeerId !== peer || !card.isConnected) return false;
            if (!result || result.meta.sha256 !== ref.sha256 || result.meta.size !== ref.size ||
                result.meta.name !== ref.name || result.meta.mime !== ref.mime)
                throw Error('Файл не найден или карточка не совпадает с сохранёнными данными.');
            const kind = previewType(result.meta.mime);
            const blob = new Blob([result.blob], {type: kind === 'file' ? 'application/octet-stream' : result.meta.mime});
            url = URL.createObjectURL(blob);
            core.blobURLs ||= []; core.blobURLs.push(url);
            target.replaceChildren();
            let element;
            if (kind === 'image') {
                element = document.createElement('img'); element.alt = result.meta.name;
                element.style.maxWidth = '100%'; element.style.maxHeight = '360px';
                element.src = url;
            } else if (kind === 'video' || kind === 'audio') {
                element = document.createElement(kind); element.controls = true; element.preload = 'metadata';
                if (kind === 'video') {element.playsInline = true; element.style.maxWidth = '100%';}
                element.src = url;
            } else {
                element = document.createElement('span'); element.textContent = 'ФАЙЛ ГОТОВ К СОХРАНЕНИЮ';
            }
            target.append(element);
            const save = document.createElement('a'); save.href = url; save.download = result.meta.name;
            save.textContent = 'СОХРАНИТЬ ФАЙЛ'; save.className = 'file-attachment'; target.append(save);
            card.dataset.loaded = 'true';
            card.querySelector('button')?.remove();
            return true;
        } catch (error) {
            if (url) URL.revokeObjectURL(url);
            if (target && card.isConnected) target.textContent = error.message || 'Не удалось открыть файл.';
            throw error;
        } finally {delete card.dataset.loading;}
    }
    function hydrateVisible(core, peer) {
        if (core.activePeerId !== peer) return;
        const cards = [...document.querySelectorAll('#log .dmash-file-card')];
        const open = card => {
            if (!card.isConnected || core.activePeerId !== peer) return;
            let ref;
            try {ref = JSON.parse(decodeURIComponent(escape(atob(card.dataset.fileRef))));}
            catch (_) {return;}
            if (previewType(ref.mime) === 'file') return;
            const id = card.closest('.msg')?.id?.slice('msg-box-'.length);
            if (id) void openInline(core, peer, ref, id).catch(() => {});
        };
        if (typeof global.IntersectionObserver !== 'function') {cards.forEach(open);return;}
        const observer = new global.IntersectionObserver(entries => {
            for (const entry of entries) if (entry.isIntersecting) {observer.unobserve(entry.target);open(entry.target);}
        }, {root: document.getElementById('log'), rootMargin: '200px'});
        for (const card of cards) if (card.dataset.loaded !== 'true') observer.observe(card);
        core._filePreviewObserver?.disconnect?.(); core._filePreviewObserver = observer;
    }
    global.DmashFileRuntime = {send, incoming, outcome, flush, cancelFile, openInline, hydrateVisible,
        forgetPeer: (core, peer) => {
            if (active?.core === core && active.peer === peer) stopActive(active);
            if (core._fileTransfer?.peer === peer) core._fileTransfer.close();
        },
        cancel: core => {
            clearTimeout(retryTimer); retryTimer = null;
            if (active?.core === core) stopActive(active);
            locallyCancelled.clear();
            core._fileTransfer?.close();
        }};
})(typeof window !== 'undefined' ? window : globalThis);

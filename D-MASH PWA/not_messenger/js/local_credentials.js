"use strict";
(function (global) {
    const error = (code, message) => Object.assign(new Error(message), { name: "LocalCredentialError", code });
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
    const HELD_CREDENTIAL_LOCK = Symbol("held-exclusive-credential-lock");
    const CREDENTIAL_LOCK = "dmash/local-credentials/v1";
    class CredentialLifecycle {
        constructor(channel = typeof global.BroadcastChannel === "function" ? new global.BroadcastChannel("dmash/local-credential-lifecycle/v1") : null) {
            this.channel = channel; this.listeners = new Set();
            if (channel) { channel.onmessage = ({ data }) => { if (data?.kind === "wipe-pending" && data.version === 1) for (const listener of this.listeners) listener(); }; channel.unref?.(); }
        }
        subscribe(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
        invalidate() {
            if (!this.channel) throw error("CREDENTIAL_LIFECYCLE_UNAVAILABLE", "Cross-context lifecycle invalidation adapter is required.");
            this.channel.postMessage({ kind: "wipe-pending", version: 1 });
            for (const listener of this.listeners) listener();
        }
        close() { this.channel?.close(); this.listeners.clear(); }
    }
    const WIPE_PROFILE = "sha256-prehash-argon2id-v1";
    class CredentialWorkerKdf {
        constructor({ Worker = global.Worker, url = "js/local_credentials_worker.js", timeout = 120000 } = {}) {
            this.Worker = Worker; this.url = url; this.timeout = timeout; this.tail = Promise.resolve();
        }
        derive(parameters, { signal } = {}) {
            const run = () => new Promise((resolve, reject) => {
                if (signal?.aborted) return reject(error("CREDENTIAL_CANCELLED", "Credential operation was cancelled."));
                if (typeof this.Worker !== "function") return reject(error("ARGON2_UNAVAILABLE", "A credential worker or native KDF adapter is required."));
                let worker, timer, settled = false;
                const finish = (failure, bytes) => {
                    if (settled) { bytes?.fill(0); return; } settled = true;
                    clearTimeout(timer); signal?.removeEventListener("abort", cancel); worker?.terminate();
                    failure ? reject(failure) : resolve(bytes);
                };
                const cancel = () => finish(error("CREDENTIAL_CANCELLED", "Credential operation was cancelled."));
                try {
                    worker = new this.Worker(this.url);
                    signal?.addEventListener("abort", cancel, { once: true });
                    if (signal?.aborted) return cancel();
                    worker.onerror = () => finish(error("ARGON2_FAILED", "Credential worker failed."));
                    worker.onmessage = ({ data }) => {
                        const bytes = data?.hash instanceof ArrayBuffer ? new Uint8Array(data.hash) : null;
                        if (!bytes || bytes.length !== 32 || data.error) return finish(error("ARGON2_FAILED", "Credential worker returned an invalid result."));
                        finish(null, bytes);
                    };
                    timer = setTimeout(() => finish(error("ARGON2_TIMEOUT", "Credential worker exceeded its execution budget.")), this.timeout);
                    worker.postMessage(parameters);
                } catch (_) { finish(error("ARGON2_UNAVAILABLE", "Credential worker could not start.")); }
            });
            const job = this.tail.then(run); this.tail = job.catch(() => {}); return job;
        }
    }
    const WIPE_CONTROL_DB = "dmash_local_credentials_control_v1";
    class CredentialWipeControlStore {
        constructor(indexedDb = global.indexedDB) { this.indexedDb = indexedDb; this.db = null; }
        async open() {
            if (this.db) return this.db;
            if (!this.indexedDb?.open) throw error("STORAGE_UNAVAILABLE", "Durable wipe state is unavailable.");
            this.db = await new Promise((resolve, reject) => {
                const request = this.indexedDb.open(WIPE_CONTROL_DB, 1);
                request.onupgradeneeded = () => { request.result.createObjectStore("operations", { keyPath: "id" }); };
                request.onsuccess = () => { const db = request.result; db.onversionchange = () => { db.close(); if (this.db === db) this.db = null; }; resolve(db); };
                request.onerror = request.onblocked = () => reject(error("WIPE_STATE_UNAVAILABLE", "Durable wipe state could not be opened."));
            }); return this.db;
        }
        async get() {
            const db = await this.open();
            return new Promise((resolve, reject) => { const request = db.transaction("operations", "readonly").objectStore("operations").get("wipe"); request.onsuccess = () => resolve(request.result || null); request.onerror = () => reject(error("WIPE_STATE_UNAVAILABLE", "Durable wipe state could not be read.")); });
        }
        async put(marker, { signal, assertCurrent = () => {} } = {}) {
            assertCurrent(); if (signal?.aborted) throw error("CREDENTIAL_CANCELLED", "Wipe intent was cancelled.");
            const db = await this.open(); assertCurrent();
            if (signal?.aborted) throw error("CREDENTIAL_CANCELLED", "Wipe intent was cancelled.");
            await new Promise((resolve, reject) => {
                const tx = db.transaction("operations", "readwrite"); let failure;
                const abort = () => { try { tx.abort(); } catch (_) {} };
                const cleanup = () => signal?.removeEventListener("abort", abort);
                signal?.addEventListener("abort", abort, { once: true });
                tx.oncomplete = () => { cleanup(); resolve(); }; // Actual durable acceptance boundary.
                tx.onerror = tx.onabort = () => { cleanup(); reject(failure || error(signal?.aborted ? "CREDENTIAL_CANCELLED" : "WIPE_STATE_UNAVAILABLE", "Durable wipe intent did not commit.")); };
                try { assertCurrent(); if (signal?.aborted) throw error("CREDENTIAL_CANCELLED", "Wipe intent was cancelled."); tx.objectStore("operations").put(marker); }
                catch (err) { failure = err; abort(); }
            });
        }
        close() { this.db?.close(); this.db = null; }
    }
    class DurableWipeCoordinator {
        constructor({ indexedDb = global.indexedDB, control = new CredentialWipeControlStore(indexedDb), shutdown, cleanup, timeout = 10000, lock = global.navigator?.locks, lifecycle = new CredentialLifecycle() } = {}) {
            this.indexedDb = indexedDb; this.control = control; this.shutdown = shutdown; this.cleanup = cleanup; this.timeout = timeout; this.running = false; this.lock = lock; this.lifecycle = lifecycle;
        }
        async pending() {
            const marker = await this.control.get();
            if (!marker) return null;
            if (marker.id !== "wipe" || marker.version !== 1 || !["pending", "complete"].includes(marker.state) || !Array.isArray(marker.databases) || !Array.isArray(marker.deleted) || marker.databases.length > 256 || marker.databases.some(name => typeof name !== "string" || !name || name.length > 4096 || name === WIPE_CONTROL_DB) || marker.deleted.some(name => !marker.databases.includes(name))) throw error("WIPE_STATE_CORRUPT", "Unknown durable wipe state; identity setup is blocked.");
            if (new Set(marker.databases).size !== marker.databases.length || new Set(marker.deleted).size !== marker.deleted.length || typeof marker.ancillaryComplete !== "boolean" || (marker.state === "complete" && (!marker.ancillaryComplete || marker.deleted.length !== marker.databases.length))) throw error("WIPE_STATE_CORRUPT", "Contradictory durable wipe completion state.");
            return marker.state === "pending" ? marker : null;
        }
        async _deleteDatabase(name) {
            await new Promise((resolve, reject) => {
                let settled = false;
                const finish = failure => { if (settled) return; settled = true; clearTimeout(timer); failure ? reject(failure) : resolve(); };
                const timer = setTimeout(() => finish(error("WIPE_TIMEOUT", "Database deletion did not complete; wipe remains pending.")), this.timeout);
                try {
                    const request = this.indexedDb.deleteDatabase(name);
                    request.onsuccess = () => finish();
                    request.onerror = () => finish(error("WIPE_DELETE_FAILED", "Database deletion failed; wipe remains pending."));
                    request.onblocked = () => finish(error("WIPE_BLOCKED", "Close other application tabs/processes before completing wipe."));
                } catch (_) { finish(error("WIPE_DELETE_FAILED", "Database deletion could not start; wipe remains pending.")); }
            });
        }
        _exclusive(run) {
            if (!this.lock?.request) return Promise.reject(error("CREDENTIAL_LOCK_UNAVAILABLE", "Exclusive wipe lock is required."));
            return this.lock.request(CREDENTIAL_LOCK, { mode: "exclusive" }, run);
        }
        wipe(options = {}) { return options.heldLock === HELD_CREDENTIAL_LOCK ? this._wipe(options) : this._exclusive(() => this._wipe(options)); }
        resume(options = {}) { return this._exclusive(() => this._resume(options)); }
        async _wipe({ signal, assertCurrent = () => {} } = {}) {
            if (this.running) throw error("WIPE_BUSY", "A wipe is already running.");
            if (typeof this.shutdown !== "function" || typeof this.cleanup !== "function" || typeof this.indexedDb?.databases !== "function") throw error("WIPE_UNAVAILABLE", "Complete runtime/storage wipe adapters are required.");
            this.running = true;
            try {
                assertCurrent(); if (signal?.aborted) throw error("CREDENTIAL_CANCELLED", "Wipe was cancelled before commit.");
                const old = await this.control.get(); assertCurrent();
                if (old?.state === "pending") throw error("WIPE_PENDING", "Resume the already pending wipe through an authorized recovery action.");
                const databases = await this.indexedDb.databases(); assertCurrent();
                const names = [...new Set(databases.map(item => item.name).filter(name => typeof name === "string" && name && name !== WIPE_CONTROL_DB))];
                if (names.length > 256 || names.some(name => name.length > 4096)) throw error("WIPE_INVENTORY_LIMIT", "Storage inventory exceeds the supported wipe bound.");
                const marker = { id: "wipe", version: 1, state: "pending", startedAt: Date.now(), databases: names, deleted: [], ancillaryComplete: false };
                if (signal?.aborted) throw error("CREDENTIAL_CANCELLED", "Wipe was cancelled before commit.");
                // Irreversible intent boundary. After this durable commit,
                // cancellation cannot promise rollback or permit fresh setup.
                await this.control.put(marker, { signal, assertCurrent });
                try { return await this._run(marker); }
                catch (failure) { failure.wipeAccepted = true; failure.pending = true; throw failure; }
            } finally { this.running = false; }
        }
        async _resume({ authorize } = {}) {
            if (this.running) throw error("WIPE_BUSY", "A wipe is already running.");
            if (typeof authorize !== "function" || await authorize() !== true) throw error("WIPE_AUTH_REQUIRED", "Explicit authenticated recovery/full-reset authorization is required.");
            const marker = await this.pending();
            if (!marker) return { complete: true, resumed: false };
            if (marker.version !== 1 || !Array.isArray(marker.databases) || !Array.isArray(marker.deleted) || marker.databases.some(name => typeof name !== "string" || !name || name === WIPE_CONTROL_DB)) throw error("WIPE_STATE_CORRUPT", "Pending wipe state is invalid; do not create a new identity.");
            if (typeof this.shutdown !== "function" || typeof this.cleanup !== "function") throw error("WIPE_UNAVAILABLE", "Complete runtime/storage wipe adapters are required.");
            this.running = true; try { return await this._run(marker); } finally { this.running = false; }
        }
        async _run(marker) {
            this.lifecycle.invalidate();
            await this.shutdown(); // Includes keys/workers/connections and DB handles.
            const rootDb = "dmash_device_root_v1";
            const live = new Set((await this.indexedDb.databases()).map(item => item.name).filter(name => name && name !== WIPE_CONTROL_DB));
            marker.databases = [...new Set([...marker.databases, ...live])];
            marker.deleted = marker.deleted.filter(name => !live.has(name));
            await this.control.put(marker);
            // Keep the recoverable root until all other databases and ancillary
            // storage report actual success. Cross-database wipe is resumable,
            // never represented as an atomic transaction or rollback promise.
            for (const name of marker.databases.filter(name => name !== rootDb)) {
                if (marker.deleted.includes(name)) continue;
                await this._deleteDatabase(name); marker.deleted.push(name); await this.control.put(marker);
            }
            if (!marker.ancillaryComplete) { await this.cleanup(); marker.ancillaryComplete = true; await this.control.put(marker); }
            if (marker.databases.includes(rootDb) && !marker.deleted.includes(rootDb)) {
                await this._deleteDatabase(rootDb); marker.deleted.push(rootDb); await this.control.put(marker);
            }
            const remaining = await this.indexedDb.databases();
            if (remaining.some(item => item.name && item.name !== WIPE_CONTROL_DB)) throw error("WIPE_INCOMPLETE", "Storage appeared during wipe; close other application contexts and retry.");
            marker.state = "complete"; marker.completedAt = Date.now(); await this.control.put(marker);
            return Object.freeze({ complete: true });
        }
    }
    class LocalCredentialService {
        constructor({ root = global.DeviceRoot, storage = global.localStorage, kdf = global.LocalCredentialKdf, inventory, lock = global.navigator?.locks, wipeCoordinator, lifecycle = new CredentialLifecycle(), upgradeGuard = async () => {} } = {}) {
            if (!kdf?.derive) throw error("ARGON2_UNAVAILABLE", "A credential worker or native KDF adapter is required.");
            root.credentialKdf = kdf;
            this.root = root; this.storage = storage; this.kdf = kdf; this.inventory = inventory; this.lock = lock; this.wipeCoordinator = wipeCoordinator; this.upgradeGuard = upgradeGuard;
            this.generation = 0; this.operation = null;
            this.lifecycle = lifecycle;
            this.offInvalidate = lifecycle.subscribe(() => root.invalidateStore ? root.invalidateStore() : root.lock?.());
            this.offLock = root.onLock(() => this.cancel());
        }
        cancel() { this.generation++; this.operation?.abort(); this.operation = null; }
        dispose() { this.cancel(); this.offLock(); this.offInvalidate(); this.lifecycle.close?.(); }
        _pin(pin) { if (typeof pin !== "string" || !/^\d{4,64}$/.test(pin)) throw error("INVALID_LOCAL_PIN", "Use 4 to 64 digits."); }
        _operation(run) {
            this.cancel(); const generation = this.generation, controller = new AbortController(); this.operation = controller;
            const current = () => { if (generation !== this.generation || controller.signal.aborted) throw error("CREDENTIAL_CANCELLED", "Credential operation was cancelled."); };
            const execute = async () => { current(); try {
                if (this.wipeCoordinator?.pending && await this.wipeCoordinator.pending()) throw error("WIPE_PENDING", "Local wipe is pending; explicit recovery is required before creating or unlocking an identity.");
                current(); return await run({ current, signal: controller.signal }); } finally { if (this.operation === controller) this.operation = null; } };
            // Browser/native implementations must provide an actual inter-context
            // lock. A process-local promise queue is not a cross-tab lock.
            if (!this.lock?.request) return Promise.reject(error("CREDENTIAL_LOCK_UNAVAILABLE", "Exclusive local credential lock is required."));
            return this.lock.request(CREDENTIAL_LOCK, { mode: "exclusive", signal: controller.signal }, execute);
        }
        async _prehash(pin) { return hex(new Uint8Array(await global.crypto.subtle.digest("SHA-256", new TextEncoder().encode(pin)))); }
        async _wipeVerifierFromPrehash(prehash, signal) {
            if (!/^[0-9a-f]{64}$/.test(prehash || "")) throw error("INVALID_LEGACY_WIPE", "Legacy wipe verifier is invalid.");
            if (!this.kdf?.derive) throw error("ARGON2_UNAVAILABLE", "A credential KDF adapter is required.");
            const salt = b64(global.crypto.getRandomValues(new Uint8Array(16))); let hash;
            try {
                hash = await this.kdf.derive({ pass: prehash, salt: "dmash/local-wipe/v1|" + salt, type: 2, time: 3, mem: 65536, parallelism: 1, hashLen: 32, version: 19 }, { signal });
                if (!(hash instanceof Uint8Array) || hash.length !== 32) throw error("ARGON2_FAILED", "Invalid credential KDF result.");
                return { profile: WIPE_PROFILE, salt, digest: b64(hash) };
            } finally { hash?.fill(0); }
        }
        async _cleanup(handle, current, signal) {
            const record = this.root.preparedRecord(handle);
            if (record.credentials?.legacyCleanup !== "required") return;
            current();
            try {
                this.storage.removeItem("sys_m"); this.storage.removeItem("sys_w");
                if (this.storage.getItem("sys_m") !== null || this.storage.getItem("sys_w") !== null) throw Error("cleanup not persisted");
            } catch (_) { throw Object.assign(error("MIGRATION_CLEANUP_REQUIRED", "Canonical credentials are committed; legacy cleanup remains pending. Retry using the current committed master."), { committed: true, revision: record.credentialRevision }); }
            current(); await this.root.commitPreparedMetadata(handle, { ...record.credentials, legacyCleanup: "complete" }, { signal }); current();
        }
        verifyMaster(master) {
            this._pin(master);
            return this._operation(async ({ current, signal }) => { const handle = await this.root.prepareUnlock(master, { signal }); try { current(); return true; } finally { handle.dispose(); } });
        }
        beginSetup(master) {
            this._pin(master);
            return this._operation(async ({ current, signal }) => {
                await this.upgradeGuard(); current();
                const existing = await this.root._store().get(); current();
                if (existing) {
                    this.root.validateCredentialRecord(existing);
                    if (existing.credentials?.state !== "pending-wipe") throw error("SETUP_NOT_PENDING", "Existing installation requires unlock or recovery.");
                    const resumed = await this.root.prepareUnlock(master, { signal });
                    try { current(); return { pendingSetup: true, deviceId: resumed.identity.deviceId }; } finally { resumed.dispose(); }
                }
                if (typeof this.inventory !== "function") throw error("SETUP_INVENTORY_REQUIRED", "Empty-installation inventory is required.");
                const handle = await this.root.prepareSetup(master, { assertEmpty: async () => { const empty = await this.inventory(); current(); if (empty !== true) throw error("LEGACY_MIGRATION_REQUIRED", "Existing installation data requires explicit recovery."); return true; }, signal });
                try { current(); return { pendingSetup: true, deviceId: handle.identity.deviceId }; } finally { handle.dispose(); }
            });
        }
        completeSetup(master, wipe) {
            this._pin(master); this._pin(wipe); if (master === wipe) throw error("PIN_COLLISION", "Master and wipe codes must differ.");
            return this._operation(async ({ current, signal }) => {
                const handle = await this.root.prepareUnlock(master, { signal });
                try {
                    current(); const record = this.root.preparedRecord(handle);
                    if (record.credentials?.state !== "pending-wipe") throw error("SETUP_NOT_PENDING", "This installation is already configured.");
                    const verifier = await this._wipeVerifierFromPrehash(await this._prehash(wipe), signal); current();
                    await this.root.commitPreparedMetadata(handle, { version: 1, state: "ready", wipe: verifier, legacyCleanup: "complete" }, { signal }); current();
                    return { configured: true };
                } finally { handle.dispose(); }
            });
        }
        unlock(master) {
            this._pin(master);
            return this._operation(async ({ current, signal }) => {
                const handle = await this.root.prepareUnlock(master, { signal });
                try {
                    current(); let record = this.root.preparedRecord(handle);
                    if (!record.credentials) {
                        await this.upgradeGuard(); current();
                        const oldWipe = this.storage.getItem("sys_w"), masterHash = await this._prehash(master); current();
                        const wipe = oldWipe && oldWipe !== masterHash ? await this._wipeVerifierFromPrehash(oldWipe, signal) : null; current();
                        await this.upgradeGuard(); current();
                        await this.root.commitPreparedCredentials(handle, master, { version: 1, state: "ready", wipe, wipeDisabledReason: oldWipe === masterHash ? "legacy-collision" : (wipe ? null : "not-configured"), legacyCleanup: "required" }, { signal }); current();
                        record = this.root.preparedRecord(handle);
                    }
                    if (record.credentials.state !== "ready") return { pendingSetup: true };
                    if (record.credentials.legacyCleanup === "complete" && (this.storage.getItem("sys_m") !== null || this.storage.getItem("sys_w") !== null)) {
                        await this.root.commitPreparedMetadata(handle, { ...record.credentials, legacyCleanup: "required" }, { signal }); current();
                    }
                    await this._cleanup(handle, current, signal); current();
                    return await this.root.publishPrepared(handle);
                } finally { handle.dispose(); }
            });
        }
        change(master, nextMaster, nextWipe) {
            this._pin(master); this._pin(nextMaster); this._pin(nextWipe);
            if (nextMaster === nextWipe) throw error("PIN_COLLISION", "Master and wipe codes must differ.");
            return this._operation(async ({ current, signal }) => {
                const handle = await this.root.prepareUnlock(master, { signal });
                let committed;
                try {
                    current(); const wipe = await this._wipeVerifierFromPrehash(await this._prehash(nextWipe), signal); current();
                    const result = committed = await this.root.commitPreparedCredentials(handle, nextMaster, { version: 1, state: "ready", wipe, legacyCleanup: "required" }, { signal }); current();
                    await this._cleanup(handle, current, signal); current(); return result;
                } catch (failure) {
                    if (committed || failure.committed) Object.assign(failure, { committed: true, revision: failure.revision ?? committed?.revision, masterChanged: true, useNewMaster: true });
                    throw failure;
                } finally { handle.dispose(); }
            });
        }
        prepareLegacyRecovery(passphrase) {
            if (typeof passphrase !== "string" || !passphrase) return Promise.reject(error("LEGACY_SECRET_REQUIRED", "Supply the previous credential explicitly."));
            return this._operation(async ({ current, signal }) => {
                const handle = await this.root.prepareUnlock(passphrase, { signal });
                try { current(); return handle; } catch (failure) { handle.dispose(); throw failure; }
            });
        }
        completeLegacyRecovery(handle, nextMaster, nextWipe) {
            this._pin(nextMaster); this._pin(nextWipe);
            if (nextMaster === nextWipe) throw error("PIN_COLLISION", "Master and wipe codes must differ.");
            return this._operation(async ({ current, signal }) => {
                let committed;
                try {
                    current(); this.root.preparedRecord(handle); await this.upgradeGuard(); current();
                    const wipe = await this._wipeVerifierFromPrehash(await this._prehash(nextWipe), signal); current();
                    committed = await this.root.commitPreparedCredentials(handle, nextMaster, { version: 1, state: "ready", wipe, legacyCleanup: "required" }, { signal }); current();
                    await this._cleanup(handle, current, signal); current(); return { ...committed, recovered: true };
                } catch (failure) {
                    if (committed || failure.committed) Object.assign(failure, { committed: true, revision: failure.revision ?? committed?.revision, masterChanged: true, useNewMaster: true });
                    throw failure;
                } finally { handle.dispose(); }
            });
        }
        repairFromBiometric(handle, nextMaster, nextWipe) {
            this._pin(nextMaster); this._pin(nextWipe);
            if (nextMaster === nextWipe) throw error("PIN_COLLISION", "Master and wipe codes must differ.");
            return this._operation(async ({ current, signal }) => {
                let committed;
                try {
                    await this.upgradeGuard(); current();
                    const proof = this.root.preparedAuthentication(handle);
                    if (proof.method !== "webauthn-prf" || !Number.isFinite(proof.authenticatedAt) || Date.now() - proof.authenticatedAt > 60000 || Date.now() < proof.authenticatedAt) throw error("FRESH_OS_AUTH_REQUIRED", "Fresh platform authentication is required for explicit master-wrap repair.");
                    current(); const wipe = await this._wipeVerifierFromPrehash(await this._prehash(nextWipe), signal); current();
                    const result = committed = await this.root.commitPreparedCredentials(handle, nextMaster, { version: 1, state: "ready", wipe, legacyCleanup: "required" }, { signal }); current();
                    await this._cleanup(handle, current, signal); current(); return { ...result, repaired: true };
                } catch (failure) {
                    if (committed || failure.committed) Object.assign(failure, { committed: true, revision: failure.revision ?? committed?.revision, masterChanged: true, useNewMaster: true });
                    throw failure;
                } finally { handle.dispose(); }
            });
        }
        async _matchesWipe(pin, record, signal) {
            this.root.validateCredentialRecord(record);
            const verifier = record?.credentials?.wipe;
            if (!verifier) return false;
            if (verifier.profile !== WIPE_PROFILE || typeof verifier.salt !== "string" || !/^[A-Za-z0-9+/]{22}==$/.test(verifier.salt) || b64(new Uint8Array(atob(verifier.salt).split("").map(c => c.charCodeAt(0)))) !== verifier.salt || typeof verifier.digest !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(verifier.digest)) throw error("STORAGE_CORRUPT", "Invalid wipe credential profile.");
            let bytes;
            try {
                const prehash = await this._prehash(pin);
                bytes = await this.kdf.derive({ pass: prehash, salt: "dmash/local-wipe/v1|" + verifier.salt, type: 2, time: 3, mem: 65536, parallelism: 1, hashLen: 32, version: 19 }, { signal });
                const expected = new Uint8Array(atob(verifier.digest).split("").map(c => c.charCodeAt(0)));
                if (bytes.length !== 32 || expected.length !== 32 || b64(expected) !== verifier.digest) throw error("STORAGE_CORRUPT", "Invalid wipe credential length.");
                let difference = 0; for (let i = 0; i < 32; i++) difference |= bytes[i] ^ expected[i];
                return difference === 0;
            } finally { bytes?.fill(0); }
        }
        changeWipe(master, nextWipe) {
            this._pin(master); this._pin(nextWipe);
            if (master === nextWipe) throw error("PIN_COLLISION", "Master and wipe codes must differ.");
            return this._operation(async ({ current, signal }) => {
                const handle = await this.root.prepareUnlock(master, { signal });
                let committed;
                try {
                    current(); const wipe = await this._wipeVerifierFromPrehash(await this._prehash(nextWipe), signal); current();
                    // Rewrap also upgrades legacy roots using their authenticated
                    // plaintext, without any standalone fast master verifier.
                    const result = committed = await this.root.commitPreparedCredentials(handle, master, { version: 1, state: "ready", wipe, legacyCleanup: "required" }, { signal }); current();
                    await this._cleanup(handle, current, signal); current(); return result;
                } catch (failure) {
                    if (committed || failure.committed) Object.assign(failure, { committed: true, revision: failure.revision ?? committed?.revision, masterChanged: false, useNewMaster: false });
                    throw failure;
                } finally { handle.dispose(); }
            });
        }
        wipe(pin) {
            this._pin(pin);
            return this._operation(async ({ current, signal }) => {
                const record = await this.root._store().get(); current();
                if (!(await this._matchesWipe(pin, record, signal))) throw error("WIPE_CODE_INVALID", "Wipe code was not accepted."); current();
                // Verification does not unwrap/publish root or start networking.
                // Recheck credential proof via the native read transaction before
                // invoking the coordinator while the exclusive lock is held.
                const latest = await this.root._store().get(); current();
                if (JSON.stringify(latest?.credentials) !== JSON.stringify(record?.credentials) || latest?.credentialRevision !== record?.credentialRevision) throw error("CREDENTIAL_CONFLICT", "Wipe credential changed; retry.");
                if (!this.wipeCoordinator?.wipe) throw error("WIPE_UNAVAILABLE", "Durable wipe coordinator is not installed.");
                return await this.wipeCoordinator.wipe({ signal, assertCurrent: current, heldLock: HELD_CREDENTIAL_LOCK });
            });
        }
        // Destructive integration is intentionally unavailable until a durable
        // deletion coordinator is supplied. No legacy hash can authorize it.
        emergency(master) {
            this._pin(master);
            return this._operation(async ({ current, signal }) => {
                const handle = await this.root.prepareUnlock(master, { signal });
                try { current(); if (!this.wipeCoordinator?.wipe) throw error("WIPE_UNAVAILABLE", "Durable wipe coordinator is not installed."); return await this.wipeCoordinator.wipe({ signal, assertCurrent: current, heldLock: HELD_CREDENTIAL_LOCK }); }
                finally { handle.dispose(); }
            });
        }
    }
    global.CredentialLifecycle = CredentialLifecycle;
    global.CredentialWipeControlStore = CredentialWipeControlStore;
    global.DurableWipeCoordinator = DurableWipeCoordinator;
    global.CredentialWorkerKdf = CredentialWorkerKdf;
    global.LocalCredentialService = LocalCredentialService;
    if (typeof module !== "undefined") module.exports = { LocalCredentialService, CredentialWorkerKdf, CredentialWipeControlStore, DurableWipeCoordinator, CredentialLifecycle };
})(typeof window !== "undefined" ? window : globalThis);

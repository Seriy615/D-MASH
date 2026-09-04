"use strict";

// Bump this ID for every deployed PWA release. It is intentionally visible so
// a support screenshot identifies the code a browser actually executes.
window.DMASH_RELEASE = Object.freeze({ id: "m1.5-device-auth-v2-20260901.44" });

/*
 * WebAuthn compatibility cutover.
 *
 * The March 12, 2026 PWA (24b2ed439c83704ef747dcb2bc334a6b16bf84d3)
 * used the platform authenticator directly:
 *   - explicit RP id = current hostname;
 *   - ES256;
 *   - authenticatorAttachment = platform;
 *   - userVerification = required;
 *   - residentKey = required;
 *   - PRF eval supplied on credential creation;
 *   - one credentials.get() with a 60 s timeout on unlock.
 *
 * The device-scoped implementation keeps that browser-facing WebAuthn shape,
 * while preserving the newer security boundary: the PRF wraps DeviceRoot only,
 * there is no Account credential in the WebAuthn record and no software/PIN
 * fallback when PRF is unavailable.
 */
(function installHistoricalDeviceWebAuthn(global) {
    const WRAP = "webauthn-prf-aes-256-gcm-v1";
    const PRF_BYTES = 32;
    const IV_BYTES = 12;
    const ROOT_BYTES = 32;
    const GCM_TAG_BYTES = 16;
    const AAD = new TextEncoder().encode("dmash/device-root-webauthn-prf-wrap/v1");

    const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
    const decodeB64 = (value, length) => {
        if (typeof value !== "string") throw new Error("invalid base64");
        const bytes = new Uint8Array(atob(value).split("").map((char) => char.charCodeAt(0)));
        if (length !== undefined && bytes.length !== length) throw new Error("invalid encoded length");
        return bytes;
    };
    const makeError = (code, message) => {
        if (typeof global.DeviceRootError === "function") return new global.DeviceRootError(code, message);
        const error = new Error(message); error.code = code; return error;
    };
    const rawCredentialId = (root, credential) => decodeB64(root._credentialId(credential));
    const prfInput = () => new Uint8Array(PRF_BYTES); // historical WebAuthn PRF input

    function patchDeviceRoot() {
        const root = global.DeviceRoot;
        if (!root || root.__historicalWebAuthnV1 === true) return;

        root.enrollWebAuthnPrf = async function enrollWebAuthnPrfHistorical() {
            this._requireCrypto();
            this._requireWebAuthn();
            if (!this.state?.root || !this.state?.record) {
                throw makeError("DEVICE_LOCKED", "Unlock the device with the calculator master secret before enrolling biometrics.");
            }
            if (this.state.record.biometricWrap) {
                throw makeError("WEBAUTHN_ALREADY_ENROLLED", "Device biometric authentication is already enrolled.");
            }

            const salt = prfInput();
            let credential;
            let output;
            try {
                const userId = this._crypto.getRandomValues(new Uint8Array(16));
                credential = await this._credentials().create({
                    publicKey: {
                        challenge: this._webauthnChallenge(),
                        rp: { name: "MathPro Security", id: global.location?.hostname },
                        user: { id: userId, name: "device", displayName: "MathPro Device" },
                        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                        authenticatorSelection: {
                            authenticatorAttachment: "platform",
                            userVerification: "required",
                            residentKey: "required"
                        },
                        extensions: { prf: { eval: { first: salt } } }
                    }
                });
            } catch (_) {
                throw makeError("WEBAUTHN_ENROLLMENT_FAILED", "Platform WebAuthn enrollment did not complete.");
            }

            try {
                // Historical flow consumed the PRF result returned by create().
                // Do not trigger a second biometric assertion during enrollment.
                output = this._prfResult(credential);
                const credentialId = rawCredentialId(this, credential);
                const key = await this._prfWrapKey(output);
                const iv = this._crypto.getRandomValues(new Uint8Array(IV_BYTES));
                const ciphertext = await this._crypto.subtle.encrypt(
                    { name: "AES-GCM", iv, additionalData: AAD }, key, this.state.root
                );
                const biometricWrap = {
                    wrap: WRAP,
                    credentialId: b64(credentialId),
                    prfSalt: b64(salt),
                    iv: b64(iv),
                    wrappedRoot: b64(new Uint8Array(ciphertext))
                };
                const record = { ...this.state.record, biometricWrap };
                await this._store().put(record);
                this.state.record = record;
                return Object.freeze({ enrolled: true });
            } catch (error) {
                if (error?.code) throw error;
                throw makeError("WEBAUTHN_ENROLLMENT_FAILED", "Device biometric wrapping was not saved.");
            } finally {
                output?.fill?.(0);
            }
        };

        root.unlockWithWebAuthnPrf = async function unlockWithWebAuthnPrfHistorical() {
            this._requireCrypto();
            this._requireWebAuthn();
            const record = await this._store().get();
            const wrap = record?.biometricWrap;
            let output;
            try {
                if (!record || record.version !== this.VERSION || !wrap || wrap.wrap !== WRAP) {
                    throw new Error("no supported biometric wrap");
                }
                const credentialId = decodeB64(wrap.credentialId);
                const salt = decodeB64(wrap.prfSalt, PRF_BYTES);
                const iv = decodeB64(wrap.iv, IV_BYTES);
                const wrappedRoot = decodeB64(wrap.wrappedRoot, ROOT_BYTES + GCM_TAG_BYTES);

                let assertion;
                try {
                    assertion = await this._credentials().get({
                        publicKey: {
                            challenge: this._webauthnChallenge(),
                            timeout: 60000,
                            userVerification: "required",
                            allowCredentials: [{ id: credentialId, type: "public-key" }],
                            extensions: { prf: { eval: { first: salt } } }
                        }
                    });
                } catch (_) {
                    throw makeError("WEBAUTHN_ASSERTION_FAILED", "Device biometric authentication did not unlock this device.");
                }

                output = this._prfResult(assertion);
                const key = await this._prfWrapKey(output);
                const plaintext = await this._crypto.subtle.decrypt(
                    { name: "AES-GCM", iv, additionalData: AAD }, key, wrappedRoot
                );
                const unlockedRoot = new Uint8Array(plaintext);
                if (unlockedRoot.length !== ROOT_BYTES) throw new Error("invalid root length");
                const identity = await this.deviceIdentity(unlockedRoot);
                this.state = { root: unlockedRoot, identity, created: false, record };
                return this.state;
            } catch (error) {
                if (this.state?.root) this.lock();
                if (error?.code === "WEBAUTHN_UNAVAILABLE") throw error;
                throw makeError("WEBAUTHN_UNLOCK_FAILED", "Device biometric authentication could not unlock this device.");
            } finally {
                output?.fill?.(0);
            }
        };

        Object.defineProperty(root, "__historicalWebAuthnV1", { value: true, configurable: false });
    }

    function patchLongPressUserActivation() {
        // ui_logic historically starts WebAuthn from a timer after the 3 s hold.
        // On stricter browsers that is no longer a trusted pointer event. Keep
        // the 3 s qualification, but perform credentials.create/get on pointerup
        // itself, matching the old direct-user-action WebAuthn flow.
        if (typeof ui === "undefined" || ui.__historicalWebAuthnGestureV1 === true) return;
        const keypad = document.getElementById("keypad");
        if (!keypad) return;
        const perform = ui.handleBiometricHold.bind(ui);
        ui._qualifiedBiometricToken = null;
        ui.handleBiometricHold = function qualifyHistoricalBiometricHold(token) {
            this._qualifiedBiometricToken = token;
            this._suppressToken = token;
            return Promise.resolve(false);
        };
        const tokenFor = (event) => event.target?.closest?.("[data-calc-token]")?.dataset?.calcToken || null;
        keypad.addEventListener("pointerup", (event) => {
            const token = tokenFor(event);
            if (!token || ui._qualifiedBiometricToken !== token) return;
            ui._qualifiedBiometricToken = null;
            ui._suppressToken = token;
            // Deliberately start the async WebAuthn chain before this trusted
            // pointerup handler returns.
            void perform(token);
        }, true);
        const cancel = () => { ui._qualifiedBiometricToken = null; };
        keypad.addEventListener("pointercancel", cancel, true);
        keypad.addEventListener("pointerleave", cancel, true);
        Object.defineProperty(ui, "__historicalWebAuthnGestureV1", { value: true, configurable: false });
    }

    global.addEventListener("DOMContentLoaded", () => {
        patchDeviceRoot();
        patchLongPressUserActivation();
        const badge = document.getElementById("dmash-build-id");
        if (badge) badge.textContent = `D-MASH build ${global.DMASH_RELEASE.id}`;
    });
})(window);

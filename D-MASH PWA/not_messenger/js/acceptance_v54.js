"use strict";

/*
 * D-MASH browser acceptance fixes v54.
 *
 * Emergency local recovery wipe:
 *   1020<MASTER_KEY>=
 *
 * The suffix must authenticate the existing DeviceRoot before any
 * destructive action begins. The reserved sequence is tracked separately from
 * the calculator display so it can exceed the normal decoy display length.
 * Device-biometric calculator gestures use a deliberate one-second hold.
 */
(function installAcceptanceV54(global) {
    const UI_PATCH = "__dmashAcceptanceV54EmergencyWipe";
    const PREFIX = "1020";
    const BIOMETRIC_HOLD_MS = 1000;
    const KNOWN_DATABASES = [
        "dm_gamma_vault",
        "dm_registry_v1",
        "dm_registry_secure_v1",
        "dmash_device_root_v1"
    ];

    function appUi() {
        try { if (typeof ui !== "undefined" && ui) return ui; } catch (_) {}
        return global.ui || null;
    }

    function appSys() {
        try { if (typeof sys !== "undefined" && sys) return sys; } catch (_) {}
        return global.DMashSys || null;
    }

    async function emergencyWipe(uiObject, masterKey) {
        const generation = ++uiObject.unlockGeneration;
        uiObject._credentialPending = true;
        uiObject.hist = "ПРОВЕРКА MASTER..."; uiObject.update?.();
        try {
            const service = await appSys().ensureCredentials();
            if (generation !== uiObject.unlockGeneration) return false;
            const result = await service.emergency(masterKey);
            if (result?.complete) global.location.replace("about:blank");
            return !!result?.complete;
        } catch (error) {
            if (error.wipeAccepted || generation === uiObject.unlockGeneration) { uiObject.curr = "0"; uiObject._credentialRecoveryAvailable = !!error.wipeAccepted; uiObject.hist = error.wipeAccepted ? "ОЧИСТКА НЕ ЗАВЕРШЕНА: " + error.message : uiObject.credentialError?.(error) || "ОШИБКА"; uiObject.update?.(); }
            return false;
        } finally { if (generation === uiObject.unlockGeneration) uiObject._credentialPending = false; }
    }

    function patchUi(uiObject) {
        if (!uiObject || uiObject[UI_PATCH]) return false;
        if (typeof uiObject.num !== "function" || typeof uiObject.cmd !== "function" || typeof uiObject.eval !== "function") return false;

        const originalNum = uiObject.num.bind(uiObject);
        const originalCmd = uiObject.cmd.bind(uiObject);
        const originalEval = uiObject.eval.bind(uiObject);
        const originalBeginBiometric = typeof uiObject.beginBiometricTriggerSetup === "function"
            ? uiObject.beginBiometricTriggerSetup.bind(uiObject)
            : null;

        // One second is long enough to distinguish the gesture from a tap while
        // keeping calculator biometric unlock responsive.
        uiObject.biometricHoldMs = BIOMETRIC_HOLD_MS;
        if (originalBeginBiometric) {
            uiObject.beginBiometricTriggerSetup = function beginBiometricTriggerSetupV54(...args) {
                const result = originalBeginBiometric(...args);
                if (result !== false) {
                    this.hist = `УДЕРЖИВАЙТЕ ЦИФРУ ИЛИ + − × ÷ % , ${this.biometricHoldMs / 1000} СЕК.`;
                    this.update?.();
                }
                return result;
            };
        }

        uiObject._emergencyWipeSequence = "";

        uiObject.num = function emergencySequenceNumberV54(token) {
            const suppressed = this._suppressToken === token;
            const result = originalNum(token);

            if (this.mode === 0 && !suppressed && /^[0-9]$/.test(String(token))) {
                const maxMaster = Number.isInteger(this.maxInputLength) ? this.maxInputLength : 10;
                const maxLength = PREFIX.length + maxMaster;
                this._emergencyWipeSequence = (this._emergencyWipeSequence + String(token)).slice(-maxLength);
            } else if (String(token) === ".") {
                this._emergencyWipeSequence = "";
            }
            return result;
        };

        uiObject.cmd = function emergencySequenceCommandV54(command) {
            this._emergencyWipeSequence = "";
            return originalCmd(command);
        };

        uiObject.eval = async function emergencySequenceEvalV54(...args) {
            if (this.mode === 0) {
                const sequence = String(this._emergencyWipeSequence || "");
                this._emergencyWipeSequence = "";
                if (sequence.startsWith(PREFIX)) {
                    const masterKey = sequence.slice(PREFIX.length);
                    const minLength = Number.isInteger(this.minSecretLength) ? this.minSecretLength : 4;
                    const maxLength = Number.isInteger(this.maxInputLength) ? this.maxInputLength : 10;
                    if (masterKey.length >= minLength && masterKey.length <= maxLength) {
                        if (await emergencyWipe(this, masterKey)) return;
                    } else {
                        this.curr = "0";
                        this.hist = "ОШИБКА";
                        this.op = null;
                        this.leftOperand = null;
                        this.update?.();
                    }
                    return;
                }
            }
            return originalEval(...args);
        };

        try { Object.defineProperty(uiObject, UI_PATCH, { value: true }); }
        catch (_) { uiObject[UI_PATCH] = true; }
        return true;
    }

    function install() { patchUi(appUi()); }
    if (global.DmashRuntimeReadiness) {
        global.DmashRuntimeReadiness.register("acceptance-v54-ui", 70, install, () => !!appUi()?.[UI_PATCH], ["acceptance-v51-ui"]);
        return;
    }
    install();
    const timer = setInterval(() => {
        if (patchUi(appUi())) clearInterval(timer);
    }, 25);
    setTimeout(() => clearInterval(timer), 35000);
})(window);

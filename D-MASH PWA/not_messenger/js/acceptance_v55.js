"use strict";

/* D-MASH v55: canonical emergency recovery prefix is 0010. */
(function installAcceptanceV55(global) {
    const PATCH = "__dmashAcceptanceV55EmergencyPrefix";

    function appUi() {
        try { if (typeof ui !== "undefined" && ui) return ui; } catch (_) {}
        return global.ui || null;
    }

    function patch(uiObject) {
        if (!uiObject || uiObject[PATCH] || typeof uiObject.eval !== "function") return false;
        const originalEval = uiObject.eval.bind(uiObject);
        uiObject.eval = async function emergencyPrefix0010V55(...args) {
            const sequence = String(this._emergencyWipeSequence || "");
            if (this.mode === 0 && sequence.startsWith("0010")) {
                // v54 owns the authenticated wipe implementation; translate
                // only the reserved prefix so the public combination is 0010.
                this._emergencyWipeSequence = "1020" + sequence.slice(4);
            }
            return originalEval(...args);
        };
        try { Object.defineProperty(uiObject, PATCH, { value: true }); }
        catch (_) { uiObject[PATCH] = true; }
        return true;
    }

    patch(appUi());
    const timer = setInterval(() => {
        if (patch(appUi())) clearInterval(timer);
    }, 25);
    setTimeout(() => clearInterval(timer), 35000);
})(window);

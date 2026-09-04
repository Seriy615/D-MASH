"use strict";

/*
 * Bridge the legacy classic-script lexical `const ui` into window.ui.
 *
 * ui_logic.js intentionally predates the runtime repair modules and declares
 * `const ui = {...}` at top level.  A top-level lexical binding is visible to
 * later classic scripts by identifier, but it is NOT a property of `window`.
 * runtime_fixes.js and acceptance_fixes.js are isolated IIFEs and correctly
 * look up collaborators through `window`, so without this bridge they can wait
 * forever for `window.ui` even though the visible legacy UI is already running.
 *
 * Do not duplicate UI logic here.  This file only exports the already-existing
 * object when its lexical binding becomes available.
 */
(function exposeLegacyUi(global) {
    if (global.ui) return;

    let attempts = 0;
    const expose = () => {
        attempts += 1;
        try {
            // `typeof ui` is safe before ui_logic.js has executed. Once the
            // classic script creates its global lexical binding, a later
            // classic script can resolve that identifier even though
            // `window.ui` is still absent.
            if (!global.ui && typeof ui !== "undefined" && ui) {
                global.ui = ui;
                global.dispatchEvent?.(new CustomEvent("dmash-ui-global-ready"));
                return true;
            }
        } catch (_) {}
        return false;
    };

    if (expose()) return;
    const timer = setInterval(() => {
        if (expose() || attempts > 2400) clearInterval(timer);
    }, 25);
})(window);

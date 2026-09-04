"use strict";

/*
 * Bridge legacy classic-script global lexical bindings into window properties.
 * `const ui` and `const sys` are visible to later classic scripts by identifier,
 * but are not properties of window. Runtime repair modules use window-scoped
 * collaborators deliberately, so export the existing objects without
 * duplicating their implementation.
 */
(function exposeLegacyRuntime(global) {
    let attempts = 0;
    const expose = () => {
        attempts += 1;
        let changed = false;
        try {
            if (!global.ui && typeof ui !== "undefined" && ui) {
                global.ui = ui;
                changed = true;
            }
        } catch (_) {}
        try {
            if (!global.sys && typeof sys !== "undefined" && sys) {
                global.sys = sys;
                changed = true;
            }
        } catch (_) {}
        if (changed) global.dispatchEvent?.(new CustomEvent("dmash-ui-global-ready"));
        return !!global.ui && !!global.sys;
    };

    if (expose()) return;
    const timer = setInterval(() => {
        if (expose() || attempts > 2400) clearInterval(timer);
    }, 25);
})(window);

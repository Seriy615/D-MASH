"use strict";

// One visible release identifier for the page and Service Worker generation.
window.DMASH_RELEASE = Object.freeze({ id: "m1.5-functional-repair-20260904.45" });

/*
 * Runtime repair loader.
 *
 * Do not patch DeviceRoot here at DOMContentLoaded: the legacy shell loads the
 * crypto/core modules lazily after calculator unlock, so a one-shot DOM hook
 * races them and was the reason the previous biometric compatibility patch was
 * often never installed. runtime_fixes.js waits for the actual objects.
 */
(function loadFunctionalRepair(global) {
    const ver = encodeURIComponent(global.DMASH_RELEASE.id);
    const css = document.createElement("link");
    css.rel = "stylesheet";
    css.href = `css/runtime_fixes.css?r=${ver}`;
    document.head.appendChild(css);

    const support = [
        "js/contact_payloads.js",
        "js/contact_transport.js",
        "js/pending_contact_requests.js",
        "js/resource_pow.js",
        "js/runtime_fixes.js"
    ];

    const load = src => new Promise((resolve, reject) => {
        const existing = Array.from(document.scripts).find(script => script.src && new URL(script.src, location.href).pathname.endsWith("/" + src));
        if (existing) return resolve();
        const script = document.createElement("script");
        script.src = `${src}?r=${ver}`;
        script.onload = resolve;
        script.onerror = () => reject(new Error(`Failed to load ${src}`));
        document.head.appendChild(script);
    });

    const start = async () => {
        const badge = document.getElementById("dmash-build-id");
        if (badge) badge.textContent = `D-MASH build ${global.DMASH_RELEASE.id}`;
        try {
            for (const src of support) await load(src);
        } catch (error) {
            console.error("D-MASH functional repair loader failed", error);
            const notice = document.getElementById("dmash-release-notice");
            if (notice) {
                notice.textContent = "D-MASH repair modules failed to load. Reload the application.";
                notice.style.display = "block";
            }
        }
    };

    if (document.readyState === "loading") global.addEventListener("DOMContentLoaded", start, { once: true });
    else void start();
})(window);

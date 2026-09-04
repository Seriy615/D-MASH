"use strict";

// Bump this ID for every deployed PWA release. It is intentionally visible so
// a support screenshot identifies the code a browser actually executes.
window.DMASH_RELEASE = Object.freeze({ id: "m1.5-device-auth-v2-20260901.40" });

window.addEventListener("DOMContentLoaded", () => {
    const badge = document.getElementById("dmash-build-id");
    if (badge) badge.textContent = `D-MASH build ${window.DMASH_RELEASE.id}`;
});

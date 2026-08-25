"use strict";

(() => {
    const DEFAULT_LOCALE = "en";
    const STORAGE_KEY = "dmash.locale";
    const subscribers = new Set();

    const normalize = (value) => typeof value === "string" ? value.replace(/_/g, "-") : "";
    const languageOf = (value) => normalize(value).split("-")[0].toLowerCase();
    const catalogs = () => window.DMASH_LOCALES || {};

    function supported(locale) {
        const normalized = normalize(locale);
        const available = catalogs();
        if (available[normalized]) return normalized;
        const language = languageOf(normalized);
        return Object.keys(available).find((entry) => languageOf(entry) === language) || null;
    }

    function resolveLocale() {
        const saved = supported(localStorage.getItem(STORAGE_KEY));
        if (saved) return saved;
        for (const candidate of navigator.languages || []) {
            const found = supported(candidate);
            if (found) return found;
        }
        return supported(navigator.language) || DEFAULT_LOCALE;
    }

    let activeLocale = resolveLocale();

    function valueAt(object, path) {
        return path.split(".").reduce((current, part) => current && current[part], object);
    }

    function interpolate(value, values) {
        return String(value).replace(/\{([\w.-]+)\}/g, (_, key) => values[key] ?? `{${key}}`);
    }

    function translate(key, values = {}) {
        const active = valueAt(catalogs()[activeLocale], key);
        const fallback = valueAt(catalogs()[DEFAULT_LOCALE], key);
        const message = active ?? fallback;
        if (message === undefined) {
            console.warn(`[D-MASH i18n] Missing key: ${key}`);
            return key;
        }
        if (typeof message === "object" && message !== null && "one" in message) {
            const count = Number(values.count ?? 0);
            const category = new Intl.PluralRules(activeLocale).select(count);
            return interpolate(message[category] ?? message.other, values);
        }
        return interpolate(message, values);
    }

    function setLocale(locale) {
        const resolved = supported(locale);
        if (!resolved) throw new Error(`Unsupported locale: ${locale}`);
        activeLocale = resolved;
        localStorage.setItem(STORAGE_KEY, resolved);
        document.documentElement.lang = resolved;
        document.documentElement.dir = "ltr";
        for (const listener of subscribers) listener(resolved);
        return resolved;
    }

    function locale() { return activeLocale; }
    function onChange(listener) { subscribers.add(listener); return () => subscribers.delete(listener); }
    function formatDate(value, options) { return new Intl.DateTimeFormat(activeLocale, options).format(new Date(value)); }
    function formatRelative(value) {
        const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000);
        const unit = Math.abs(seconds) < 60 ? "second" : Math.abs(seconds) < 3600 ? "minute" : "hour";
        const divisor = unit === "second" ? 1 : unit === "minute" ? 60 : 3600;
        return new Intl.RelativeTimeFormat(activeLocale, { numeric: "auto" }).format(Math.round(seconds / divisor), unit);
    }

    window.DMashI18n = Object.freeze({ t: translate, setLocale, locale, onChange, formatDate, formatRelative, supported: () => Object.keys(catalogs()) });
    document.documentElement.lang = activeLocale;
    document.documentElement.dir = "ltr";
})();

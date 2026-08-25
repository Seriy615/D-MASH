"use strict";

/*
 * D-MASH application shell. This layer owns navigation and presentation only.
 * Cryptographic state, message storage and node transport remain in Core/Storage/NodeManager.
 */
(() => {
    const text = (key, values) => window.DMashI18n?.t(key, values) || key;
    const make = (tag, options = {}, children = []) => {
        const node = document.createElement(tag);
        if (options.className) node.className = options.className;
        if (options.id) node.id = options.id;
        if (options.type) node.type = options.type;
        if (options.text !== undefined) node.textContent = options.text;
        if (options.label) node.setAttribute("aria-label", options.label);
        if (options.attrs) Object.entries(options.attrs).forEach(([name, value]) => node.setAttribute(name, value));
        if (options.onClick) node.addEventListener("click", options.onClick);
        for (const child of children) node.append(child);
        return node;
    };

    const App = {
        current: "chats",
        unsubscribeLocale: null,

        mountWorkspace(core) {
            const workspace = document.getElementById("workspace");
            workspace.replaceChildren();
            workspace.className = "dmash-ui";
            workspace.dataset.release = window.DMASH_RELEASE?.id || "development";

            const shell = make("div", { className: "dmash-shell", id: "dmash-app-shell" });
            const sidebar = this.createSidebar(core);
            const content = make("main", { className: "dmash-content", id: "main-grid", attrs: { "aria-live": "polite" } });
            const chat = this.createChatSurface(core);
            const contacts = make("section", { className: "dmash-screen", id: "dmash-contacts-screen", attrs: { hidden: "", "aria-labelledby": "dmash-contacts-title" } });
            const network = make("section", { className: "dmash-screen", id: "dmash-network-screen", attrs: { hidden: "", "aria-labelledby": "dmash-network-title" } });
            const settings = make("section", { className: "dmash-screen", id: "dmash-settings-screen", attrs: { hidden: "", "aria-labelledby": "dmash-settings-title" } });

            content.append(chat, contacts, network, settings);
            shell.append(sidebar, content, this.createBottomNavigation(core));
            workspace.append(shell);
            this.renderContacts(core);
            this.renderNetwork(core);
            this.renderSettings(core);
            this.listenForState(core);
            this.navigate("chats");

            this.unsubscribeLocale?.();
            this.unsubscribeLocale = window.DMashI18n?.onChange(() => this.refresh(core));
        },

        refresh(core) {
            const active = this.current;
            this.renderContacts(core);
            this.renderNetwork(core);
            this.renderSettings(core);
            this.updateNavigation();
            this.navigate(active);
        },

        createSidebar(core) {
            const sidebar = make("aside", { className: "dmash-sidebar", attrs: { "aria-label": text("nav.primary") } });
            const brand = make("button", { className: "dmash-brand", type: "button", onClick: () => this.navigate("chats") }, [
                make("span", { className: "dmash-brand-mark", text: "D" }),
                make("span", { className: "dmash-brand-copy" }, [make("strong", { text: "D-MASH" }), make("small", { text: text("release.privateMessenger") })])
            ]);
            const nav = make("nav", { className: "dmash-primary-nav", attrs: { "aria-label": text("nav.primary") } });
            for (const item of this.navigationItems()) {
                nav.append(make("button", { className: "dmash-nav-item", type: "button", attrs: { "data-nav": item.id }, onClick: () => this.navigate(item.id) }, [
                    make("span", { className: "dmash-nav-icon", text: item.icon, attrs: { "aria-hidden": "true" } }),
                    make("span", { text: text(item.key), attrs: { "data-nav-label": item.id } })
                ]));
            }
            const contactHeader = make("div", { className: "dmash-sidebar-section" }, [
                make("div", { className: "dmash-section-title", text: text("chats.title") }),
                make("button", { className: "dmash-icon-button", type: "button", label: text("contacts.add"), text: "+", onClick: () => core.addPeerPrompt() })
            ]);
            const list = make("div", { id: "contact-list", className: "dmash-contact-list", attrs: { role: "list" } });
            const account = make("button", { className: "dmash-identity-summary", type: "button", onClick: () => this.navigate("settings") }, [
                make("span", { className: "dmash-avatar", text: (core.activeIdentity || "D").slice(0, 1).toUpperCase() }),
                make("span", { className: "dmash-identity-copy" }, [
                    make("strong", { text: core.activeIdentity || text("settings.identity") }),
                    make("small", { text: text("security.protected") })
                ])
            ]);
            sidebar.append(brand, nav, contactHeader, list, account);
            return sidebar;
        },

        createBottomNavigation() {
            const nav = make("nav", { className: "dmash-bottom-nav", attrs: { "aria-label": text("nav.primary") } });
            for (const item of this.navigationItems()) {
                nav.append(make("button", { className: "dmash-nav-item", type: "button", attrs: { "data-nav": item.id }, onClick: () => this.navigate(item.id) }, [
                    make("span", { className: "dmash-nav-icon", text: item.icon, attrs: { "aria-hidden": "true" } }),
                    make("span", { text: text(item.key), attrs: { "data-nav-label": item.id } })
                ]));
            }
            return nav;
        },

        createChatSurface(core) {
            const section = make("section", { className: "dmash-chat-screen", id: "dmash-chats-screen", attrs: { "aria-label": text("chats.title") } });
            const header = make("header", { id: "chat-header", className: "dmash-chat-header" }, [
                make("button", { id: "back-btn", className: "dmash-icon-button", type: "button", label: text("common.back"), text: "←", onClick: () => core.closeChat() }),
                make("div", { className: "dmash-chat-heading" }, [
                    make("strong", { id: "chat-title", text: text("chats.selectConversation") }),
                    make("span", { className: "dmash-security-indicator", text: text("security.protected") })
                ]),
                make("div", { className: "dmash-header-actions" }, [
                    make("button", { id: "voip-btn", className: "dmash-icon-button", type: "button", label: text("chats.call"), text: "☎", attrs: { hidden: "" }, onClick: () => core.initVoip() }),
                    make("button", { className: "dmash-icon-button", type: "button", label: text("settings.title"), text: "⋯", onClick: () => this.navigate("settings") })
                ])
            ]);
            const empty = make("div", { className: "dmash-chat-empty", id: "dmash-chat-empty" }, [
                make("div", { className: "dmash-empty-icon", text: "✦", attrs: { "aria-hidden": "true" } }),
                make("h1", { text: text("chats.welcomeTitle") }),
                make("p", { text: text("chats.welcomeBody") }),
                make("button", { className: "dmash-button dmash-button--primary", type: "button", text: text("contacts.add"), onClick: () => core.addPeerPrompt() })
            ]);
            const log = make("div", { id: "log", className: "dmash-message-log", attrs: { role: "log", "aria-label": text("chats.messages") } });
            const composer = make("form", { id: "input-area", className: "dmash-composer", attrs: { hidden: "" } });
            composer.addEventListener("submit", event => { event.preventDefault(); core.sendMessage(); });
            composer.append(
                make("button", { className: "dmash-icon-button", type: "button", label: text("chats.attachment"), text: "+", onClick: () => core.uiAttach() }),
                make("textarea", { id: "msgInput", attrs: { rows: "1", placeholder: text("chats.compose"), spellcheck: "false" } }),
                make("button", { id: "circle-btn", className: "dmash-icon-button", type: "button", label: text("chats.recordVideo"), text: "○", onClick: () => core.uiCircle() }),
                make("button", { id: "voice-btn", className: "dmash-icon-button", type: "button", label: text("chats.recordVoice"), text: "◉", onClick: () => core.uiVoice() }),
                make("button", { className: "dmash-button dmash-button--primary", type: "submit", text: text("chats.send") })
            );
            section.append(header, empty, log, composer);
            return section;
        },

        navigationItems() {
            return [
                { id: "chats", icon: "◌", key: "nav.chats" },
                { id: "contacts", icon: "◎", key: "nav.contacts" },
                { id: "network", icon: "◍", key: "nav.network" },
                { id: "settings", icon: "⚙", key: "nav.settings" }
            ];
        },

        navigate(target) {
            this.current = target;
            const screens = {
                chats: "dmash-chats-screen",
                contacts: "dmash-contacts-screen",
                network: "dmash-network-screen",
                settings: "dmash-settings-screen"
            };
            for (const [name, id] of Object.entries(screens)) {
                const screen = document.getElementById(id);
                if (!screen) continue;
                screen.hidden = name !== target;
            }
            document.querySelectorAll("[data-nav]").forEach(node => {
                const selected = node.dataset.nav === target;
                node.classList.toggle("is-active", selected);
                node.setAttribute("aria-current", selected ? "page" : "false");
            });
        },

        renderContacts(core) {
            const screen = document.getElementById("dmash-contacts-screen");
            if (!screen) return;
            screen.replaceChildren(
                this.screenHeader(text("contacts.title"), text("contacts.subtitle"), make("button", { className: "dmash-button dmash-button--primary", type: "button", text: text("contacts.add"), onClick: () => core.addPeerPrompt() })),
                make("div", { className: "dmash-search" }, [make("span", { text: "⌕", attrs: { "aria-hidden": "true" } }), make("input", { attrs: { type: "search", placeholder: text("contacts.search"), "aria-label": text("contacts.search") } })]),
                make("div", { className: "dmash-panel dmash-empty-state" }, [make("h2", { text: text("contacts.emptyTitle") }), make("p", { text: text("contacts.emptyBody") })])
            );
        },

        renderNetwork(core) {
            const screen = document.getElementById("dmash-network-screen");
            if (!screen) return;
            const manager = window.NodeManager;
            const state = manager?.state || "disconnected";
            const active = manager?.active;
            const status = this.statusBadge(state);
            const nodes = make("div", { className: "dmash-node-list", id: "dmash-node-list" });
            if (!manager?.endpoints?.length) nodes.append(this.emptyState(text("network.emptyTitle"), text("network.emptyBody")));
            for (const endpoint of manager?.endpoints || []) nodes.append(this.nodeItem(endpoint, manager));
            const actions = make("div", { className: "dmash-action-row" }, [
                make("button", { className: "dmash-button dmash-button--primary", type: "button", text: state === "connected" ? text("network.disconnect") : text("network.connect"), onClick: () => this.connectOrDisconnect(manager) }),
                make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: manager?.transportMode === "legacy" ? "Legacy Relay (explicit)" : "D-MASH Mesh (default)", onClick: () => { manager.setTransportMode(manager.transportMode === "legacy" ? "mesh" : "legacy"); this.renderNetwork(core); } }),
                make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("network.refresh"), onClick: async () => { try { await manager.loadOriginList(); this.renderNetwork(core); } catch (error) { this.showToast(error.message, true); } } })
            ]);
            screen.replaceChildren(
                this.screenHeader(text("network.title"), text("network.subtitle")),
                make("article", { className: "dmash-panel dmash-current-node" }, [
                    make("div", { className: "dmash-panel-heading" }, [make("div", {}, [make("span", { className: "dmash-eyebrow", text: text("network.currentNode") }), make("h2", { text: active?.label || text("network.noNode") })]), status]),
                    make("p", { className: "dmash-endpoint", text: active?.url || text("network.noNodeDescription"), attrs: { "data-mono": "" } }),
                    make("p", { className: "dmash-muted", text: this.networkHint(manager) }), actions
                ]),
                make("div", { className: "dmash-section-heading" }, [make("h2", { text: text("network.knownNodes") }), make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("network.addNode"), onClick: () => this.openNodeDialog(core) })]),
                nodes
            );
        },

        nodeItem(endpoint, manager) {
            const selected = manager.active?.url === endpoint.url;
            return make("article", { className: `dmash-node-item${selected ? " is-selected" : ""}` }, [
                make("button", { className: "dmash-node-main", type: "button", onClick: () => { manager.select(endpoint.url); this.renderNetwork(window.Core); } }, [
                    make("span", { className: "dmash-node-dot", attrs: { "aria-hidden": "true" } }),
                    make("span", { className: "dmash-node-copy" }, [make("strong", { text: endpoint.label }), make("small", { text: endpoint.url, attrs: { "data-mono": "" } })]),
                    make("span", { className: "dmash-node-selection", text: selected ? text("network.primary") : text("network.select") })
                ]),
                make("button", { className: "dmash-icon-button", type: "button", label: text("network.remove"), text: "×", onClick: () => { manager.remove(endpoint.url); this.renderNetwork(window.Core); } })
            ]);
        },

        renderSettings(core) {
            const screen = document.getElementById("dmash-settings-screen");
            if (!screen) return;
            const language = make("select", { attrs: { "aria-label": text("settings.language") } });
            for (const locale of window.DMashI18n?.supported() || ["en", "ru"]) {
                const option = make("option", { text: locale === "ru" ? "Русский" : "English", attrs: { value: locale } });
                option.selected = window.DMashI18n?.locale() === locale;
                language.append(option);
            }
            language.addEventListener("change", event => window.DMashI18n?.setLocale(event.target.value));
            screen.replaceChildren(
                this.screenHeader(text("settings.title"), text("settings.subtitle")),
                this.settingsSection(text("settings.identity"), text("settings.identityDescription"), [
                    this.settingRow(text("settings.displayName"), core.activeIdentity || text("settings.notAvailable")),
                    this.settingRow(text("settings.fingerprint"), core.keys?.server_id ? `${core.keys.server_id.slice(0, 16)}…` : text("settings.notAvailable"), true),
                    make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("settings.showQr"), onClick: () => core.showMyQR() })
                ]),
                this.settingsSection(text("settings.preferences"), text("settings.preferencesDescription"), [
                    this.settingRow(text("settings.language"), language),
                    this.settingRow(text("settings.appearance"), this.themeControl())
                ]),
                this.settingsSection(text("settings.network"), text("settings.networkDescription"), [
                    make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("network.title"), onClick: () => this.navigate("network") })
                ]),
                this.settingsSection(text("settings.notifications"), text("settings.notificationsDescription"), [
                    make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("notifications.personalBot"), onClick: () => this.openNotifications(core) })
                ]),
                this.settingsSection(text("settings.advanced"), text("settings.advancedDescription"), [
                    make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("settings.diagnostics"), onClick: () => this.openDiagnostics() }),
                    this.settingRow(text("release.buildId"), window.DMASH_RELEASE?.id || "development", true)
                ])
            );
        },

        screenHeader(title, subtitle, action) {
            const heading = make("header", { className: "dmash-screen-header" }, [make("div", {}, [make("h1", { text: title }), make("p", { text: subtitle })])]);
            if (action) heading.append(action);
            return heading;
        },

        settingsSection(title, description, children) {
            return make("section", { className: "dmash-settings-section" }, [make("div", { className: "dmash-settings-section-heading" }, [make("h2", { text: title }), make("p", { text: description })]), make("div", { className: "dmash-panel dmash-settings-rows" }, children)]);
        },

        settingRow(label, value, mono = false) {
            const valueNode = value instanceof Element ? value : make("span", { text: value, className: mono ? "dmash-value-mono" : "" });
            return make("div", { className: "dmash-setting-row" }, [make("span", { text: label }), valueNode]);
        },

        themeControl() {
            const select = make("select", { attrs: { "aria-label": text("settings.appearance") } });
            for (const theme of ["system", "dark", "light"]) {
                const option = make("option", { text: text(`settings.theme.${theme}`), attrs: { value: theme } });
                option.selected = (localStorage.getItem("dmash.theme") || "system") === theme;
                select.append(option);
            }
            select.addEventListener("change", event => this.setTheme(event.target.value));
            return select;
        },

        setTheme(theme) {
            localStorage.setItem("dmash.theme", theme);
            document.documentElement.dataset.theme = theme === "system" ? "" : theme;
        },

        statusBadge(state) {
            const normalized = ["connected", "connecting", "reconnecting", "error"].includes(state) ? state : "offline";
            return make("span", { className: `dmash-status dmash-status--${normalized}`, text: text(`network.status.${normalized}`) });
        },

        networkHint(manager) {
            if (!manager?.active) return text("network.selectHint");
            if (!window.Core?.keys?.sign) return text("network.unlockHint");
            if (manager.transportMode !== "legacy") return "D-MASH Mesh mode: message bridge is not active yet; legacy relay is blocked";
            if (manager.state === "reconnecting") return text("network.reconnectingHint");
            if (manager.error) return text("network.errorHint");
            if (Number.isFinite(manager.lastLatencyMs)) return `${text("network.readyHint")} ${text("network.latency", { value: manager.lastLatencyMs })}`;
            return text("network.readyHint");
        },

        connectOrDisconnect(manager) {
            if (!manager) return;
            if (manager.state === "connected" || manager.state === "connecting") {
                manager.disconnect(false);
                return;
            }
            manager.connect().catch(error => this.showToast(this.userNetworkError(error), true));
        },

        userNetworkError(error) {
            const message = error?.message || String(error);
            if (/identity is not unlocked/i.test(message)) return text("network.unlockHint");
            if (/select a node/i.test(message)) return text("network.selectHint");
            return text("network.connectionError");
        },

        openNodeDialog(core) {
            const form = make("form", { className: "dmash-dialog-card" });
            const label = make("label", { text: text("network.nodeEndpoint") });
            const endpoint = make("input", { attrs: { type: "url", required: "", placeholder: "wss://node.example/dmash-client/v1", autocomplete: "off" } });
            const name = make("input", { attrs: { type: "text", placeholder: text("network.nodeName"), autocomplete: "off" } });
            label.append(endpoint);
            form.append(make("h2", { text: text("network.addNode") }), label, make("label", { text: text("network.nodeName") }, [name]), make("p", { className: "dmash-dialog-error", id: "dmash-node-dialog-error" }), make("div", { className: "dmash-action-row" }, [
                make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("common.cancel"), onClick: () => this.closeDialog() }),
                make("button", { className: "dmash-button dmash-button--primary", type: "submit", text: text("common.save") })
            ]));
            form.addEventListener("submit", event => {
                event.preventDefault();
                try { window.NodeManager.add(endpoint.value.trim(), name.value.trim()); window.NodeManager.select(endpoint.value.trim()); this.closeDialog(); this.renderNetwork(core); }
                catch (error) { document.getElementById("dmash-node-dialog-error").textContent = this.userNetworkError(error); }
            });
            this.openDialog(form);
            endpoint.focus();
        },

        openNotifications(core) {
            const manager = window.NodeManager;
            const form = make("form", { className: "dmash-dialog-card" });
            const url = make("input", { attrs: { type: "url", placeholder: "https://origin.example", autocomplete: "off" } });
            url.value = localStorage.getItem(manager?.originKey || "") || "";
            const token = make("input", { attrs: { type: "password", placeholder: text("notifications.token"), autocomplete: "new-password" } });
            const status = make("p", { className: "dmash-dialog-error", id: "dmash-notification-status" });
            const connect = make("button", { className: "dmash-button dmash-button--primary", type: "submit", text: text("notifications.connect") });
            form.append(make("h2", { text: text("notifications.personalBot") }), make("p", { text: text("notifications.personalBotDescription") }), make("label", { text: text("notifications.originUrl") }, [url]), make("label", { text: text("notifications.botToken") }, [token]), status, make("div", { className: "dmash-action-row" }, [make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("common.cancel"), onClick: () => this.closeDialog() }), connect]));
            form.addEventListener("submit", async event => {
                event.preventDefault();
                try {
                    const origin = new URL(url.value.trim());
                    if (origin.protocol !== "https:") throw new Error("origin");
                    localStorage.setItem(manager.originKey, origin.href.replace(/\/$/, ""));
                    const enrolled = await manager.enrollPersonalBot(token.value);
                    token.value = "";
                    status.className = "dmash-dialog-success";
                    status.textContent = text("notifications.waitingForTelegram");
                    if (enrolled.deep_link) {
                        const link = make("a", { text: text("notifications.openTelegram"), attrs: { href: enrolled.deep_link, target: "_blank", rel: "noopener noreferrer" } });
                        status.replaceChildren(make("span", { text: `${text("notifications.waitingForTelegram")} ` }), link);
                    }
                } catch (error) { token.value = ""; status.textContent = this.userNetworkError(error); }
            });
            this.openDialog(form);
        },

        async openDiagnostics() {
            const details = await this.runtimeDiagnostics();
            const pre = make("pre", { className: "dmash-diagnostics", text: details, attrs: { "data-mono": "" } });
            this.openDialog(make("div", { className: "dmash-dialog-card" }, [make("h2", { text: text("settings.diagnostics") }), pre, make("button", { className: "dmash-button dmash-button--secondary", type: "button", text: text("common.copy"), onClick: () => navigator.clipboard?.writeText(details).then(() => this.showToast(text("common.copied"))) }), make("button", { className: "dmash-button dmash-button--primary", type: "button", text: text("common.done"), onClick: () => this.closeDialog() })]));
        },

        async runtimeDiagnostics() {
            const scripts = performance.getEntriesByType("resource").map(entry => entry.name).filter(url => /\/(ui_logic|core_engine|node_manager|app_shell|release)\.js(?:\?|$)/.test(url));
            let cacheKeys = [];
            try { cacheKeys = await caches.keys(); } catch (_) { cacheKeys = ["unavailable"]; }
            return [
                `build=${window.DMASH_RELEASE?.id || "missing"}`,
                `href=${location.href}`,
                `origin=${location.origin}`,
                `serviceWorker=${navigator.serviceWorker.controller?.scriptURL || "none"}`,
                `scope=${(await navigator.serviceWorker.getRegistration())?.scope || "none"}`,
                `nodeState=${window.NodeManager?.state || "unavailable"}`,
                `activeNode=${window.NodeManager?.active?.url || "none"}`,
                `caches=${cacheKeys.join(",") || "none"}`,
                "assets=",
                ...scripts
            ].join("\n");
        },

        openDialog(content) {
            let dialog = document.getElementById("dmash-dialog");
            if (!dialog) {
                dialog = make("dialog", { id: "dmash-dialog", className: "dmash-dialog" });
                document.body.append(dialog);
                dialog.addEventListener("click", event => { if (event.target === dialog) dialog.close(); });
            }
            dialog.replaceChildren(content);
            dialog.showModal();
        },

        closeDialog() { document.getElementById("dmash-dialog")?.close(); },

        showToast(message, isError = false) {
            let toast = document.getElementById("dmash-toast");
            if (!toast) { toast = make("div", { id: "dmash-toast", className: "dmash-toast", attrs: { role: "status", "aria-live": "polite" } }); document.body.append(toast); }
            toast.textContent = message;
            toast.classList.toggle("is-error", isError);
            toast.classList.add("is-visible");
            clearTimeout(this.toastTimer);
            this.toastTimer = setTimeout(() => toast.classList.remove("is-visible"), 4200);
        },

        emptyState(title, description) { return make("div", { className: "dmash-panel dmash-empty-state" }, [make("h2", { text: title }), make("p", { text: description })]); },

        listenForState(core) {
            if (this.stateListener) window.removeEventListener("dmash-node-state", this.stateListener);
            this.stateListener = () => this.renderNetwork(core);
            window.addEventListener("dmash-node-state", this.stateListener);
            const theme = localStorage.getItem("dmash.theme") || "system";
            this.setTheme(theme);
        },

        updateNavigation() {
            document.querySelectorAll("[data-nav-label]").forEach(node => node.textContent = text(this.navigationItems().find(item => item.id === node.dataset.navLabel)?.key || ""));
        }
    };

    window.DMashApp = Object.freeze(App);
})();

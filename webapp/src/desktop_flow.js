// System-browser login for Mattermost Desktop ("external_browser" mode).
//
// DOM- and React-free: every environment dependency is injected via `env`, so the
// state machine runs under `node --test` (see test/desktop_flow.test.js).
//
//   idle -> starting -> waiting -> redeeming -> done
//                          \-> error (flow stays open until it expires or is cancelled)
//
// Secrets: `dv` (the desktop verifier) is created here, kept only in
// sessionStorage of this view and sent only in the redeem request body. The
// server learns SHA-256(dv) at start and checks it at redeem. The handoff code
// that comes back via mattermost://...?oidc_desktop_code=... is removed from the
// URL before any network call. No session token ever passes through this module.

const PLUGIN_BASE = '/plugins/mattermost-oidc/oauth2';
const FLOW_KEY = 'mattermost_oidc_desktop_flow';
const CODE_PARAM = 'oidc_desktop_code';
const FLOW_TTL_MS = 10 * 60 * 1000;
const WATCH_INTERVAL_MS = 300;
const ERROR_MESSAGE = 'Anmeldung nicht möglich. Bitte erneut versuchen.';

export function isDesktopUserAgent(userAgent) {
    const ua = typeof userAgent === 'string' ? userAgent : '';
    return ua.indexOf('Mattermost') !== -1 && ua.indexOf('Electron') !== -1;
}

// 'browser' (regular browser), 'popup' (Desktop, RC2 behaviour) or 'external_browser'.
export function selectDesktopLoginMode({publicConfig, userAgent}) {
    if (!isDesktopUserAgent(userAgent)) {
        return 'browser';
    }
    if (publicConfig && publicConfig.desktop_login_mode === 'external_browser') {
        return 'external_browser';
    }
    return 'popup';
}

// Same-origin relative path only; anything else becomes '/'.
export function safeReturnTo(value) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) {
        return '/';
    }
    for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        if (c < 0x20 || c === 0x7f) {
            return '/';
        }
    }
    return value;
}

function toBase64Url(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
        bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Base64Url(env, text) {
    const digest = await env.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return toBase64Url(new Uint8Array(digest));
}

function isUsableAuthorizeUrl(raw, env) {
    let u;
    try {
        u = new URL(raw);
    } catch (e) {
        return false;
    }
    return u.protocol === 'https:' && !u.username && !u.password && u.origin !== env.location.origin;
}

export function createDesktopFlow(env) {
    const listeners = [];
    const attempted = new Set(); // handoff codes already sent (or discarded): never twice
    let timer = null;
    // Every async continuation belongs to the flow that started it. A user can
    // cancel or restart while crypto/fetch is pending, so stale continuations
    // must not open a browser, remove a newer verifier, or navigate the view.
    let generation = 0;

    const flow = {
        state: 'idle',
        message: '',
        subscribe(fn) {
            listeners.push(fn);
            return () => {
                const i = listeners.indexOf(fn);
                if (i >= 0) {
                    listeners.splice(i, 1);
                }
            };
        },
    };

    function setState(state, message = '') {
        flow.state = state;
        flow.message = message;
        listeners.slice().forEach((fn) => fn(flow));
    }

    function readRecord() {
        try {
            const rec = JSON.parse(env.sessionStorage.getItem(FLOW_KEY));
            if (rec && typeof rec.dv === 'string' && typeof rec.startedAt === 'number') {
                return rec;
            }
        } catch (e) {
            // fall through: no usable flow
        }
        return null;
    }

    function stopWatcher() {
        if (timer !== null) {
            env.clearInterval(timer);
            timer = null;
        }
    }

    function startWatcher() {
        if (timer === null) {
            // Local URL comparison only; this never talks to the server.
            timer = env.setInterval(() => {
                flow.check();
            }, WATCH_INTERVAL_MS);
        }
    }

    function discard() {
        stopWatcher();
        env.sessionStorage.removeItem(FLOW_KEY);
    }

    function isCurrent(flowGeneration) {
        return generation === flowGeneration;
    }

    function currentCode() {
        const code = new URLSearchParams(env.location.search).get(CODE_PARAM);
        return code || null;
    }

    // Remove the handoff code from the address bar before anything else happens.
    function stripCodeFromUrl() {
        const params = new URLSearchParams(env.location.search);
        params.delete(CODE_PARAM);
        const qs = params.toString();
        env.history.replaceState(null, '', env.location.pathname + (qs ? `?${qs}` : '') + (env.location.hash || ''));
    }

    flow.cancel = function cancel() {
        // The browser applies Set-Cookie before fetch resolves. Do not allow a
        // competing login flow while a redeem response may still create a
        // session, otherwise that response could invalidate the new flow.
        if (flow.state === 'redeeming') {
            return;
        }
        generation += 1;
        discard();
        setState('idle');
    };

    flow.useInAppPopup = function useInAppPopup({returnTo} = {}) {
        if (flow.state === 'redeeming') {
            return;
        }
        flow.cancel();
        // Unchanged RC2 popup flow.
        const target = safeReturnTo(returnTo);
        env.open(`${PLUGIN_BASE}/connect?return_to=${encodeURIComponent(target)}&popup=1`, 'oidc_login', 'width=520,height=680');
    };

    flow.start = async function start({returnTo} = {}) {
        if (flow.state === 'redeeming') {
            return;
        }
        const flowGeneration = generation + 1;
        generation = flowGeneration;
        discard(); // at most one flow per view; the old dv is gone
        setState('starting');

        const bytes = new Uint8Array(32);
        env.crypto.getRandomValues(bytes);
        const dv = `dv1_${toBase64Url(bytes)}`;
        env.sessionStorage.setItem(FLOW_KEY, JSON.stringify({dv, startedAt: env.now()}));

        let authorizeUrl;
        try {
            const challenge = await sha256Base64Url(env, dv);
            const res = await env.fetch(`${PLUGIN_BASE}/desktop/start`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                credentials: 'same-origin',
                body: JSON.stringify({challenge, return_to: safeReturnTo(returnTo)}),
            });
            if (!res.ok) {
                throw new Error('start failed');
            }
            authorizeUrl = (await res.json()).authorize_url;
        } catch (e) {
            if (!isCurrent(flowGeneration)) {
                return;
            }
            discard();
            setState('error', ERROR_MESSAGE);
            return;
        }
        if (!isCurrent(flowGeneration)) {
            return;
        }
        if (typeof authorizeUrl !== 'string' || !isUsableAuthorizeUrl(authorizeUrl, env)) {
            discard();
            setState('error', ERROR_MESSAGE);
            return;
        }

        // window.open may return null in Electron even though the system browser
        // opened (deny + openExternal): the return value is not a success signal.
        env.open(authorizeUrl, '_blank', 'noopener,noreferrer');
        setState('waiting');
        startWatcher();
    };

    flow.check = async function check() {
        const flowGeneration = generation;
        const rec = readRecord();
        if (rec && env.now() - rec.startedAt > FLOW_TTL_MS) {
            flow.cancel();
            return;
        }
        if (rec) {
            startWatcher(); // restored after a reload
        }

        const code = currentCode();
        if (!code) {
            return;
        }
        stripCodeFromUrl();

        // A code without an open flow in this view, for an already logged-in user, or
        // one we have seen before is dropped without any network call.
        if (!rec || flow.state === 'redeeming' || flow.state === 'done' || attempted.has(code) || env.isLoggedIn()) {
            return;
        }
        attempted.add(code);

        setState('redeeming');
        try {
            const res = await env.fetch(`${PLUGIN_BASE}/desktop/redeem`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                credentials: 'same-origin',
                body: JSON.stringify({code, verifier: rec.dv}),
            });
            if (!res.ok) {
                throw new Error('redeem failed');
            }
            const body = await res.json();
            if (!isCurrent(flowGeneration)) {
                return;
            }
            discard();
            setState('done');
            env.location.assign(safeReturnTo(body && body.return_to));
        } catch (e) {
            if (!isCurrent(flowGeneration)) {
                return;
            }
            // The flow stays open: a foreign or stale code must not destroy it.
            setState('error', ERROR_MESSAGE);
        }
    };

    return flow;
}

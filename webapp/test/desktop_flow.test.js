// Regression tests for the system-browser desktop login state machine. Run with
// `npm test` (node --test, no new dependency).
//
// Contract of webapp/src/desktop_flow.js (DOM-/React-free, everything injected):
//   export function selectDesktopLoginMode({publicConfig, userAgent})
//       -> 'browser' | 'popup' | 'external_browser'
//   export function createDesktopFlow(env)
//       env = {sessionStorage, localStorage, fetch, open, location, history, crypto,
//              now, setInterval, clearInterval, isLoggedIn}
//       flow.state                      'idle'|'starting'|'waiting'|'redeeming'|'done'|'error'
//       flow.message                    fixed user-facing text, never contains secrets
//       await flow.start({returnTo})    idle -> starting -> waiting | error
//       await flow.check()              one watcher tick (also called on initialize/mount)
//       flow.cancel()                   -> idle, dv deleted
//       flow.useInAppPopup({returnTo})  RC2 popup flow; clears an open desktop flow
// Endpoints are relative, like the RC2 button: /plugins/mattermost-oidc/oauth2/...

import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto, createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const ORIGIN = 'https://mm.example';
const BASE = '/plugins/mattermost-oidc/oauth2';
const START = `${BASE}/desktop/start`;
const REDEEM = `${BASE}/desktop/redeem`;
const FLOW_KEY = 'mattermost_oidc_desktop_flow';
const FIXED_ERROR = 'Anmeldung nicht möglich. Bitte erneut versuchen.';
const IDP_URL = 'https://idp.example/authorize?client_id=mattermost&state=abc';
const HC = 'hc1_' + 'A'.repeat(43);
const HC2 = 'hc1_' + 'B'.repeat(43);

async function loadModule() {
    return import('../src/desktop_flow.js');
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256b64url = (s) => createHash('sha256').update(s, 'utf8').digest('base64url');
const flush = async () => {
    for (let i = 0; i < 5; i++) {
        await new Promise((r) => setImmediate(r));
    }
};

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return {promise, resolve, reject};
}

function response(next) {
    return {ok: next.status >= 200 && next.status < 300, status: next.status, json: async () => next.body};
}

function fakeEnv(o = {}) {
    const calls = [];
    const store = new Map();
    const local = [];
    const loc = {origin: ORIGIN, pathname: '/login', search: o.search || '', hash: ''};
    const intervals = new Map();
    let nextTimer = 1;
    let clock = 1_000_000;
    let rngCalls = 0;
    const rngLengths = [];
    const responses = [...(o.responses || [])];
    const env = {
        calls,
        store,
        local,
        loc,
        loggedIn: Boolean(o.loggedIn),
        sessionStorage: {
            getItem: (k) => (store.has(k) ? store.get(k) : null),
            setItem: (k, v) => {
                calls.push(['sessionStorage.setItem', k]);
                store.set(k, String(v));
            },
            removeItem: (k) => {
                calls.push(['sessionStorage.removeItem', k]);
                store.delete(k);
            },
        },
        // Any use is recorded: dv must never end up here.
        localStorage: {
            getItem: (k) => {
                local.push(['get', k]);
                return null;
            },
            setItem: (k, v) => local.push(['set', k, String(v)]),
            removeItem: (k) => local.push(['remove', k]),
        },
        location: {
            get origin() {
                return loc.origin;
            },
            get pathname() {
                return loc.pathname;
            },
            get search() {
                return loc.search;
            },
            get hash() {
                return loc.hash;
            },
            get href() {
                return loc.origin + loc.pathname + loc.search + loc.hash;
            },
            assign: (u) => calls.push(['assign', u]),
        },
        history: {
            replaceState: (state, title, u) => {
                calls.push(['replaceState', u]);
                if (!o.stickyUrl) {
                    const parsed = new URL(u, loc.origin);
                    loc.pathname = parsed.pathname;
                    loc.search = parsed.search;
                    loc.hash = parsed.hash;
                }
            },
            pushState: () => calls.push(['pushState']),
        },
        fetch: async (url, init = {}) => {
            calls.push(['fetch', url, init]);
            const next = responses.shift();
            if (!next) {
                throw new Error(`unexpected fetch ${url}`);
            }
            if (typeof next.then === 'function') {
                return next;
            }
            if (next instanceof Error) {
                throw next;
            }
            return {ok: next.status >= 200 && next.status < 300, status: next.status, json: async () => next.body};
        },
        open: (...args) => {
            calls.push(['open', ...args]);
            return null; // Electron's deny+openExternal returns null: not a failure signal
        },
        crypto: {
            subtle: webcrypto.subtle,
            getRandomValues: (arr) => {
                rngCalls += 1;
                rngLengths.push(arr.length);
                if (o.fixedBytes) {
                    arr.set(o.fixedBytes);
                } else {
                    webcrypto.getRandomValues(arr);
                }
                return arr;
            },
        },
        now: () => clock,
        setInterval: (fn, ms) => {
            const id = nextTimer++;
            intervals.set(id, {fn, ms});
            return id;
        },
        clearInterval: (id) => intervals.delete(id),
        isLoggedIn: () => env.loggedIn,
        advance: (ms) => {
            clock += ms;
        },
        async tick(ms = 300) {
            clock += ms;
            for (const {fn} of [...intervals.values()]) {
                fn();
            }
            await flush();
        },
        activeIntervals: () => intervals.size,
        rngCalls: () => rngCalls,
        rngLengths,
        queue: (...r) => responses.push(...r),
        fetches: (suffix) => calls.filter((c) => c[0] === 'fetch' && (!suffix || c[1] === suffix)),
        opens: () => calls.filter((c) => c[0] === 'open'),
        assigns: () => calls.filter((c) => c[0] === 'assign'),
        flowRecord: () => (store.has(FLOW_KEY) ? JSON.parse(store.get(FLOW_KEY)) : null),
        setCode(code, extra = '') {
            loc.search = `?${extra}oidc_desktop_code=${code}`;
        },
    };
    return env;
}

const startOk = (url = IDP_URL) => ({status: 200, body: {authorize_url: url, expires_in: 600}});
const redeemOk = (returnTo = '/team/channels/town-square') => ({status: 200, body: {return_to: returnTo}});
const redeemFail = () => ({status: 401, body: {error: 'invalid_handoff'}});

async function startedFlow(o = {}) {
    const {createDesktopFlow} = await loadModule();
    const env = fakeEnv({responses: [startOk(), ...(o.after || [])], ...o});
    const flow = createDesktopFlow(env);
    await flow.start({returnTo: o.returnTo || '/team/channels/town-square'});
    return {env, flow, createDesktopFlow};
}

// ---------------------------------------------------------------- mode selection

test('selectDesktopLoginMode: popup stays default, external_browser needs exact value and Electron UA', async () => {
    const {selectDesktopLoginMode} = await loadModule();
    const desktopUA = 'Mozilla/5.0 Mattermost/6.3.1 Chrome/130 Electron/33 Safari/537.36';
    const browserUA = 'Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15';
    const table = [
        [{desktop_login_mode: 'external_browser'}, desktopUA, 'external_browser'],
        [{desktop_login_mode: 'popup'}, desktopUA, 'popup'],
        [{}, desktopUA, 'popup'], // RC2 server without the field
        [{desktop_login_mode: 'External_Browser'}, desktopUA, 'popup'],
        [{desktop_login_mode: 'garbage'}, desktopUA, 'popup'],
        [{desktop_login_mode: 'external_browser'}, browserUA, 'browser'],
        [{desktop_login_mode: 'popup'}, browserUA, 'browser'],
        [undefined, desktopUA, 'popup'],
        [{desktop_login_mode: 'external_browser'}, 'Mattermost only', 'browser'],
    ];
    for (const [publicConfig, userAgent, want] of table) {
        assert.equal(selectDesktopLoginMode({publicConfig, userAgent}), want, JSON.stringify([publicConfig, userAgent]));
    }
});

// ---------------------------------------------------------------- dv / dc generation

test('generates dv with 256 bit, dv1_ prefix and crypto.getRandomValues, never Math.random', async () => {
    const realRandom = Math.random;
    Math.random = () => {
        throw new Error('Math.random must not be used for secrets');
    };
    try {
        const {env} = await startedFlow();
        const dv = env.flowRecord().dv;
        assert.match(dv, /^dv1_[A-Za-z0-9_-]{43}$/);
        assert.ok(env.rngCalls() >= 1, 'crypto.getRandomValues not used');
        assert.ok(env.rngLengths.includes(32), `no 32-byte request in ${env.rngLengths}`);
    } finally {
        Math.random = realRandom;
    }
});

test('two flows get different dv', async () => {
    const a = (await startedFlow()).env.flowRecord().dv;
    const b = (await startedFlow()).env.flowRecord().dv;
    assert.notEqual(a, b);
});

test('challenge equals base64url(SHA-256(utf8(dv))) - reference vector', async () => {
    const bytes = Uint8Array.from({length: 32}, (_, i) => i);
    const {env} = await startedFlow({fixedBytes: bytes});
    const dv = 'dv1_' + b64url(bytes);
    assert.equal(env.flowRecord().dv, dv);
    const body = JSON.parse(env.fetches(START)[0][2].body);
    assert.equal(body.challenge, sha256b64url(dv));
    assert.match(body.challenge, /^[A-Za-z0-9_-]{43}$/);
});

// ---------------------------------------------------------------- start

test('start request shape: POST JSON, XHR header, same-origin credentials, only challenge+return_to, no query', async () => {
    const {env} = await startedFlow({returnTo: '/team/channels/x'});
    const fetches = env.fetches();
    assert.equal(fetches.length, 1);
    const [, url, init] = fetches[0];
    assert.equal(url, START);
    assert.equal(init.method, 'POST');
    const headers = Object.fromEntries(Object.entries(init.headers).map(([k, v]) => [k.toLowerCase(), v]));
    assert.equal(headers['content-type'], 'application/json');
    assert.equal(headers['x-requested-with'], 'XMLHttpRequest');
    assert.equal(init.credentials, 'same-origin');
    const body = JSON.parse(init.body);
    assert.deepEqual(Object.keys(body).sort(), ['challenge', 'return_to']);
    assert.equal(body.return_to, '/team/channels/x');
    assert.ok(!url.includes('?') && !url.includes(body.challenge));
});

test('dv lives only in sessionStorage and the redeem body - never localStorage, console, URLs or messages', async () => {
    const logged = [];
    const orig = {};
    for (const m of ['log', 'info', 'warn', 'error', 'debug']) {
        orig[m] = console[m];
        console[m] = (...a) => logged.push(a.map(String).join(' '));
    }
    let env;
    let dv;
    try {
        ({env} = await startedFlow({after: [redeemFail(), redeemOk()]}));
        dv = env.flowRecord().dv;
        env.setCode(HC);
        await env.tick();
        env.setCode(HC2);
        await env.tick();
    } finally {
        Object.assign(console, orig);
    }
    const dc = sha256b64url(dv);
    const redeems = env.fetches(REDEEM);
    assert.equal(redeems.length, 2);
    for (const r of redeems) {
        assert.equal(JSON.parse(r[2].body).verifier, dv);
    }
    const inspect = {
        localStorage: JSON.stringify(env.local),
        console: logged.join('\n'),
        openUrls: JSON.stringify(env.opens()),
        fetchUrls: env.fetches().map((c) => c[1]).join('\n'),
        replaceStateUrls: JSON.stringify(env.calls.filter((c) => c[0] === 'replaceState')),
        assigns: JSON.stringify(env.assigns()),
    };
    for (const [sink, text] of Object.entries(inspect)) {
        assert.ok(!text.includes(dv), `dv leaked into ${sink}`);
        assert.ok(!text.includes(dc), `dc leaked into ${sink}`);
    }
    assert.ok(!JSON.stringify(env.fetches(START)[0][2].body).includes(dv), 'dv sent in the start body');
});

test('opens only an https authorize_url on a different origin, with noopener,noreferrer', async () => {
    const {createDesktopFlow} = await loadModule();
    const bad = [
        'http://idp.example/authorize',
        'javascript:alert(1)',
        'file:///etc/passwd',
        'data:text/html,hi',
        'https://user:pw@idp.example/authorize',
        `${ORIGIN}/plugins/mattermost-oidc/oauth2/connect`, // same origin: Desktop would keep it inside the app
        'not a url',
        '',
    ];
    for (const url of bad) {
        const env = fakeEnv({responses: [startOk(url)]});
        const flow = createDesktopFlow(env);
        await flow.start({returnTo: '/'});
        assert.equal(env.opens().length, 0, `window.open called for ${JSON.stringify(url)}`);
        assert.equal(flow.state, 'error', `state for ${JSON.stringify(url)}`);
        assert.equal(env.activeIntervals(), 0, 'watcher running without a valid flow');
    }
    const {env, flow} = await startedFlow();
    assert.equal(flow.state, 'waiting');
    assert.equal(env.opens().length, 1);
    assert.deepEqual(env.opens()[0].slice(1), [IDP_URL, '_blank', 'noopener,noreferrer']);
});

test('start failures (404, 503, network) end in a fixed-message error state without window.open', async () => {
    const {createDesktopFlow} = await loadModule();
    for (const resp of [{status: 404, body: {error: 'not_available'}}, {status: 503, body: {error: 'provider_unavailable'}}, new Error('offline')]) {
        const env = fakeEnv({responses: [resp]});
        const flow = createDesktopFlow(env);
        await flow.start({returnTo: '/'});
        assert.equal(flow.state, 'error');
        assert.equal(env.opens().length, 0);
        assert.ok(typeof flow.message === 'string' && flow.message.length > 0);
    }
});

test('second start replaces the first flow: one flow per view, redeem uses the newest dv', async () => {
    const {createDesktopFlow} = await loadModule();
    const env = fakeEnv({responses: [startOk(), startOk(), redeemOk()]});
    const flow = createDesktopFlow(env);
    await flow.start({returnTo: '/a'});
    const first = env.flowRecord().dv;
    await flow.start({returnTo: '/b'});
    const second = env.flowRecord().dv;
    assert.notEqual(first, second);
    assert.equal(env.store.size, 1);
    env.setCode(HC);
    await env.tick();
    const redeem = env.fetches(REDEEM)[0];
    assert.equal(JSON.parse(redeem[2].body).verifier, second);
});

test('a stale start cannot erase or open a newer flow after overlapping requests', async () => {
    const {createDesktopFlow} = await loadModule();
    const first = deferred();
    const second = deferred();
    const env = fakeEnv({responses: [first.promise, second.promise]});
    const flow = createDesktopFlow(env);

    const startA = flow.start({returnTo: '/a'});
    await flush();
    const startB = flow.start({returnTo: '/b'});
    await flush();
    const verifierB = env.flowRecord().dv;

    first.resolve(response(startOk()));
    await startA;
    assert.equal(flow.state, 'starting');
    assert.equal(env.flowRecord().dv, verifierB);
    assert.equal(env.opens().length, 0);

    second.resolve(response(startOk()));
    await startB;
    assert.equal(flow.state, 'waiting');
    assert.equal(env.flowRecord().dv, verifierB);
    assert.equal(env.opens().length, 1);
});

test('a start response arriving after cancel cannot open a browser or change state', async () => {
    const {createDesktopFlow} = await loadModule();
    const pending = deferred();
    const env = fakeEnv({responses: [pending.promise]});
    const flow = createDesktopFlow(env);

    const start = flow.start({returnTo: '/'});
    await flush();
    flow.cancel();
    pending.resolve(response(startOk()));
    await start;

    assert.equal(flow.state, 'idle');
    assert.equal(env.flowRecord(), null);
    assert.equal(env.opens().length, 0);
});

// ---------------------------------------------------------------- redeem

test('redeem only with an open flow and a logged-out user: otherwise no network call and the code is removed', async () => {
    const {createDesktopFlow} = await loadModule();

    // (a) foreign deep link, no flow in this view
    const a = fakeEnv();
    const flowA = createDesktopFlow(a);
    a.setCode(HC, 'redirect_to=%2Fx&');
    await flowA.check();
    assert.equal(a.fetches().length, 0, 'network call without an open flow');
    assert.ok(!a.loc.search.includes('oidc_desktop_code'), `code still in URL: ${a.loc.search}`);
    assert.ok(a.loc.search.includes('redirect_to=%2Fx'), 'unrelated query parameters must survive');

    // (b) open flow but the user already has a session
    const b = fakeEnv({responses: [startOk()]});
    const flowB = createDesktopFlow(b);
    await flowB.start({returnTo: '/'});
    b.loggedIn = true;
    b.setCode(HC);
    await b.tick();
    assert.equal(b.fetches(REDEEM).length, 0, 'redeem attempted for an already logged-in user');
    assert.ok(!b.loc.search.includes('oidc_desktop_code'));
});

test('removes oidc_desktop_code from the URL BEFORE the network call', async () => {
    const {env} = await startedFlow({after: [redeemOk()]});
    env.setCode(HC);
    await env.tick();
    const order = env.calls.map((c) => c[0] + (c[0] === 'fetch' ? ':' + c[1] : '')).filter((c) => c.startsWith('replaceState') || c === `fetch:${REDEEM}`);
    assert.deepEqual(order, ['replaceState', `fetch:${REDEEM}`]);
    const url = env.calls.find((c) => c[0] === 'replaceState')[1];
    assert.ok(!String(url).includes(HC));
});

test('redeem request shape: POST, {code, verifier} in the body only', async () => {
    const {env} = await startedFlow({after: [redeemOk()]});
    const dv = env.flowRecord().dv;
    env.setCode(HC);
    await env.tick();
    const [, url, init] = env.fetches(REDEEM)[0];
    assert.equal(url, REDEEM);
    assert.ok(!url.includes('?') && !url.includes(HC) && !url.includes(dv));
    assert.equal(init.method, 'POST');
    const headers = Object.fromEntries(Object.entries(init.headers).map(([k, v]) => [k.toLowerCase(), v]));
    assert.equal(headers['content-type'], 'application/json');
    assert.equal(headers['x-requested-with'], 'XMLHttpRequest');
    assert.equal(init.credentials, 'same-origin');
    assert.deepEqual(JSON.parse(init.body), {code: HC, verifier: dv});
});

test('success clears dv, stops the watcher and navigates to the validated return_to', async () => {
    const {env, flow} = await startedFlow({after: [redeemOk('/team/channels/x')]});
    env.setCode(HC);
    await env.tick();
    assert.equal(flow.state, 'done');
    assert.deepEqual(env.assigns(), [['assign', '/team/channels/x']]);
    assert.equal(env.flowRecord(), null, 'dv must be deleted after success');
    assert.equal(env.activeIntervals(), 0, 'watcher still running after success');
});

test('server-supplied return_to is re-validated client side', async () => {
    for (const bad of ['//evil.example', 'https://evil.example/', '/a\\b', 'javascript:alert(1)', undefined, '', 42]) {
        const {env} = await startedFlow({after: [{status: 200, body: {return_to: bad}}]});
        env.setCode(HC);
        await env.tick();
        assert.deepEqual(env.assigns(), [['assign', '/']], `return_to ${JSON.stringify(bad)}`);
    }
});

test('failure keeps the flow open, shows the fixed message, never retries the same code', async () => {
    const {env, flow} = await startedFlow({stickyUrl: true, after: [redeemFail(), redeemOk()]});
    const dvBefore = env.flowRecord().dv;
    env.setCode(HC);
    await env.tick();
    await env.tick();
    await env.tick();
    assert.equal(flow.state, 'error');
    assert.equal(flow.message, FIXED_ERROR);
    assert.ok(!flow.message.includes(HC));
    assert.equal(env.fetches(REDEEM).length, 1, 'same code sent more than once');
    assert.equal(env.flowRecord().dv, dvBefore, 'a foreign/failed code must not destroy the legitimate flow');

    // A later, different code still completes the still-open flow.
    env.setCode(HC2);
    await env.tick();
    assert.equal(env.fetches(REDEEM).length, 2);
    assert.equal(flow.state, 'done');
});

test('network error during redeem is handled like a failure', async () => {
    const {env, flow} = await startedFlow({after: [new Error('offline')]});
    env.setCode(HC);
    await env.tick();
    assert.equal(flow.state, 'error');
    assert.equal(flow.message, FIXED_ERROR);
    assert.ok(env.flowRecord(), 'flow must stay open after a network error');
    assert.deepEqual(env.assigns(), []);
});

test('a redeem in progress cannot be cancelled, restarted or switched to popup before its response settles', async () => {
    const {createDesktopFlow} = await loadModule();
    const pending = deferred();
    const env = fakeEnv({responses: [startOk(), pending.promise]});
    const flow = createDesktopFlow(env);
    await flow.start({returnTo: '/'});
    env.setCode(HC);
    const redeem = flow.check();
    await flush();
    const verifier = env.flowRecord().dv;
    flow.cancel();
    await flow.start({returnTo: '/other'});
    flow.useInAppPopup({returnTo: '/other'});
    assert.equal(flow.state, 'redeeming');
    assert.equal(env.flowRecord().dv, verifier);
    assert.equal(env.fetches(START).length, 1);
    assert.equal(env.opens().length, 1);
    pending.resolve(response(redeemOk('/team/channels/x')));
    await redeem;

    assert.equal(flow.state, 'done');
    assert.equal(env.flowRecord(), null);
    assert.deepEqual(env.assigns(), [['assign', '/team/channels/x']]);
});

// ---------------------------------------------------------------- lifecycle / watcher

test('cancel deletes dv and stops the watcher; a new start creates a new dv', async () => {
    const {env, flow} = await startedFlow({after: [startOk()]});
    const first = env.flowRecord().dv;
    flow.cancel();
    assert.equal(flow.state, 'idle');
    assert.equal(env.flowRecord(), null);
    assert.equal(env.activeIntervals(), 0);
    await flow.start({returnTo: '/'});
    assert.notEqual(env.flowRecord().dv, first);
});

test('flow expires after 10 minutes: dv deleted, code ignored', async () => {
    const {env, flow} = await startedFlow({after: [redeemOk()]});
    env.advance(601_000);
    await env.tick();
    assert.equal(flow.state, 'idle');
    assert.equal(env.flowRecord(), null);
    assert.equal(env.activeIntervals(), 0);
    env.setCode(HC);
    await flow.check();
    assert.equal(env.fetches(REDEEM).length, 0, 'redeem after the flow timed out');
});

test('watcher sees a code delivered by push (no reload) and by reload (restored from sessionStorage)', async () => {
    // push: view stays mounted, only location.search changes
    const push = await startedFlow({after: [redeemOk()]});
    assert.equal(push.env.activeIntervals(), 1);
    await push.env.tick();
    assert.equal(push.env.fetches(REDEEM).length, 0);
    push.env.setCode(HC);
    await push.env.tick();
    assert.equal(push.env.fetches(REDEEM).length, 1);

    // reload: new module instance over the same sessionStorage, code already in the URL
    const {createDesktopFlow} = await loadModule();
    const first = await startedFlow({after: [redeemOk()]});
    const reloaded = fakeEnv({responses: [redeemOk()], search: `?oidc_desktop_code=${HC}`});
    reloaded.store.set(FLOW_KEY, first.env.store.get(FLOW_KEY));
    const flow = createDesktopFlow(reloaded);
    await flow.check();
    assert.equal(reloaded.fetches(REDEEM).length, 1);
    assert.equal(flow.state, 'done');
});

test('watcher never polls the server: only start and redeem fetches exist', async () => {
    const {env} = await startedFlow();
    for (let i = 0; i < 40; i++) {
        await env.tick();
    }
    assert.equal(env.fetches().length, 1, 'extra fetches while waiting');
    assert.equal(env.fetches()[0][1], START);
});

test('in-app popup fallback runs the unchanged RC2 popup flow and clears the desktop flow', async () => {
    const {env, flow} = await startedFlow();
    flow.useInAppPopup({returnTo: '/team/channels/x'});
    assert.equal(env.flowRecord(), null);
    assert.equal(env.activeIntervals(), 0);
    assert.equal(env.fetches().length, 1, 'fallback must not call desktop/start again');
    const opens = env.opens();
    assert.deepEqual(opens[opens.length - 1].slice(1), [`${BASE}/connect?return_to=${encodeURIComponent('/team/channels/x')}&popup=1`, 'oidc_login', 'width=520,height=680']);
});

// ---------------------------------------------------------------- green guards: RC2 popup/browser code stays

test('guard: index.js keeps the RC2 popup flow (popup=1, storage broadcast listener, allowlisted redirect)', () => {
    const src = readFileSync(join(here, '..', 'src', 'index.js'), 'utf8');
    for (const needle of ["&popup=1", "'oidc_login'", "mattermost_oidc_login", "window.addEventListener('storage'", "returnTo.startsWith('//')", 'window.location.href = base']) {
        assert.ok(src.includes(needle), `index.js lost RC2 behaviour marker ${needle}`);
    }
});

test('guard: no webapp source stores secrets outside sessionStorage', () => {
    const src = readFileSync(join(here, '..', 'src', 'index.js'), 'utf8');
    assert.ok(!/localStorage\.setItem\([^)]*(MMAUTHTOKEN|MMCSRF|verifier|dv)/i.test(src));
});

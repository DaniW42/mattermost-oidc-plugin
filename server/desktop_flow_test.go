package main

// Regression tests for the external_browser system-browser login. They drive
// the plugin exclusively through its HTTP router, plugin API mock, and KV store.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

const (
	dfSiteURL = "https://mm.example"
	dfUserID  = "user-alice-id"
	dfNonce   = "nonce-desktop-test"
	cbSubject = "desktop-user"
	cbEmail   = "alice@example.test"

	dfStartPath  = "/oauth2/desktop/start"
	dfRedeemPath = "/oauth2/desktop/redeem"

	dfHandoffPrefix = "oidc_dh_"
	dfHandoffDomain = "mattermost-oidc/desktop-handoff/v1\x00"
)

var (
	dfHCRe        = regexp.MustCompile(`^hc1_[A-Za-z0-9_-]{43}$`)
	dfDVRe        = regexp.MustCompile(`^dv1_[A-Za-z0-9_-]{43}$`)
	dfDeepLinkRe  = regexp.MustCompile(`mattermost://[^"'<>\s\\]+`)
	dfCSPNonceRe  = regexp.MustCompile(`'nonce-([A-Za-z0-9+/=_-]+)'`)
	dfScriptTagRe = regexp.MustCompile(`(?s)<script.*?</script>`)
	dfHrefAttrRe  = regexp.MustCompile(`href="[^"]*"`)
)

// ---------------------------------------------------------------- KV fake

// fakeKV is an in-memory KV store with a truly atomic KVCompareAndDelete, so
// single-use tests are meaningful (a mock that always answers true would not be).
type fakeKV struct {
	mu     sync.Mutex
	m      map[string][]byte
	ttl    map[string]int64
	writes int
}

func newFakeKV() *fakeKV { return &fakeKV{m: map[string][]byte{}, ttl: map[string]int64{}} }

func (k *fakeKV) get(key string) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	if v, ok := k.m[key]; ok {
		return append([]byte(nil), v...)
	}
	return nil
}

func (k *fakeKV) set(key string, v []byte, ttl int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.writes++
	k.m[key] = append([]byte(nil), v...)
	k.ttl[key] = ttl
}

func (k *fakeKV) compareAndDelete(key string, old []byte) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, ok := k.m[key]
	if !ok || !bytes.Equal(cur, old) {
		return false
	}
	delete(k.m, key)
	return true
}

func (k *fakeKV) keysWithPrefix(prefix string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for key := range k.m {
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func (k *fakeKV) writeCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.writes
}

func (k *fakeKV) ttlOf(key string) int64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ttl[key]
}

// ---------------------------------------------------------------- harness

type dfOpts struct {
	desktopMode string // value of the DesktopLoginMode setting; "" = key absent (RC2 config)
	siteURL     string // default dfSiteURL
	siteIsIdP   bool   // SiteURL origin == IdP origin
	noEnable    bool   // Enable=false
}

type dfHarness struct {
	t        *testing.T
	p        *Plugin
	api      *plugintest.API
	kv       *fakeKV
	idp      *httptest.Server
	mmCfg    *model.Config
	user     *model.User
	siteURL  string
	issuer   string
	sessions atomic.Int64
	created  []*model.Session
	sessMu   sync.Mutex

	nonceMu sync.Mutex
	nonce   string

	lastStateRaw []byte
}

func (h *dfHarness) setNonce(n string) { h.nonceMu.Lock(); h.nonce = n; h.nonceMu.Unlock() }
func (h *dfHarness) getNonce() string  { h.nonceMu.Lock(); defer h.nonceMu.Unlock(); return h.nonce }

func newDFHarness(t *testing.T, o dfOpts) *dfHarness {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	h := &dfHarness{t: t, kv: newFakeKV(), nonce: dfNonce}
	var issuer string
	h.idp = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
				"userinfo_endpoint": issuer + "/userinfo",
			})
		case "/token":
			payload, _ := json.Marshal(map[string]any{
				"iss": issuer, "sub": cbSubject, "aud": "mattermost", "nonce": h.getNonce(),
				"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
				"email": cbEmail, "email_verified": true,
			})
			signed, _ := signer.Sign(payload)
			raw, _ := signed.CompactSerialize()
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "token_type": "Bearer", "id_token": raw})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": cbSubject})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.idp.Close)
	issuer = h.idp.URL
	h.issuer = issuer

	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), h.idp.Client()), issuer)
	if err != nil {
		t.Fatalf("discover provider: %v", err)
	}

	h.siteURL = o.siteURL
	if h.siteURL == "" {
		h.siteURL = dfSiteURL
	}
	if o.siteIsIdP {
		h.siteURL = issuer
	}

	// The new setting is injected through JSON so this file compiles on the RC2 base,
	// where Configuration has no DesktopLoginMode field (the key is then ignored).
	base := Configuration{
		Enable: !o.noEnable, IssuerURL: issuer, ClientID: "mattermost", ClientSecret: "client-secret-value",
		EmailClaim: "email", UsernameClaim: "preferred_username", EmailVerifiedClaim: "email_verified",
	}
	raw, _ := json.Marshal(base)
	generic := map[string]any{}
	_ = json.Unmarshal(raw, &generic)
	if o.desktopMode != "" {
		generic["DesktopLoginMode"] = o.desktopMode
	}
	raw, _ = json.Marshal(generic)
	var cfg Configuration
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config: %v", err)
	}

	h.api = &plugintest.API{}
	h.p = &Plugin{
		encryptionKey: "test-key-0123456789",
		configuration: &cfg,
		oidcProvider:  provider,
		oidcVerifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{&privateKey.PublicKey},
		}, &oidc.Config{ClientID: "mattermost"}),
		oauth2Config: &oauth2.Config{
			ClientID: "mattermost", ClientSecret: "client-secret-value",
			Endpoint:    oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token"},
			RedirectURL: h.siteURL + "/plugins/" + PluginID + "/oauth2/callback",
		},
	}
	h.p.SetAPI(desktopQuietAPI{h.api})
	h.p.initRouter()

	h.mmCfg = &model.Config{}
	h.mmCfg.SetDefaults()
	h.setSiteURL(h.siteURL)
	h.api.On("GetConfig").Return(func() *model.Config { return h.mmCfg })

	h.kv.set(KVOIDCUserPrefix+cbSubject, []byte(dfUserID), 0)
	h.kv.writes = 0 // seeding is not a flow write

	h.user = &model.User{Id: dfUserID, Username: "alice", Email: cbEmail, EmailVerified: true,
		AuthService: AuthService, AuthData: model.NewPointer(cbSubject)}

	h.api.On("KVGet", mock.Anything).Return(func(k string) ([]byte, *model.AppError) { return h.kv.get(k), nil }).Maybe()
	h.api.On("KVSet", mock.Anything, mock.Anything).Return(func(k string, v []byte) *model.AppError { h.kv.set(k, v, 0); return nil }).Maybe()
	h.api.On("KVSetWithExpiry", mock.Anything, mock.Anything, mock.Anything).Return(func(k string, v []byte, ttl int64) *model.AppError { h.kv.set(k, v, ttl); return nil }).Maybe()
	h.api.On("KVCompareAndDelete", mock.Anything, mock.Anything).Return(func(k string, old []byte) (bool, *model.AppError) { return h.kv.compareAndDelete(k, old), nil }).Maybe()
	h.api.On("GetUser", mock.Anything).Return(func(uid string) (*model.User, *model.AppError) {
		if uid != dfUserID {
			return nil, &model.AppError{StatusCode: http.StatusNotFound}
		}
		cp := *h.user
		return &cp, nil
	}).Maybe()
	h.api.On("GetUserByEmail", mock.Anything).Return(nil, &model.AppError{StatusCode: http.StatusNotFound}).Maybe()
	h.api.On("UpdateUser", mock.Anything).Return(func(u *model.User) (*model.User, *model.AppError) { return u, nil }).Maybe()
	h.api.On("UpdateUserAuth", mock.Anything, mock.Anything).Return(&model.UserAuth{}, nil).Maybe()
	h.api.On("CreateSession", mock.Anything).Return(func(s *model.Session) (*model.Session, *model.AppError) {
		n := h.sessions.Add(1)
		cp := *s
		cp.Id = fmt.Sprintf("sess-id-%d", n)
		cp.Token = fmt.Sprintf("session-token-secret-%d-%s", n, strings.Repeat("x", 20))
		h.sessMu.Lock()
		h.created = append(h.created, &cp)
		h.sessMu.Unlock()
		return &cp, nil
	}).Maybe()
	return h
}

// desktopQuietAPI suppresses log calls, which the generated plugin test mock
// otherwise treats as unexpected. The desktop flow is tested through HTTP
// responses and storage effects rather than log output.
type desktopQuietAPI struct{ *plugintest.API }

func (desktopQuietAPI) LogDebug(string, ...any) {}
func (desktopQuietAPI) LogInfo(string, ...any)  {}
func (desktopQuietAPI) LogWarn(string, ...any)  {}
func (desktopQuietAPI) LogError(string, ...any) {}

func (h *dfHarness) setSiteURL(s string) { h.mmCfg.ServiceSettings.SiteURL = model.NewPointer(s) }

func (h *dfHarness) lastSession() *model.Session {
	h.sessMu.Lock()
	defer h.sessMu.Unlock()
	if len(h.created) == 0 {
		return nil
	}
	return h.created[len(h.created)-1]
}

// serve runs a request through the real plugin router.
func (h *dfHarness) serve(r *http.Request) *httptest.ResponseRecorder {
	r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, h.idp.Client()))
	w := httptest.NewRecorder()
	h.p.ServeHTTP(nil, w, r)
	return w
}

// postJSON sends a POST with every header a legitimate Desktop renderer sends;
// mods then break exactly one property.
func (h *dfHarness) postJSON(path string, body any, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	var buf []byte
	switch b := body.(type) {
	case string:
		buf = []byte(b)
	case []byte:
		buf = b
	default:
		buf, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Requested-With", "XMLHttpRequest")
	r.Header.Set("Origin", dfSiteURL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, m := range mods {
		m(r)
	}
	return h.serve(r)
}

func (h *dfHarness) start(challenge, returnTo string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	body := map[string]string{"challenge": challenge}
	if returnTo != "" {
		body["return_to"] = returnTo
	}
	return h.postJSON(dfStartPath, body, mods...)
}

func (h *dfHarness) redeem(code, verifier string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	return h.postJSON(dfRedeemPath, map[string]string{"code": code, "verifier": verifier}, mods...)
}

// ---------------------------------------------------------------- value helpers

func dfRandB64(t testing.TB) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func dfNewDV(t testing.TB) string { return "dv1_" + dfRandB64(t) }
func dfNewHC(t testing.TB) string { return "hc1_" + dfRandB64(t) }

// dfChallenge is dc = base64url(SHA-256(utf8(dv))) (spec 3.3).
func dfChallenge(dv string) string {
	sum := sha256.Sum256([]byte(dv))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// dfHandoffKey is oidc_dh_<hex(SHA-256(domain || hc))> (spec 3.2).
func dfHandoffKey(hc string) string {
	sum := sha256.Sum256([]byte(dfHandoffDomain + hc))
	return dfHandoffPrefix + hex.EncodeToString(sum[:])
}

type dfRecord struct {
	V         int    `json:"v"`
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
	SiteURL   string `json:"site_url"`
	ReturnTo  string `json:"return_to"`
	CreateAt  int64  `json:"create_at"`
}

// seedHandoff writes a handoff record exactly as spec 3.2 defines it, so redeem
// tests do not depend on the callback implementation. mods tweak the record.
func (h *dfHarness) seedHandoff(hc, dv string, mods ...func(*dfRecord)) {
	h.t.Helper()
	rec := dfRecord{V: 1, UserID: dfUserID, Challenge: dfChallenge(dv), SiteURL: dfSiteURL, ReturnTo: "/team/channels/town-square", CreateAt: time.Now().UnixMilli()}
	for _, m := range mods {
		m(&rec)
	}
	raw, _ := json.Marshal(rec)
	h.kv.set(dfHandoffKey(hc), raw, 120)
}

func (h *dfHarness) handoffKeys() []string { return h.kv.keysWithPrefix(dfHandoffPrefix) }

func dfFlipLast(s string) string {
	last := s[len(s)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return s[:len(s)-1] + string(repl)
}

func dfErrCode(w *httptest.ResponseRecorder) string {
	var v struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return v.Error
}

func dfSetCookies(w *httptest.ResponseRecorder) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, c := range w.Result().Cookies() {
		out[c.Name] = c
	}
	return out
}

func dfNoACAO(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for k := range w.Header() {
		if strings.HasPrefix(strings.ToLower(k), "access-control-allow-") {
			t.Errorf("response carries CORS header %s (spec 2.1 #8)", k)
		}
	}
}

// ---------------------------------------------------------------- state seeding for callback tests

// seedDesktopState stores an OAuth state as POST /oauth2/desktop/start would
// (spec 2.2/3.1) and returns the signed state parameter the IdP echoes back.
func (h *dfHarness) seedDesktopState(dv string, mods ...func(map[string]any)) (signed, token string) {
	h.t.Helper()
	token = fmt.Sprintf("state-%s", dfRandB64(h.t)[:24])
	st := map[string]any{
		"token": token, "create_at": time.Now().UnixMilli(), "return_to": "/team/channels/off-topic",
		"nonce": dfNonce, "code_verifier": "pkce-verifier-" + dfRandB64(h.t),
		"mode": "desktop_external", "desktop_challenge": dfChallenge(dv),
	}
	for _, m := range mods {
		m(st)
	}
	raw, _ := json.Marshal(st)
	h.kv.set(KVOAuthStatePrefix+token, raw, 600)
	return h.p.signState(token), token
}

func (h *dfHarness) callback(signedState string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	q := url.Values{"code": {"auth-code-opaque"}, "state": {signedState}}
	r := httptest.NewRequest(http.MethodGet, "/oauth2/callback?"+q.Encode(), nil)
	for _, m := range mods {
		m(r)
	}
	return h.serve(r)
}

func dfWithCookie(name, value string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: name, Value: value}) }
}

// requireHandoff drives start -> callback and returns hc plus the callback response.
// It fails the test if the system-browser flow does not work; this is the
// positive control that makes every negative callback test fail on RC2.
func (h *dfHarness) requireHandoff(dv, returnTo string) (string, *httptest.ResponseRecorder, string) {
	h.t.Helper()
	w := h.start(dfChallenge(dv), returnTo)
	if w.Code != http.StatusOK {
		h.t.Fatalf("POST %s = %d %q, want 200 (positive control for the external_browser flow)", dfStartPath, w.Code, strings.TrimSpace(w.Body.String()))
	}
	var resp struct {
		AuthorizeURL string `json:"authorize_url"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.AuthorizeURL == "" {
		h.t.Fatalf("start body %q has no authorize_url", w.Body.String())
	}
	au, err := url.Parse(resp.AuthorizeURL)
	if err != nil {
		h.t.Fatalf("authorize_url: %v", err)
	}
	signed := au.Query().Get("state")
	stateToken, err := h.p.verifyAndExtractState(signed)
	if err != nil {
		h.t.Fatalf("authorize_url state does not verify: %v", err)
	}
	var st OAuthState
	if err := json.Unmarshal(h.kv.get(KVOAuthStatePrefix+stateToken), &st); err != nil {
		h.t.Fatalf("state not stored: %v", err)
	}
	h.setNonce(st.Nonce)
	cw := h.callback(signed) // NO MMOIDCSTATE cookie: the callback happens in another browser
	if cw.Code != http.StatusOK {
		h.t.Fatalf("callback = %d, want 200 handoff page; body: %s", cw.Code, cw.Body.String())
	}
	link := dfDeepLinkRe.FindString(cw.Body.String())
	if link == "" {
		h.t.Fatalf("callback page has no mattermost:// deep link:\n%s", cw.Body.String())
	}
	u, err := url.Parse(strings.ReplaceAll(link, "&amp;", "&"))
	if err != nil {
		h.t.Fatalf("deep link: %v", err)
	}
	return u.Query().Get("oidc_desktop_code"), cw, resp.AuthorizeURL
}

// ================================================================= config / routes

func TestEffectiveDesktopLoginMode(t *testing.T) {
	cases := []struct {
		name string
		o    dfOpts
		want string
	}{
		{"setting absent (RC2 config) is popup", dfOpts{}, "popup"},
		{"explicit popup", dfOpts{desktopMode: "popup"}, "popup"},
		{"external_browser with https SiteURL", dfOpts{desktopMode: "external_browser"}, "external_browser"},
		{"wrong case falls back", dfOpts{desktopMode: "External_Browser"}, "popup"},
		{"garbage falls back", dfOpts{desktopMode: "yolo"}, "popup"},
		{"http SiteURL falls back", dfOpts{desktopMode: "external_browser", siteURL: "http://mm.example"}, "popup"},
		{"SiteURL with userinfo falls back", dfOpts{desktopMode: "external_browser", siteURL: "https://u:p@mm.example"}, "popup"},
		{"SiteURL with query falls back", dfOpts{desktopMode: "external_browser", siteURL: "https://mm.example?x=1"}, "popup"},
		{"IdP on SiteURL origin falls back", dfOpts{desktopMode: "external_browser", siteIsIdP: true}, "popup"},
		{"plugin disabled falls back", dfOpts{desktopMode: "external_browser", noEnable: true}, "popup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, tc.o)
			w := h.serve(httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("public config is not JSON: %v", err)
			}
			if got["desktop_login_mode"] != tc.want {
				t.Errorf("desktop_login_mode = %v, want %q (public config: %v)", got["desktop_login_mode"], tc.want, got)
			}
		})
	}
}

// Green guard: the pre-RC3 public config contract (read by webapp and mobile-bridge) must not change.
func TestPublicConfigKeepsLegacyFields(t *testing.T) {
	h := newDFHarness(t, dfOpts{})
	h.p.configuration.ButtonText, h.p.configuration.ButtonColor = "simul8 SSO", "#123456"
	w := h.serve(httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["enable"] != true || got["button_text"] != "simul8 SSO" || got["button_color"] != "#123456" {
		t.Errorf("legacy public config changed: %v", got)
	}
}

func TestRoutesNoPollingEndpoint(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	var got []string
	_ = h.p.router.Walk(func(rt *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, _ := rt.GetPathTemplate()
		methods, _ := rt.GetMethods()
		got = append(got, strings.Join(methods, ",")+" "+tpl)
		return nil
	})
	sort.Strings(got)
	want := []string{
		"GET /api/v1/config", "GET /oauth2/callback", "GET /oauth2/connect",
		"POST /oauth2/desktop/redeem", "POST /oauth2/desktop/start",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("router routes = %q\nwant exactly %q (no status/poll route, I-04)", got, want)
	}
}

// ================================================================= start

func TestDesktopStartDisabledReturns404(t *testing.T) {
	for _, mode := range []string{"", "popup", "garbage"} {
		t.Run("mode="+mode, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: mode})
			w := h.start(dfChallenge(dfNewDV(t)), "")
			if w.Code != http.StatusNotFound || dfErrCode(w) != "not_available" {
				t.Errorf("start = %d %q, want 404 {\"error\":\"not_available\"}", w.Code, strings.TrimSpace(w.Body.String()))
			}
			if n := h.kv.writeCount(); n != 0 {
				t.Errorf("disabled start wrote %d KV entries", n)
			}
			w = h.redeem(dfNewHC(t), dfNewDV(t))
			if w.Code != http.StatusNotFound || dfErrCode(w) != "not_available" {
				t.Errorf("redeem = %d %q, want 404 {\"error\":\"not_available\"}", w.Code, strings.TrimSpace(w.Body.String()))
			}
		})
	}
}

func TestDesktopStartRejectsSelfOriginIdP(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser", siteIsIdP: true})
	w := h.postJSON(dfStartPath, map[string]string{"challenge": dfChallenge(dfNewDV(t))}, func(r *http.Request) { r.Header.Set("Origin", h.siteURL) })
	if w.Code != http.StatusNotFound || dfErrCode(w) != "not_available" {
		t.Errorf("start with IdP on SiteURL origin = %d %q, want 404 not_available (Desktop would open the IdP inside the app)", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

func TestDesktopStartRequestValidation(t *testing.T) {
	good := dfChallenge(dfNewDV(t))
	valid := map[string]string{"challenge": good}
	cases := []struct {
		name   string
		path   string
		body   any
		mod    func(*http.Request)
		status int
		code   string
	}{
		{"wrong method", dfStartPath, valid, func(r *http.Request) { r.Method = http.MethodGet }, 405, ""},
		{"content type text/plain", dfStartPath, valid, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415, "unsupported_media_type"},
		{"content type form", dfStartPath, valid, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, 415, "unsupported_media_type"},
		{"missing X-Requested-With", dfStartPath, valid, func(r *http.Request) { r.Header.Del("X-Requested-With") }, 403, "forbidden"},
		{"Sec-Fetch-Site cross-site", dfStartPath, valid, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403, "forbidden"},
		{"missing Origin", dfStartPath, valid, func(r *http.Request) { r.Header.Del("Origin") }, 403, "forbidden"},
		{"foreign Origin", dfStartPath, valid, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403, "forbidden"},
		{"Origin other port", dfStartPath, valid, func(r *http.Request) { r.Header.Set("Origin", "https://mm.example:8443") }, 403, "forbidden"},
		{"Origin http scheme", dfStartPath, valid, func(r *http.Request) { r.Header.Set("Origin", "http://mm.example") }, 403, "forbidden"},
		{"query string present", dfStartPath + "?challenge=" + good, valid, nil, 400, "invalid_request"},
		{"body over 4096 bytes", dfStartPath, `{"challenge":"` + good + `","return_to":"/` + strings.Repeat("a", 5000) + `"}`, nil, 400, "invalid_request"},
		{"unknown field popup", dfStartPath, map[string]any{"challenge": good, "popup": "1"}, nil, 400, "invalid_request"},
		{"unknown field mobile_redirect", dfStartPath, map[string]any{"challenge": good, "mobile_redirect": "mmauth://callback"}, nil, 400, "invalid_request"},
		{"unknown field code", dfStartPath, map[string]any{"challenge": good, "code": dfNewHC(t)}, nil, 400, "invalid_request"},
		{"second JSON value", dfStartPath, `{"challenge":"` + good + `"}{"challenge":"` + good + `"}`, nil, 400, "invalid_request"},
		{"not JSON", dfStartPath, `challenge=` + good, nil, 400, "invalid_request"},
		{"challenge missing", dfStartPath, map[string]string{}, nil, 400, "invalid_request"},
		{"challenge empty", dfStartPath, map[string]string{"challenge": ""}, nil, 400, "invalid_request"},
		{"challenge too short", dfStartPath, map[string]string{"challenge": good[:42]}, nil, 400, "invalid_request"},
		{"challenge too long", dfStartPath, map[string]string{"challenge": good + "A"}, nil, 400, "invalid_request"},
		{"challenge bad alphabet", dfStartPath, map[string]string{"challenge": good[:42] + "+"}, nil, 400, "invalid_request"},
		{"challenge padded base64", dfStartPath, map[string]string{"challenge": good[:42] + "="}, nil, 400, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
			// Positive control: the unmodified request must work, otherwise rejections prove nothing.
			if w := h.start(good, ""); w.Code != http.StatusOK {
				t.Fatalf("control start = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
			}
			before := h.kv.writeCount()
			var mods []func(*http.Request)
			if tc.mod != nil {
				mods = append(mods, tc.mod)
			}
			w := h.postJSON(tc.path, tc.body, mods...)
			if w.Code != tc.status {
				t.Errorf("status = %d, want %d (body %q)", w.Code, tc.status, strings.TrimSpace(w.Body.String()))
			}
			if tc.code != "" && dfErrCode(w) != tc.code {
				t.Errorf("error = %q, want %q", dfErrCode(w), tc.code)
			}
			if h.kv.writeCount() != before {
				t.Error("rejected start request wrote to KV")
			}
			dfNoACAO(t, w)
			if body := w.Body.String(); strings.Contains(body, "evil.example") || strings.Contains(body, good) {
				t.Errorf("error body reflects input: %q", body)
			}
		})
	}
}

func TestDesktopStartStoresStateAndNoCookie(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	dv := dfNewDV(t)
	dc := dfChallenge(dv)
	w := h.start(dc, "/team/channels/town-square")
	if w.Code != http.StatusOK {
		t.Fatalf("start = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", w.Header().Get("Referrer-Policy"))
	}
	dfNoACAO(t, w)
	if len(w.Result().Cookies()) != 0 {
		t.Errorf("start sets cookies %v; the MMOIDCSTATE cookie would sit in the wrong browser (D1/T-20)", w.Result().Cookies())
	}

	var resp struct {
		AuthorizeURL string `json:"authorize_url"`
		ExpiresIn    int    `json:"expires_in"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want 600", resp.ExpiresIn)
	}
	au, err := url.Parse(resp.AuthorizeURL)
	if err != nil || au.Scheme != "https" || au.User != nil {
		t.Fatalf("authorize_url %q must be an https URL without userinfo", resp.AuthorizeURL)
	}
	idpURL, _ := url.Parse(h.issuer)
	if au.Host != idpURL.Host || au.Path != "/authorize" {
		t.Errorf("authorize_url points to %s%s, want the discovered IdP endpoint", au.Host, au.Path)
	}
	q := au.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
		t.Errorf("authorize_url lacks PKCE S256/nonce: %s", au.RawQuery)
	}
	if strings.Contains(resp.AuthorizeURL, dv) || strings.Contains(resp.AuthorizeURL, dc) {
		t.Error("authorize_url leaks the desktop verifier or challenge to the IdP (I-12)")
	}
	stateToken, err := h.p.verifyAndExtractState(q.Get("state"))
	if err != nil {
		t.Fatalf("state parameter is not a valid signed state: %v", err)
	}
	raw := h.kv.get(KVOAuthStatePrefix + stateToken)
	if raw == nil {
		t.Fatal("state not stored in KV")
	}
	var st map[string]any
	_ = json.Unmarshal(raw, &st)
	if st["mode"] != "desktop_external" || st["desktop_challenge"] != dc {
		t.Errorf("stored state mode/desktop_challenge = %v/%v, want desktop_external/%s", st["mode"], st["desktop_challenge"], dc)
	}
	for _, f := range []string{"code_verifier", "nonce"} {
		if s, _ := st[f].(string); s == "" {
			t.Errorf("stored state lacks %s", f)
		}
	}
	if _, ok := st["popup"]; ok {
		t.Error("desktop_external state must not carry popup")
	}
	if s, _ := st["mobile_redirect"].(string); s != "" {
		t.Error("desktop_external state must not carry mobile_redirect")
	}
	if st["nonce"] != q.Get("nonce") {
		t.Error("state nonce differs from the nonce sent to the IdP")
	}
	if ttl := h.kv.ttlOf(KVOAuthStatePrefix + stateToken); ttl != 600 {
		t.Errorf("state KV expiry = %d s, want 600", ttl)
	}
}

func TestDesktopStartReturnToSanitized(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"valid path kept", "/team/channels/x?y=1", "/team/channels/x?y=1"},
		{"protocol relative", "//evil.example", "/"},
		{"absolute url", "https://evil.example/", "/"},
		{"javascript scheme", "javascript:alert(1)", "/"},
		{"backslash", `/a\b`, "/"},
		{"newline", "/a\nb", "/"},
		{"nul", "/a\x00b", "/"},
		{"del", "/a\x7fb", "/"},
		{"too long", "/" + strings.Repeat("a", 512), "/"},
		{"empty", "", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
			w := h.start(dfChallenge(dfNewDV(t)), tc.in)
			if w.Code != http.StatusOK {
				t.Fatalf("start = %d %q, want 200 (invalid return_to is sanitized silently, not rejected)", w.Code, strings.TrimSpace(w.Body.String()))
			}
			var resp struct {
				AuthorizeURL string `json:"authorize_url"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			au, _ := url.Parse(resp.AuthorizeURL)
			tok, _ := h.p.verifyAndExtractState(au.Query().Get("state"))
			var st OAuthState
			_ = json.Unmarshal(h.kv.get(KVOAuthStatePrefix+tok), &st)
			if st.ReturnTo != tc.want {
				t.Errorf("stored return_to = %q, want %q", st.ReturnTo, tc.want)
			}
		})
	}
}

// ================================================================= callback

func TestCallbackDesktopIssuesHandoffWithoutSession(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	dv := dfNewDV(t)
	before := time.Now().UnixMilli()
	hc, w, _ := h.requireHandoff(dv, "/team/channels/town-square")

	if !dfHCRe.MatchString(hc) {
		t.Errorf("handoff code %q does not match hc1_ + 43 base64url chars", hc)
	}
	if c := w.Result().Cookies(); len(c) != 0 {
		t.Errorf("callback sets cookies %v; the system browser must never hold a session or clear the Electron state (I-31)", c)
	}
	if n := h.sessions.Load(); n != 0 {
		t.Errorf("callback created %d sessions, want 0 (session is created at redeem)", n)
	}
	keys := h.handoffKeys()
	if len(keys) != 1 {
		t.Fatalf("handoff records = %v, want exactly one", keys)
	}
	if keys[0] != dfHandoffKey(hc) {
		t.Errorf("KV key %q != %q: hc must be stored only as SHA-256(domain||hc)", keys[0], dfHandoffKey(hc))
	}
	if strings.Contains(keys[0], hc) {
		t.Error("KV key contains the plaintext handoff code")
	}
	raw := h.kv.get(keys[0])
	for _, secret := range []string{hc, dv, cbEmail, cbSubject} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("handoff record contains %q", secret)
		}
	}
	var rec dfRecord
	_ = json.Unmarshal(raw, &rec)
	if rec.V != 1 || rec.UserID != dfUserID || rec.Challenge != dfChallenge(dv) || rec.SiteURL != dfSiteURL || rec.ReturnTo != "/team/channels/town-square" {
		t.Errorf("handoff record = %+v", rec)
	}
	if rec.CreateAt < before || rec.CreateAt > time.Now().UnixMilli() {
		t.Errorf("create_at %d outside [%d, now]", rec.CreateAt, before)
	}
	if ttl := h.kv.ttlOf(keys[0]); ttl <= 0 || ttl > 120 {
		t.Errorf("handoff KV expiry = %d s, want 1..120", ttl)
	}
}

func TestDesktopHandoffCodesAreRandomFormattedAndShortLived(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	seen := map[string]bool{}
	for i := 0; i < 25; i++ {
		hc, _, _ := h.requireHandoff(dfNewDV(t), "")
		if !dfHCRe.MatchString(hc) {
			t.Fatalf("hc %q has wrong format", hc)
		}
		if seen[hc] {
			t.Fatalf("hc %q generated twice: not random", hc)
		}
		seen[hc] = true
		if ttl := h.kv.ttlOf(dfHandoffKey(hc)); ttl <= 0 || ttl > 120 {
			t.Fatalf("hc KV expiry = %d s, want 1..120", ttl)
		}
	}
	// 256 bits of entropy: the base64url body must not be a low-entropy encoding.
	var sample []string
	for hc := range seen {
		sample = append(sample, strings.TrimPrefix(hc, "hc1_"))
	}
	chars := map[rune]bool{}
	for _, s := range sample {
		for _, r := range s {
			chars[r] = true
		}
	}
	if len(chars) < 40 {
		t.Errorf("only %d distinct characters across 25 codes; suspicious entropy", len(chars))
	}
}

func TestCallbackDesktopDeepLinkFromSiteURLOnly(t *testing.T) {
	cases := []struct {
		name, siteURL, wantPrefix string
	}{
		{"root site", "https://mm.example", "mattermost://mm.example/login?"},
		{"subpath site", "https://h.example/mm/", "mattermost://h.example/mm/login?"},
		{"port site", "https://mm.example:8443", "mattermost://mm.example:8443/login?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: "external_browser", siteURL: tc.siteURL})
			dv := dfNewDV(t)
			w := h.postJSON(dfStartPath, map[string]string{"challenge": dfChallenge(dv)}, func(r *http.Request) {
				u, _ := url.Parse(tc.siteURL)
				r.Header.Set("Origin", u.Scheme+"://"+u.Host)
			})
			if w.Code != http.StatusOK {
				t.Fatalf("start = %d %q", w.Code, strings.TrimSpace(w.Body.String()))
			}
			var resp struct {
				AuthorizeURL string `json:"authorize_url"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			au, _ := url.Parse(resp.AuthorizeURL)
			tok, _ := h.p.verifyAndExtractState(au.Query().Get("state"))
			var st OAuthState
			_ = json.Unmarshal(h.kv.get(KVOAuthStatePrefix+tok), &st)
			h.setNonce(st.Nonce)

			// Attacker-controlled request metadata must not influence the link.
			cw := h.callback(au.Query().Get("state"), func(r *http.Request) {
				r.Host = "evil.example"
				r.Header.Set("X-Forwarded-Host", "evil.example")
				r.Header.Set("X-Forwarded-Proto", "http")
				r.Header.Set("Forwarded", "host=evil.example")
			})
			if cw.Code != http.StatusOK {
				t.Fatalf("callback = %d", cw.Code)
			}
			link := dfDeepLinkRe.FindString(cw.Body.String())
			if !strings.HasPrefix(link, tc.wantPrefix) {
				t.Errorf("deep link %q does not start with %q", link, tc.wantPrefix)
			}
			u, err := url.Parse(link)
			if err != nil {
				t.Fatalf("deep link unparsable: %v", err)
			}
			if u.Scheme != "mattermost" {
				t.Errorf("scheme = %q, want mattermost", u.Scheme)
			}
			if len(u.Query()) != 1 || u.Query().Get("oidc_desktop_code") == "" {
				t.Errorf("deep link query = %v, want only oidc_desktop_code (no server_token/client_token, no user/return_to/token data)", u.Query())
			}
			if u.Fragment != "" {
				t.Error("deep link carries a fragment; Desktop drops it (D3)")
			}
			if strings.Contains(cw.Body.String(), "evil.example") {
				t.Error("handoff page reflects request-controlled host")
			}
		})
	}
}

func TestCallbackDesktopHandoffPageHeadersAndEscaping(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	h.user.Username = `</script><img src=x onerror=alert(1)>"'&`
	hc, w, _ := h.requireHandoff(dfNewDV(t), "")

	hd := w.Header()
	if ct := hd.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	for _, want := range []string{"no-store", "private"} {
		if !strings.Contains(hd.Get("Cache-Control"), want) {
			t.Errorf("Cache-Control %q lacks %q", hd.Get("Cache-Control"), want)
		}
	}
	if hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Referrer-Policy/X-Content-Type-Options = %q/%q", hd.Get("Referrer-Policy"), hd.Get("X-Content-Type-Options"))
	}
	csp := hd.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	body := w.Body.String()
	m := dfCSPNonceRe.FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("CSP %q has no script nonce", csp)
	}
	if !strings.Contains(body, `nonce="`+m[1]+`"`) {
		t.Error("page script does not carry the CSP nonce")
	}
	if strings.Contains(body, "<img") || strings.Contains(body, "</script><img") {
		t.Error("username injected unescaped into the handoff page")
	}
	if opens, closes := strings.Count(body, "<script"), strings.Count(body, "</script>"); opens != closes {
		t.Errorf("%d <script> openings vs %d closings: injection through a value", opens, closes)
	}
	if regexp.MustCompile(`(?i)(src|href)="https?://`).MatchString(body) {
		t.Error("page loads/links external http(s) resources")
	}
	if strings.Contains(body, "localStorage") {
		t.Error("handoff page must not use localStorage")
	}
	visible := dfHrefAttrRe.ReplaceAllString(dfScriptTagRe.ReplaceAllString(body, ""), "")
	if strings.Contains(visible, hc) {
		t.Error("handoff code is shown as visible text (T-03)")
	}
	if m2 := dfCSPNonceRe.FindStringSubmatch(h.callbackAgainNonce(t)); m2 != nil && m2[1] == m[1] {
		t.Error("CSP nonce reused across responses")
	}
}

// callbackAgainNonce runs a second full flow and returns its CSP header.
func (h *dfHarness) callbackAgainNonce(t *testing.T) string {
	_, w, _ := h.requireHandoff(dfNewDV(t), "")
	return w.Header().Get("Content-Security-Policy")
}

func TestCallbackDesktopRequiresValidChallenge(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(map[string]any)
	}{
		{"missing challenge", func(s map[string]any) { delete(s, "desktop_challenge") }},
		{"empty challenge", func(s map[string]any) { s["desktop_challenge"] = "" }},
		{"short challenge", func(s map[string]any) { s["desktop_challenge"] = "abc" }},
		{"bad alphabet", func(s map[string]any) { s["desktop_challenge"] = strings.Repeat("!", 43) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
			// Control: the same seeded state with a valid challenge yields a handoff.
			signed, _ := h.seedDesktopState(dfNewDV(t))
			if w := h.callback(signed); w.Code != http.StatusOK || len(h.handoffKeys()) != 1 {
				t.Fatalf("control callback = %d, handoffs %v; want 200 and one handoff", w.Code, h.handoffKeys())
			}
			signed, _ = h.seedDesktopState(dfNewDV(t), tc.mod)
			w := h.callback(signed)
			if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "mattermost://") {
				t.Errorf("callback = %d with deep link despite invalid challenge", w.Code)
			}
			if len(h.handoffKeys()) != 1 {
				t.Errorf("handoff records = %v, want only the control's", h.handoffKeys())
			}
		})
	}
}

func TestCallbackDesktopRejectsWhenModeDisabledAfterStart(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	signed, _ := h.seedDesktopState(dfNewDV(t))
	if w := h.callback(signed); w.Code != http.StatusOK {
		t.Fatalf("control callback = %d, want 200", w.Code)
	}
	signed, _ = h.seedDesktopState(dfNewDV(t))
	cfg := h.p.getConfiguration()
	raw, _ := json.Marshal(cfg)
	generic := map[string]any{}
	_ = json.Unmarshal(raw, &generic)
	generic["DesktopLoginMode"] = "popup"
	raw, _ = json.Marshal(generic)
	var popupCfg Configuration
	_ = json.Unmarshal(raw, &popupCfg)
	h.p.setConfiguration(&popupCfg)

	w := h.callback(signed)
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "mattermost://") {
		t.Errorf("callback = %d: handoff issued although the mode was switched back to popup (I-46)", w.Code)
	}
	if len(h.handoffKeys()) != 1 {
		t.Errorf("handoff records = %v, want only the control's", h.handoffKeys())
	}
}

func TestCallbackDesktopRejectsMixedStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(map[string]any)
	}{
		{"popup flag", func(s map[string]any) { s["popup"] = true }},
		{"mobile redirect", func(s map[string]any) { s["mobile_redirect"] = "mmauth://callback" }},
		{"unknown mode", func(s map[string]any) { s["mode"] = "desktop_external2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
			signed, _ := h.seedDesktopState(dfNewDV(t))
			if w := h.callback(signed); w.Code != http.StatusOK || len(h.handoffKeys()) != 1 {
				t.Fatalf("control callback = %d, want 200 + one handoff", w.Code)
			}
			signed, _ = h.seedDesktopState(dfNewDV(t), tc.mod)
			w := h.callback(signed)
			if len(h.handoffKeys()) != 1 {
				t.Errorf("mixed state produced a handoff: %v", h.handoffKeys())
			}
			if strings.Contains(w.Body.String(), "oidc_desktop_code") {
				t.Error("mixed state produced a deep link")
			}
		})
	}
}

func TestCallbackDesktopStateReplayNoNewHandoff(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	signed, _ := h.seedDesktopState(dfNewDV(t))
	if w := h.callback(signed); w.Code != http.StatusOK {
		t.Fatalf("first callback = %d, want 200", w.Code)
	}
	w := h.callback(signed)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "mattermost://") {
		t.Errorf("replayed callback = %d (body has link: %v), want 400 error page", w.Code, strings.Contains(w.Body.String(), "mattermost://"))
	}
	if n := len(h.handoffKeys()); n != 1 {
		t.Errorf("handoff records after replay = %d, want 1", n)
	}
}

func TestCallbackDesktopStateExpiredOrTamperedFailsClosed(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	signed, _ := h.seedDesktopState(dfNewDV(t))
	if w := h.callback(signed); w.Code != http.StatusOK {
		t.Fatalf("control callback = %d, want 200", w.Code)
	}
	expired, _ := h.seedDesktopState(dfNewDV(t), func(s map[string]any) { s["create_at"] = time.Now().Add(-11 * time.Minute).UnixMilli() })
	if w := h.callback(expired); w.Code == http.StatusOK {
		t.Error("expired state accepted")
	}
	good, _ := h.seedDesktopState(dfNewDV(t))
	if w := h.callback(dfFlipLast(good)); w.Code == http.StatusOK {
		t.Error("state with tampered signature accepted")
	}
	if w := h.callback(h.p.signState("state-never-stored-0123456789")); w.Code == http.StatusOK {
		t.Error("unknown state accepted")
	}
	if n := len(h.handoffKeys()); n != 1 {
		t.Errorf("handoff records = %d, want only the control's", n)
	}
}

// ================================================================= redeem

func TestRedeemSuccess(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	hc, dv := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hc, dv)
	w := h.redeem(hc, dv)
	if w.Code != http.StatusOK {
		t.Fatalf("redeem = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if len(body) != 1 || body["return_to"] != "/team/channels/town-square" {
		t.Errorf("body = %v, want exactly {\"return_to\":\"/team/channels/town-square\"}", body)
	}
	sess := h.lastSession()
	if sess == nil || h.sessions.Load() != 1 {
		t.Fatalf("sessions created = %d, want 1", h.sessions.Load())
	}
	if sess.UserId != dfUserID || sess.IsOAuth {
		t.Errorf("session user/IsOAuth = %s/%v", sess.UserId, sess.IsOAuth)
	}
	if sess.Props["platform"] != "oidc_plugin" || sess.Props[model.UserAuthServiceIsMobile] != "false" || sess.Props[model.UserAuthServiceIsOAuth] != "true" {
		t.Errorf("session props = %v", sess.Props)
	}
	if body := w.Body.String(); strings.Contains(body, sess.Token) || strings.Contains(body, sess.GetCSRF()) {
		t.Error("redeem body contains the session token or CSRF value (I-11)")
	}
	cookies := dfSetCookies(w)
	tok, ok := cookies[model.SessionCookieToken]
	if !ok || tok.Value != sess.Token || !tok.HttpOnly || !tok.Secure || tok.SameSite != http.SameSiteLaxMode || tok.Path != "/" {
		t.Errorf("MMAUTHTOKEN cookie = %+v", tok)
	}
	if c, ok := cookies[model.SessionCookieCsrf]; !ok || c.Value != sess.GetCSRF() || c.HttpOnly {
		t.Errorf("MMCSRF cookie = %+v", c)
	}
	if c, ok := cookies[model.SessionCookieUser]; !ok || c.Value != dfUserID {
		t.Errorf("MMUSERID cookie = %+v", c)
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Cache-Control/Referrer-Policy = %q/%q", w.Header().Get("Cache-Control"), w.Header().Get("Referrer-Policy"))
	}
	dfNoACAO(t, w)
	if h.kv.get(dfHandoffKey(hc)) != nil {
		t.Error("handoff record still present after successful redeem")
	}
}

func TestRedeemReturnToRevalidated(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"//evil.example", "/"}, {"https://evil.example", "/"}, {`/a\b`, "/"}, {"", "/"}, {"/ok/path", "/ok/path"},
	} {
		h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
		hc, dv := dfNewHC(t), dfNewDV(t)
		h.seedHandoff(hc, dv, func(r *dfRecord) { r.ReturnTo = tc.in })
		w := h.redeem(hc, dv)
		if w.Code != http.StatusOK {
			t.Fatalf("redeem(%q) = %d, want 200", tc.in, w.Code)
		}
		var body struct {
			ReturnTo string `json:"return_to"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body.ReturnTo != tc.want {
			t.Errorf("return_to for stored %q = %q, want %q", tc.in, body.ReturnTo, tc.want)
		}
	}
}

func TestRedeemMalformedInputDoesNotTouchKV(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	hc, dv := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hc, dv)
	// Control: the code is redeemable at all (checked on a twin so the record under test stays intact).
	hc2, dv2 := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hc2, dv2)
	if w := h.redeem(hc2, dv2); w.Code != http.StatusOK {
		t.Fatalf("control redeem = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}

	cases := []struct {
		name string
		body any
	}{
		{"state token as code", map[string]string{"code": "state-0123456789abcdef", "verifier": dv}},
		{"challenge as verifier", map[string]string{"code": hc, "verifier": dfChallenge(dv)}},
		{"verifier as code", map[string]string{"code": dv, "verifier": dv}},
		{"code as verifier", map[string]string{"code": hc, "verifier": hc}},
		{"empty code", map[string]string{"code": "", "verifier": dv}},
		{"missing verifier", map[string]string{"code": hc}},
		{"verifier wrong prefix", map[string]string{"code": hc, "verifier": "dv2_" + dfRandB64(t)}},
		{"code too short", map[string]string{"code": hc[:len(hc)-1], "verifier": dv}},
		{"extra field", map[string]any{"code": hc, "verifier": dv, "popup": "1"}},
		{"array body", []string{hc, dv}},
		{"not JSON", "code=" + hc + "&verifier=" + dv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := h.postJSON(dfRedeemPath, tc.body)
			if w.Code != http.StatusBadRequest || dfErrCode(w) != "invalid_request" {
				t.Errorf("redeem = %d %q, want 400 invalid_request", w.Code, strings.TrimSpace(w.Body.String()))
			}
			if h.kv.get(dfHandoffKey(hc)) == nil {
				t.Error("malformed request consumed a valid handoff record: anyone could burn codes")
			}
			if len(w.Result().Cookies()) != 0 {
				t.Error("rejected redeem set cookies")
			}
		})
	}
	if h.sessions.Load() != 1 { // only the control
		t.Errorf("sessions = %d, want 1 (control only)", h.sessions.Load())
	}
}

func TestRedeemRejectsRequestShape(t *testing.T) {
	// Failures before any KV access: status per spec 2.1, record stays valid.
	hc, dv := dfNewHC(t), dfNewDV(t)
	cases := []struct {
		name   string
		path   string
		mod    func(*http.Request)
		status int
	}{
		{"wrong method", dfRedeemPath, func(r *http.Request) { r.Method = http.MethodGet }, 405},
		{"content type", dfRedeemPath, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"missing X-Requested-With", dfRedeemPath, func(r *http.Request) { r.Header.Del("X-Requested-With") }, 403},
		{"Sec-Fetch-Site cross-site", dfRedeemPath, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"credentials in query", dfRedeemPath + "?code=" + hc + "&verifier=" + dv, nil, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
			h.seedHandoff(hc, dv)
			var mods []func(*http.Request)
			if tc.mod != nil {
				mods = append(mods, tc.mod)
			}
			w := h.postJSON(tc.path, map[string]string{"code": hc, "verifier": dv}, mods...)
			if w.Code != tc.status {
				t.Errorf("status = %d, want %d", w.Code, tc.status)
			}
			if h.sessions.Load() != 0 || len(w.Result().Cookies()) != 0 {
				t.Error("rejected request created a session or cookies")
			}
			if h.kv.get(dfHandoffKey(hc)) == nil {
				t.Error("pre-KV rejection burned the record")
			}
			// Control: with the intact request the record is still redeemable.
			if cw := h.redeem(hc, dv); cw.Code != http.StatusOK {
				t.Errorf("control redeem = %d %q, want 200", cw.Code, strings.TrimSpace(cw.Body.String()))
			}
			dfNoACAO(t, w)
		})
	}
}

// Every decision failure is an identical 401, the code is burned, and no
// session/cookie appears. Cases are the "unknown, expired, tampered, wrongly bound" set.
func TestRedeemFailsClosedAndBurnsCode(t *testing.T) {
	foreignOrigin := func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }
	noOrigin := func(r *http.Request) { r.Header.Del("Origin") }
	cases := []struct {
		name        string
		record      func(*dfRecord)
		user        func(*model.User)
		mod         func(*http.Request)
		verifier    func(dv string) string
		wantStatus  []int // acceptable statuses
		wantBurned  bool
		unknownCode bool
	}{
		{name: "wrong verifier", verifier: func(string) string { return dfNewDV(t) }, wantStatus: []int{401}, wantBurned: true},
		{name: "verifier with one char flipped", verifier: dfFlipLast, wantStatus: []int{401}, wantBurned: true},
		{name: "verifier of another flow", verifier: func(string) string { return dfNewDV(t) }, wantStatus: []int{401}, wantBurned: true},
		{name: "foreign Origin", mod: foreignOrigin, wantStatus: []int{401, 403}, wantBurned: true},
		{name: "missing Origin", mod: noOrigin, wantStatus: []int{401, 403}, wantBurned: true},
		{name: "Origin other port", mod: func(r *http.Request) { r.Header.Set("Origin", "https://mm.example:8443") }, wantStatus: []int{401, 403}, wantBurned: true},
		{name: "expired 121 s", record: func(r *dfRecord) { r.CreateAt = time.Now().Add(-121 * time.Second).UnixMilli() }, wantStatus: []int{401}, wantBurned: true},
		{name: "created in the future", record: func(r *dfRecord) { r.CreateAt = time.Now().Add(10 * time.Minute).UnixMilli() }, wantStatus: []int{401}, wantBurned: true},
		{name: "SiteURL changed since issue", record: func(r *dfRecord) { r.SiteURL = "https://other.example" }, wantStatus: []int{401}, wantBurned: true},
		{name: "record bound to other challenge", record: func(r *dfRecord) { r.Challenge = dfChallenge(dfNewDV(t)) }, wantStatus: []int{401}, wantBurned: true},
		{name: "record version 2", record: func(r *dfRecord) { r.V = 2 }, wantStatus: []int{401}, wantBurned: true},
		{name: "user deactivated", user: func(u *model.User) { u.DeleteAt = model.GetMillis() }, wantStatus: []int{401}, wantBurned: true},
		{name: "user is bot", user: func(u *model.User) { u.IsBot = true }, wantStatus: []int{401}, wantBurned: true},
		{name: "user not an oidc account", user: func(u *model.User) { u.AuthService = "gitlab" }, wantStatus: []int{401}, wantBurned: true},
		{name: "record points to unknown user", record: func(r *dfRecord) { r.UserID = "does-not-exist-000000000000" }, wantStatus: []int{401}, wantBurned: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
			hc, dv := dfNewHC(t), dfNewDV(t)
			// Control twin proves the harness can redeem at all.
			hcOK, dvOK := dfNewHC(t), dfNewDV(t)
			h.seedHandoff(hcOK, dvOK)
			if w := h.redeem(hcOK, dvOK); w.Code != http.StatusOK {
				t.Fatalf("control redeem = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
			}
			sessionsBefore := h.sessions.Load()

			var recMods []func(*dfRecord)
			if tc.record != nil {
				recMods = append(recMods, tc.record)
			}
			h.seedHandoff(hc, dv, recMods...)
			if tc.user != nil {
				tc.user(h.user)
			}
			verifier := dv
			if tc.verifier != nil {
				verifier = tc.verifier(dv)
			}
			var mods []func(*http.Request)
			if tc.mod != nil {
				mods = append(mods, tc.mod)
			}
			w := h.redeem(hc, verifier, mods...)

			okStatus := false
			for _, s := range tc.wantStatus {
				okStatus = okStatus || w.Code == s
			}
			if !okStatus {
				t.Errorf("status = %d, want one of %v", w.Code, tc.wantStatus)
			}
			if w.Code == http.StatusUnauthorized && strings.TrimSpace(w.Body.String()) != `{"error":"invalid_handoff"}` {
				t.Errorf("body = %q, want exactly {\"error\":\"invalid_handoff\"} (no oracle on the failure reason)", strings.TrimSpace(w.Body.String()))
			}
			if len(w.Result().Cookies()) != 0 {
				t.Errorf("failed redeem set cookies: %v", w.Result().Cookies())
			}
			if h.sessions.Load() != sessionsBefore {
				t.Error("failed redeem created a session")
			}
			if tc.wantBurned && h.kv.get(dfHandoffKey(hc)) != nil {
				t.Error("record survived a failed redeem (burn-on-failure, I-09)")
			}
			// The legitimate holder cannot recover the code after a failure.
			h.user.DeleteAt, h.user.IsBot, h.user.AuthService = 0, false, AuthService
			if again := h.redeem(hc, dv); again.Code == http.StatusOK {
				t.Error("code redeemed successfully after a failed attempt")
			}
			dfNoACAO(t, w)
			for _, s := range []string{hc, verifier, dfChallenge(dv)} {
				if strings.Contains(w.Body.String(), s) {
					t.Errorf("error body reflects %q", s)
				}
			}
		})
	}
}

func TestRedeemUnknownAndTamperedCode(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	hc, dv := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hc, dv)
	for name, bad := range map[string]string{
		"unknown":          dfNewHC(t),
		"tampered last":    dfFlipLast(hc),
		"tampered prefix":  "hc2_" + strings.TrimPrefix(hc, "hc1_"),
		"swapped case":     "hc1_" + strings.ToUpper(strings.TrimPrefix(hc, "hc1_")),
		"state-token-like": "hc1_" + strings.Repeat("a", 43),
	} {
		t.Run(name, func(t *testing.T) {
			w := h.redeem(bad, dv)
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 401/400", w.Code)
			}
			if w.Code == http.StatusUnauthorized && strings.TrimSpace(w.Body.String()) != `{"error":"invalid_handoff"}` {
				t.Errorf("body = %q", strings.TrimSpace(w.Body.String()))
			}
			if len(w.Result().Cookies()) != 0 || h.sessions.Load() != 0 {
				t.Error("guessing produced a session/cookies")
			}
		})
	}
	// Guessing must neither consume nor reveal the real record, and the real one still works.
	if w := h.redeem(hc, dv); w.Code != http.StatusOK {
		t.Errorf("legitimate redeem after guesses = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

func TestRedeemReplay(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	hc, dv := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hc, dv)
	if w := h.redeem(hc, dv); w.Code != http.StatusOK {
		t.Fatalf("first redeem = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}
	w := h.redeem(hc, dv)
	if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"error":"invalid_handoff"}` {
		t.Errorf("replay = %d %q, want 401 invalid_handoff", w.Code, strings.TrimSpace(w.Body.String()))
	}
	if len(w.Result().Cookies()) != 0 || h.sessions.Load() != 1 {
		t.Errorf("replay produced cookies or a second session (sessions=%d)", h.sessions.Load())
	}
}

func TestRedeemConcurrentSingleWinner(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	hc, dv := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hc, dv)

	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = h.redeem(hc, dv).Code
		}(i)
	}
	close(start)
	wg.Wait()

	wins, losses := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
		case http.StatusUnauthorized:
			losses++
		}
	}
	if wins != 1 || losses != n-1 {
		t.Errorf("results = %v: want exactly 1x200 and %d x401 (atomic single use, I-14)", codes, n-1)
	}
	if got := h.sessions.Load(); got != 1 {
		t.Errorf("sessions created = %d, want 1", got)
	}
}

func TestRedeemIgnoresIncomingSessionCookies(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	hc, dv := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hc, dv)
	w := h.redeem(hc, dv, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: model.SessionCookieToken, Value: "attacker-token"})
		r.AddCookie(&http.Cookie{Name: model.SessionCookieUser, Value: "attacker-user-id"})
		r.AddCookie(&http.Cookie{Name: model.SessionCookieCsrf, Value: "attacker-csrf"})
	})
	if w.Code != http.StatusOK {
		t.Fatalf("redeem = %d %q, want 200", w.Code, strings.TrimSpace(w.Body.String()))
	}
	c := dfSetCookies(w)
	if c[model.SessionCookieToken] == nil || c[model.SessionCookieToken].Value == "attacker-token" || c[model.SessionCookieToken].Value != h.lastSession().Token {
		t.Errorf("MMAUTHTOKEN cookie not replaced by the fresh session: %+v", c[model.SessionCookieToken])
	}
	if c[model.SessionCookieUser] == nil || c[model.SessionCookieUser].Value != dfUserID {
		t.Errorf("MMUSERID cookie = %+v, want %s", c[model.SessionCookieUser], dfUserID)
	}
	if c[model.SessionCookieCsrf] == nil || c[model.SessionCookieCsrf].Value == "attacker-csrf" {
		t.Errorf("MMCSRF cookie = %+v", c[model.SessionCookieCsrf])
	}
}

func TestRedeemTwoParallelFlowsIndependent(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	hcA, dvA := dfNewHC(t), dfNewDV(t)
	hcB, dvB := dfNewHC(t), dfNewDV(t)
	h.seedHandoff(hcA, dvA)
	h.seedHandoff(hcB, dvB)

	if w := h.redeem(hcA, dvB); w.Code != http.StatusUnauthorized {
		t.Errorf("A with dv_B = %d, want 401", w.Code)
	}
	if w := h.redeem(hcB, dvB); w.Code != http.StatusOK {
		t.Errorf("B with dv_B = %d, want 200 (A's failed attempt must not affect B)", w.Code)
	}
	if w := h.redeem(hcA, dvA); w.Code != http.StatusUnauthorized {
		t.Errorf("A after burn = %d, want 401", w.Code)
	}
	if h.sessions.Load() != 1 {
		t.Errorf("sessions = %d, want 1", h.sessions.Load())
	}
}

// ================================================================= leaks: URLs, HTML, logs, errors

func TestDesktopFlowNeverLeaksSessionSecrets(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	dv := dfNewDV(t)
	dc := dfChallenge(dv)
	hc, cw, authURL := h.requireHandoff(dv, "/team/channels/town-square")

	rw := h.redeem(hc, dv)
	if rw.Code != http.StatusOK {
		t.Fatalf("redeem = %d %q, want 200", rw.Code, strings.TrimSpace(rw.Body.String()))
	}
	sess := h.lastSession()
	if sess == nil {
		t.Fatal("no session")
	}
	token, csrf := sess.Token, sess.GetCSRF()

	// Failure paths whose output is also inspected.
	failures := []*httptest.ResponseRecorder{
		h.redeem(hc, dv),                        // replay
		h.redeem(dfNewHC(t), dfNewDV(t)),        // unknown
		h.redeem("hc1_short", "dv1_short"),      // malformed
		h.start("short", ""),                    // bad challenge
		h.callback(h.p.signState("unknown-st")), // unknown state
	}

	links := dfDeepLinkRe.FindAllString(cw.Body.String(), -1)
	surfaces := map[string]string{
		"authorize_url":     authURL,
		"callback body":     cw.Body.String(),
		"callback headers":  fmt.Sprint(cw.Header()),
		"callback Location": cw.Header().Get("Location"),
		"deep links":        strings.Join(links, "\n"),
		"redeem body":       rw.Body.String(),
		"redeem Location":   rw.Header().Get("Location"),
		"redeem non-cookie hdrs": func() string {
			hd := rw.Header().Clone()
			hd.Del("Set-Cookie")
			return fmt.Sprint(hd)
		}(),
	}
	for i, f := range failures {
		surfaces[fmt.Sprintf("failure %d body", i)] = f.Body.String()
		surfaces[fmt.Sprintf("failure %d headers", i)] = fmt.Sprint(f.Header())
	}
	for name, content := range surfaces {
		for what, secret := range map[string]string{"session token": token, "csrf token": csrf} {
			if strings.Contains(content, secret) {
				t.Errorf("%s contains the %s", name, what)
			}
		}
	}
	for _, name := range []string{"callback body", "callback Location", "deep links", "authorize_url", "redeem body"} {
		for _, term := range []string{"MMAUTHTOKEN", "MMCSRF"} {
			if strings.Contains(surfaces[name], term) {
				t.Errorf("%s mentions %s: the desktop handoff must never carry session cookie data", name, term)
			}
		}
	}
	for _, f := range failures {
		for _, s := range []string{hc, dv, dc} {
			if strings.Contains(f.Body.String(), s) {
				t.Errorf("failure body reflects a flow secret: %q", f.Body.String())
			}
		}
	}
}

// ================================================================= regression guards (green on RC2, must stay green)

func dfWebLoginConnect(t *testing.T, h *dfHarness, query string) (*httptest.ResponseRecorder, OAuthState, string) {
	t.Helper()
	w := h.serve(httptest.NewRequest(http.MethodGet, "/oauth2/connect?"+query, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("connect = %d, want 302", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	signed := loc.Query().Get("state")
	tok, err := h.p.verifyAndExtractState(signed)
	if err != nil {
		t.Fatalf("connect state: %v", err)
	}
	h.lastStateRaw = h.kv.get(KVOAuthStatePrefix + tok)
	var st OAuthState
	if err := json.Unmarshal(h.lastStateRaw, &st); err != nil {
		t.Fatalf("state not in KV: %v", err)
	}
	h.setNonce(st.Nonce)
	return w, st, signed
}

func TestRegressionBrowserFlowUnchanged(t *testing.T) {
	for _, mode := range []string{"", "external_browser"} {
		t.Run("desktop mode "+mode, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: mode})
			cw, _, signed := dfWebLoginConnect(t, h, "return_to=/team/channels/x")
			if strings.Contains(string(h.lastStateRaw), `"mode"`) {
				t.Errorf("browser flow state carries a mode: %s", h.lastStateRaw)
			}
			stateCookie := dfSetCookies(cw)[oidcStateCookie]
			if stateCookie == nil {
				t.Fatal("connect no longer sets MMOIDCSTATE")
			}
			w := h.callback(signed, dfWithCookie(oidcStateCookie, stateCookie.Value))
			if w.Code != http.StatusFound || w.Header().Get("Location") != dfSiteURL+"/team/channels/x" {
				t.Errorf("callback = %d Location %q, want 302 to return_to", w.Code, w.Header().Get("Location"))
			}
			if dfSetCookies(w)[model.SessionCookieToken] == nil || h.sessions.Load() != 1 {
				t.Error("browser login must set MMAUTHTOKEN and create exactly one session")
			}
		})
	}
}

func TestRegressionWebCallbackStillRequiresStateCookie(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	_, _, signed := dfWebLoginConnect(t, h, "return_to=/")
	w := h.callback(signed) // no cookie: login CSRF
	if w.Code != http.StatusBadRequest {
		t.Errorf("callback without MMOIDCSTATE = %d, want 400", w.Code)
	}
	if h.sessions.Load() != 0 || len(dfSetCookies(w)) != 0 && dfSetCookies(w)[model.SessionCookieToken] != nil {
		t.Error("login CSRF exemption leaked into the web flow (I-32): session issued without the state cookie")
	}
	// Popup state is cookie-bound too.
	_, _, signedPopup := dfWebLoginConnect(t, h, "return_to=/&popup=1")
	if w := h.callback(signedPopup); w.Code != http.StatusBadRequest || h.sessions.Load() != 0 {
		t.Errorf("popup callback without cookie = %d (sessions %d), want 400/0", w.Code, h.sessions.Load())
	}
	// And a mismatched cookie value is rejected.
	_, _, signed3 := dfWebLoginConnect(t, h, "return_to=/")
	if w := h.callback(signed3, dfWithCookie(oidcStateCookie, "some-other-state")); w.Code != http.StatusBadRequest || h.sessions.Load() != 0 {
		t.Errorf("callback with wrong cookie = %d (sessions %d), want 400/0", w.Code, h.sessions.Load())
	}
}

func TestRegressionPopupModeStillWorks(t *testing.T) {
	for _, mode := range []string{"", "popup", "external_browser"} {
		t.Run("desktop mode "+mode, func(t *testing.T) {
			h := newDFHarness(t, dfOpts{desktopMode: mode})
			cw, st, signed := dfWebLoginConnect(t, h, "return_to=/team/channels/x&popup=1")
			if !st.Popup || st.MobileRedirect != "" {
				t.Fatalf("popup=1 not stored: %+v", st)
			}
			cookie := dfSetCookies(cw)[oidcStateCookie]
			if cookie == nil {
				t.Fatal("popup connect must set the MMOIDCSTATE cookie (shared Electron jar)")
			}
			w := h.callback(signed, dfWithCookie(oidcStateCookie, cookie.Value))
			if w.Code != http.StatusOK {
				t.Fatalf("popup callback = %d, want 200 HTML page", w.Code)
			}
			body := w.Body.String()
			for _, want := range []string{"mattermost_oidc_login", "window.opener", "window.close()", dfSiteURL + "/team/channels/x"} {
				if !strings.Contains(body, want) {
					t.Errorf("popup page lacks %q", want)
				}
			}
			if dfSetCookies(w)[model.SessionCookieToken] == nil {
				t.Error("popup mode must still set the session cookie in the (shared) browser jar")
			}
			sess := h.lastSession()
			if strings.Contains(body, sess.Token) || strings.Contains(body, sess.GetCSRF()) || strings.Contains(body, "mmauth://") || strings.Contains(body, "mattermost://") {
				t.Error("popup page contains session secrets or deep links")
			}
		})
	}
}

func TestRegressionMobileFlowUnchanged(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	_, st, signed := dfWebLoginConnect(t, h, "mobile_redirect="+url.QueryEscape("mmauth://callback"))
	if st.MobileRedirect != "mmauth://callback" {
		t.Fatalf("mobile redirect not stored: %+v", st)
	}
	w := h.callback(signed) // mobile flow is cookie-exempt
	if w.Code != http.StatusOK {
		t.Fatalf("mobile callback = %d, want 200 page", w.Code)
	}
	body := w.Body.String()
	sess := h.lastSession()
	if !strings.Contains(body, "mmauth://callback?") || !strings.Contains(body, "MMAUTHTOKEN="+sess.Token) || !strings.Contains(body, "MMCSRF="+sess.GetCSRF()) {
		t.Errorf("mobile page lost the mmauth:// handoff:\n%s", body)
	}
	if dfSetCookies(w)[model.SessionCookieToken] != nil {
		t.Error("mobile flow must not set a browser session cookie")
	}
	if sess.Props[model.UserAuthServiceIsMobile] != "true" {
		t.Errorf("mobile session prop = %q", sess.Props[model.UserAuthServiceIsMobile])
	}
	if strings.Contains(body, "mattermost://") || strings.Contains(body, "oidc_desktop_code") {
		t.Error("mobile page contains desktop handoff data")
	}
}

func TestRegressionMobileRedirectAllowlist(t *testing.T) {
	for _, bad := range []string{
		"evil://callback", "https://evil.example/", "mmauth://callback.evil.example", "mmauth://evil",
		"mattermost://login", "javascript:alert(1)", "mmauth://callback/../x", "MMAUTH://callback",
	} {
		h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
		_, st, _ := dfWebLoginConnect(t, h, "mobile_redirect="+url.QueryEscape(bad))
		if st.MobileRedirect != "" {
			t.Errorf("mobile_redirect %q accepted", bad)
		}
	}
	for _, good := range []string{"mmauth://callback", "mmauthbeta://callback", "mmauth://callback?x=1"} {
		h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
		_, st, _ := dfWebLoginConnect(t, h, "mobile_redirect="+url.QueryEscape(good))
		if st.MobileRedirect != good {
			t.Errorf("mobile_redirect %q rejected", good)
		}
	}
}

func TestRegressionConnectReturnToSanitized(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"//evil.example", "/"}, {"https://evil.example", "/"}, {`/a\b`, "/"}, {"/ok", "/ok"}, {"", "/"},
	} {
		h := newDFHarness(t, dfOpts{})
		_, st, _ := dfWebLoginConnect(t, h, "return_to="+url.QueryEscape(tc.in))
		if st.ReturnTo != tc.want {
			t.Errorf("connect return_to %q -> %q, want %q", tc.in, st.ReturnTo, tc.want)
		}
	}
}

func TestRegressionRC2StateJSONLoadsAsWebFlow(t *testing.T) {
	// A state written by RC2 (no mode / desktop_challenge) that is in flight during
	// the update must keep working as a normal web login (spec 3.1, 8).
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	tok := "state-rc2-inflight-0123456789"
	raw := []byte(fmt.Sprintf(`{"token":%q,"create_at":%d,"return_to":"/team","nonce":%q,"code_verifier":"v"}`, tok, time.Now().UnixMilli(), dfNonce))
	h.kv.set(KVOAuthStatePrefix+tok, raw, 600)
	w := h.callback(h.p.signState(tok), dfWithCookie(oidcStateCookie, tok))
	if w.Code != http.StatusFound || w.Header().Get("Location") != dfSiteURL+"/team" {
		t.Errorf("RC2 state callback = %d Location %q, want 302 /team", w.Code, w.Header().Get("Location"))
	}
	if len(h.handoffKeys()) != 0 {
		t.Error("RC2 state produced a desktop handoff")
	}
}

func TestRegressionIdPErrorNotReflected(t *testing.T) {
	h := newDFHarness(t, dfOpts{desktopMode: "external_browser"})
	q := url.Values{"error": {"access_denied"}, "error_description": {"<script>alert(1)</script>hc1_leak"}, "state": {"x"}}
	w := h.serve(httptest.NewRequest(http.MethodGet, "/oauth2/callback?"+q.Encode(), nil))
	if strings.Contains(w.Body.String(), "<script>alert") || strings.Contains(w.Body.String(), "hc1_leak") {
		t.Errorf("IdP error text reflected: %s", w.Body.String())
	}
	if len(h.handoffKeys()) != 0 || strings.Contains(w.Body.String(), "mattermost://") {
		t.Error("IdP error produced a handoff")
	}
	_ = io.Discard
}

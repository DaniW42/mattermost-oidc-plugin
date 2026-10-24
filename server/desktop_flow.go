package main

// System-browser login for Mattermost Desktop ("external_browser" mode).
//
// The Desktop app cannot complete an IdP login in its own window when the IdP
// needs a real browser (password manager, passkeys). In this mode the webapp
// asks the plugin for an authorize URL (start), opens it in the system browser,
// and the system browser finishes the OIDC flow at /oauth2/callback. The
// callback does NOT create a session in that browser: it stores a short-lived,
// single-use handoff record and returns to the app via mattermost://. The app
// then redeems the handoff code together with a secret verifier that never left
// the app, and only then receives the session cookies.
//
//	dv (verifier)  secret, app only; sent only in the redeem body
//	dc (challenge) base64url(SHA-256(dv)); sent at start, bound into state + record
//	hc (handoff)   server generated, 256 bit, only stored hashed, 120 s, single use
//
// The handoff protocol deliberately keeps both session tokens and the verifier
// out of URLs, browser history, and plugin KV values.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"golang.org/x/oauth2"
)

const (
	desktopModePopup           = "popup"
	desktopModeExternalBrowser = "external_browser"

	// stateModeDesktopExternal marks an OAuthState created by /oauth2/desktop/start.
	stateModeDesktopExternal = "desktop_external"

	// KVDesktopHandoffPrefix is the KV prefix of handoff records (key = prefix + hex(SHA-256(domain || hc))).
	KVDesktopHandoffPrefix = "oidc_dh_"

	desktopHandoffDomain = "mattermost-oidc/desktop-handoff/v1\x00"
	desktopHandoffTTL    = 120 * time.Second
	desktopMaxBodyBytes  = 4096
	desktopMaxReturnTo   = 512
	desktopHandoffCodeP  = "hc1_"
)

var (
	desktopChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	desktopCodeRe      = regexp.MustCompile(`^hc1_[A-Za-z0-9_-]{43}$`)
	desktopVerifierRe  = regexp.MustCompile(`^dv1_[A-Za-z0-9_-]{43}$`)
)

// desktopHandoff is the KV record behind a handoff code. It carries no token,
// e-mail or subject.
type desktopHandoff struct {
	V         int    `json:"v"`
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
	SiteURL   string `json:"site_url"`
	ReturnTo  string `json:"return_to"`
	CreateAt  int64  `json:"create_at"`
}

// originOf returns scheme://host[:port] of an absolute URL, or "".
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// effectiveDesktopLoginMode returns external_browser only if the setting says so
// and every precondition holds; otherwise popup (fail closed).
func (p *Plugin) effectiveDesktopLoginMode() string {
	config := p.getConfiguration()
	// Exact match first: this also keeps the default path free of any API call.
	if config.DesktopLoginMode != desktopModeExternalBrowser {
		return desktopModePopup
	}
	if !config.Enable || config.IsValid() != nil {
		return desktopModePopup
	}
	siteURL := p.getSiteURL()
	u, err := url.Parse(siteURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(siteURL, "#") {
		return desktopModePopup
	}
	oauthConfig := p.getOAuthConfig()
	if oauthConfig == nil {
		return desktopModePopup
	}
	// With an IdP on the SiteURL origin the Desktop app would open the IdP URL
	// inside the app instead of handing it to the system browser.
	idp := originOf(oauthConfig.Endpoint.AuthURL)
	if idp == "" || idp == originOf(siteURL) {
		return desktopModePopup
	}
	return desktopModeExternalBrowser
}

// isSafeRelativePath reports whether s is a same-origin relative path.
func isSafeRelativePath(s string) bool {
	if s == "" || len(s) > desktopMaxReturnTo || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.Contains(s, "\\") {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func sanitizeDesktopReturnTo(s string) string {
	if isSafeRelativePath(s) {
		return s
	}
	return "/"
}

func writeDesktopJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeDesktopError(w http.ResponseWriter, status int, code string) {
	writeDesktopJSON(w, status, map[string]string{"error": code})
}

// logDesktopKVError records a storage failure without including the state or
// handoff identifier, which are bearer secrets.
func (p *Plugin) logDesktopKVError(operation, resource string, appErr *model.AppError) {
	p.API.LogError("Desktop login KV operation failed", "operation", operation, "resource", resource, "error", appErr.Error())
}

// desktopPreflight runs the request checks shared by start and redeem that must
// happen before any KV access (spec 2.1, steps 2-5, 9). It writes the error
// response itself and returns false on rejection.
func (p *Plugin) desktopPreflight(w http.ResponseWriter, r *http.Request) bool {
	if p.effectiveDesktopLoginMode() != desktopModeExternalBrowser {
		writeDesktopError(w, http.StatusNotFound, "not_available")
		return false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeDesktopError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	// A custom header forces a CORS preflight for cross-origin callers.
	if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
		writeDesktopError(w, http.StatusForbidden, "forbidden")
		return false
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeDesktopError(w, http.StatusForbidden, "forbidden")
		return false
	}
	if r.URL.RawQuery != "" {
		writeDesktopError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

// decodeDesktopBody strictly decodes a single JSON object of at most 4 KiB.
func decodeDesktopBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, desktopMaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeDesktopError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeDesktopError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

// handleDesktopStart starts a system-browser login and returns the IdP URL.
func (p *Plugin) handleDesktopStart(w http.ResponseWriter, r *http.Request) {
	if !p.desktopPreflight(w, r) {
		return
	}
	siteURL := p.getSiteURL()
	if r.Header.Get("Origin") != originOf(siteURL) {
		writeDesktopError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req struct {
		Challenge string `json:"challenge"`
		ReturnTo  string `json:"return_to"`
	}
	if !decodeDesktopBody(w, r, &req) {
		return
	}
	if !desktopChallengeRe.MatchString(req.Challenge) {
		writeDesktopError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	p.retryOIDCProvider()
	oauthConfig := p.getOAuthConfig()
	if oauthConfig == nil {
		writeDesktopError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}

	stateToken, err1 := generateRandomKey(16)
	nonce, err2 := generateRandomKey(16)
	if err1 != nil || err2 != nil {
		p.API.LogError("Failed to generate desktop login state")
		writeDesktopError(w, http.StatusInternalServerError, "internal")
		return
	}
	codeVerifier := oauth2.GenerateVerifier()
	state := OAuthState{
		Token:            stateToken,
		CreateAt:         time.Now().UnixMilli(),
		ReturnTo:         sanitizeDesktopReturnTo(req.ReturnTo),
		Nonce:            nonce,
		CodeVerifier:     codeVerifier,
		Mode:             stateModeDesktopExternal,
		DesktopChallenge: req.Challenge,
	}
	stateBytes, err := json.Marshal(state)
	if err != nil {
		p.API.LogError("Failed to marshal desktop login state")
		writeDesktopError(w, http.StatusInternalServerError, "internal")
		return
	}
	// No MMOIDCSTATE cookie: the callback arrives in the system browser, which is
	// not the browser (cookie jar) that made this request. Binding is the verifier.
	if appErr := p.API.KVSetWithExpiry(KVOAuthStatePrefix+stateToken, stateBytes, int64(stateExpiry.Seconds())); appErr != nil {
		p.logDesktopKVError("set", "oauth_state", appErr)
		writeDesktopError(w, http.StatusInternalServerError, "internal")
		return
	}

	authURL := oauthConfig.AuthCodeURL(p.signState(stateToken),
		oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(codeVerifier))

	// Self-consistency: only ever hand the app an https URL on the discovered IdP host.
	au, err := url.Parse(authURL)
	idp, idpErr := url.Parse(oauthConfig.Endpoint.AuthURL)
	if err != nil || idpErr != nil || au.Scheme != "https" || au.User != nil || au.Host != idp.Host {
		p.API.LogError("Refusing to return an inconsistent authorize URL")
		writeDesktopError(w, http.StatusInternalServerError, "internal")
		return
	}

	writeDesktopJSON(w, http.StatusOK, map[string]any{
		"authorize_url": authURL,
		"expires_in":    int(stateExpiry.Seconds()),
	})
}

func desktopHandoffKey(code string) string {
	sum := sha256.Sum256([]byte(desktopHandoffDomain + code))
	return KVDesktopHandoffPrefix + hex.EncodeToString(sum[:])
}

func desktopChallengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// handleDesktopRedeem exchanges a handoff code plus the app's verifier for a session.
func (p *Plugin) handleDesktopRedeem(w http.ResponseWriter, r *http.Request) {
	if !p.desktopPreflight(w, r) {
		return
	}
	var req struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if !decodeDesktopBody(w, r, &req) {
		return
	}
	// Format errors never reach the KV store, so nobody can burn a foreign code
	// with garbage and the code/verifier/state-token namespaces stay separate.
	if !desktopCodeRe.MatchString(req.Code) || !desktopVerifierRe.MatchString(req.Verifier) {
		writeDesktopError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	key := desktopHandoffKey(req.Code)
	raw, appErr := p.API.KVGet(key)
	if appErr != nil {
		p.logDesktopKVError("get", "desktop_handoff", appErr)
		writeDesktopError(w, http.StatusInternalServerError, "internal")
		return
	}
	if raw == nil {
		writeDesktopError(w, http.StatusUnauthorized, "invalid_handoff")
		return
	}
	// Atomic single use: exactly one concurrent caller gets deleted == true. From
	// here on the code is burned, whatever else fails.
	deleted, delErr := p.API.KVCompareAndDelete(key, raw)
	if delErr != nil {
		p.logDesktopKVError("compare_delete", "desktop_handoff", delErr)
		writeDesktopError(w, http.StatusInternalServerError, "internal")
		return
	}
	if !deleted {
		writeDesktopError(w, http.StatusUnauthorized, "invalid_handoff")
		return
	}

	user, reason := p.checkDesktopHandoff(r, raw, req.Verifier)
	if reason != "" {
		p.API.LogWarn("Desktop handoff rejected", "reason", reason)
		writeDesktopError(w, http.StatusUnauthorized, "invalid_handoff")
		return
	}
	var rec desktopHandoff
	_ = json.Unmarshal(raw, &rec) // already validated by checkDesktopHandoff

	session, _, sessErr := p.createLoginSession(r, user, false)
	if sessErr != nil {
		p.API.LogError("Failed to create session", "error", sessErr.Error(), "user_id", user.Id)
		writeDesktopError(w, http.StatusInternalServerError, "internal")
		return
	}
	// Session cookies only; the body never carries a token. Incoming session
	// cookies are not read.
	p.setSessionCookie(w, r, session, p.getSiteURL())
	p.API.LogDebug("OIDC desktop login succeeded", "user_id", user.Id)
	writeDesktopJSON(w, http.StatusOK, map[string]string{"return_to": sanitizeDesktopReturnTo(rec.ReturnTo)})
}

// checkDesktopHandoff validates a consumed handoff record. It returns the user
// or a short internal reason (logged, never sent to the client).
func (p *Plugin) checkDesktopHandoff(r *http.Request, raw []byte, verifier string) (*model.User, string) {
	var rec desktopHandoff
	if err := json.Unmarshal(raw, &rec); err != nil || rec.V != 1 {
		return nil, "invalid_record"
	}
	age := time.Since(time.UnixMilli(rec.CreateAt))
	if age < 0 || age > desktopHandoffTTL {
		return nil, "expired"
	}
	siteURL := p.getSiteURL()
	if rec.SiteURL != siteURL || originOf(rec.SiteURL) == "" || r.Header.Get("Origin") != originOf(rec.SiteURL) {
		return nil, "origin_mismatch"
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return nil, "cross_site"
	}
	if !desktopChallengeRe.MatchString(rec.Challenge) ||
		subtle.ConstantTimeCompare([]byte(desktopChallengeOf(verifier)), []byte(rec.Challenge)) != 1 {
		return nil, "verifier_mismatch"
	}
	if p.effectiveDesktopLoginMode() != desktopModeExternalBrowser {
		return nil, "mode_disabled"
	}
	user, appErr := p.API.GetUser(rec.UserID)
	if appErr != nil || user == nil {
		return nil, "user_unavailable"
	}
	if user.DeleteAt > 0 || user.IsBot || user.AuthService != AuthService {
		return nil, "user_not_allowed"
	}
	return user, ""
}

// issueDesktopHandoff stores a handoff record for an authenticated user and
// renders the page that returns to the app. No session is created here.
func (p *Plugin) issueDesktopHandoff(w http.ResponseWriter, state *OAuthState, user *model.User) {
	siteURL := p.getSiteURL()
	u, err := url.Parse(siteURL)
	if err != nil || u.Host == "" {
		p.renderError(w, "Internal error")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		p.API.LogError("Failed to generate desktop handoff code")
		p.renderError(w, "Internal error")
		return
	}
	code := desktopHandoffCodeP + base64.RawURLEncoding.EncodeToString(buf)

	rec, err := json.Marshal(desktopHandoff{
		V: 1, UserID: user.Id, Challenge: state.DesktopChallenge, SiteURL: siteURL,
		ReturnTo: sanitizeDesktopReturnTo(state.ReturnTo), CreateAt: time.Now().UnixMilli(),
	})
	if err != nil {
		p.renderError(w, "Internal error")
		return
	}
	if appErr := p.API.KVSetWithExpiry(desktopHandoffKey(code), rec, int64(desktopHandoffTTL.Seconds())); appErr != nil {
		p.logDesktopKVError("set", "desktop_handoff", appErr)
		p.renderError(w, "Internal error")
		return
	}

	// The link is built from SiteURL only, never from the request.
	deepLink := "mattermost://" + u.Host + strings.TrimRight(u.EscapedPath(), "/") + "/login?oidc_desktop_code=" + code
	p.renderDesktopHandoff(w, deepLink, u.Host, user.Username)
}

// renderDesktopHandoff renders the page shown in the system browser. It carries
// the single-use handoff code in the deep link only (not as visible text).
func (p *Plugin) renderDesktopHandoff(w http.ResponseWriter, deepLink, host, username string) {
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		p.renderError(w, "Internal error")
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nb)
	linkJS, _ := json.Marshal(deepLink) // escapes <, >, & as \u00XX

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	h.Set("Pragma", "no-cache")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nonce, nonce))
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Back to Mattermost</title>
	<style nonce="%[1]s">body { font-family: sans-serif; max-width: 600px; margin: 50px auto; text-align: center; }</style>
</head>
<body>
	<h2>Back to Mattermost</h2>
	<p>You signed in as <strong>@%[2]s</strong> on <strong>%[3]s</strong>.</p>
	<p><a href="%[4]s">Open Mattermost</a></p>
	<p>If nothing opens, the mattermost:// link is not registered on this computer. In the Mattermost window choose &ldquo;Sign in in the app window&rdquo;.</p>
	<script nonce="%[1]s">location.href = %[5]s;</script>
</body>
</html>`, nonce, html.EscapeString(username), html.EscapeString(host), html.EscapeString(deepLink), linkJS)
}

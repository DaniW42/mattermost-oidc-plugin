package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

const (
	// KVDesktopCodePrefix is the KV key prefix for codes handed to the Desktop app.
	KVDesktopCodePrefix = "oidc_dh_"
	desktopCodeExpiry   = 120 * time.Second
)

var (
	desktopChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	desktopCodeRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type desktopCodeRecord struct {
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
	ReturnTo  string `json:"return_to"`
}

func desktopCodeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return KVDesktopCodePrefix + hex.EncodeToString(sum[:])
}

// issueDesktopCode stores a single-use code for the user and sends the system browser back to the Desktop app.
func (p *Plugin) issueDesktopCode(w http.ResponseWriter, state *OAuthState, user *model.User) {
	code, err := generateRandomKey(32)
	if err != nil {
		p.API.LogError("Failed to generate desktop code", "error", err.Error())
		p.renderError(w, "Internal error")
		return
	}
	record, _ := json.Marshal(desktopCodeRecord{UserID: user.Id, Challenge: state.DesktopChallenge, ReturnTo: safeReturnTo(state.ReturnTo)})
	if appErr := p.API.KVSetWithExpiry(desktopCodeKey(code), record, int64(desktopCodeExpiry.Seconds())); appErr != nil {
		p.API.LogError("Failed to store desktop code", "error", appErr.Error())
		p.renderError(w, "Internal error")
		return
	}

	// Built from SiteURL only, never from request headers.
	siteURL, err := url.Parse(strings.TrimRight(p.getSiteURL(), "/"))
	if err != nil || siteURL.Host == "" {
		p.renderError(w, "Internal error")
		return
	}
	p.renderAppRedirect(w, "mattermost://"+siteURL.Host+siteURL.Path+"/login?desktop_code="+code)
}

// handleDesktopRedeem exchanges a desktop code plus the app's verifier for a session.
func (p *Plugin) handleDesktopRedeem(w http.ResponseWriter, r *http.Request) {
	siteURL, err := url.Parse(p.getSiteURL())
	if err != nil || r.Header.Get("Origin") != siteURL.Scheme+"://"+siteURL.Host {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	var req struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		!desktopCodeRe.MatchString(req.Code) || !desktopChallengeRe.MatchString(req.Verifier) {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	user, record := p.redeemDesktopCode(req.Code, req.Verifier)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	session, _, appErr := p.createLoginSession(r, user, false)
	if appErr != nil {
		p.API.LogError("Failed to create session", "error", appErr.Error(), "user_id", user.Id)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	p.setSessionCookie(w, r, session, p.getSiteURL())

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"return_to": record.ReturnTo})
}

// redeemDesktopCode consumes the code and returns its user if the verifier matches the stored challenge.
func (p *Plugin) redeemDesktopCode(code, verifier string) (*model.User, *desktopCodeRecord) {
	raw, err := p.consumeKV(desktopCodeKey(code))
	if err != nil {
		p.API.LogWarn("Desktop code rejected", "error", err.Error())
		return nil, nil
	}
	var record desktopCodeRecord
	if json.Unmarshal(raw, &record) != nil {
		return nil, nil
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(record.Challenge)) != 1 {
		p.API.LogWarn("Desktop code rejected: verifier mismatch")
		return nil, nil
	}
	user, appErr := p.API.GetUser(record.UserID)
	if appErr != nil || user == nil || user.DeleteAt > 0 || user.IsBot || user.AuthService != AuthService {
		p.API.LogWarn("Desktop code rejected: user not eligible")
		return nil, nil
	}
	return user, &record
}

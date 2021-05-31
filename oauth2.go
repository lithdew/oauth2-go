package oauth2

import (
	"context"
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"sync"
	"time"
)

var GlobalSecret = []byte("GrK6N6-u9Tp6&e@=kb&&Af/Pw-9TV-K(pL8pz(?i?CeHWR9&(AE3UWxu=5L*yj##")

type ResponseType string

const (
	ResponseTypeCode    ResponseType = "code"
	ResponseTypeToken   ResponseType = "token"
	ResponseTypeIDToken ResponseType = "id_token"
)

var ResponseTypes = map[ResponseType]struct{}{
	ResponseTypeCode:    {},
	ResponseTypeToken:   {},
	ResponseTypeIDToken: {},
}

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

var GrantTypes = map[GrantType]struct{}{
	GrantTypeAuthorizationCode: {},
	GrantTypeRefreshToken:      {},
}

type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
)

type CodeChallengeMethod string

const (
	CodeChallengePlain CodeChallengeMethod = "plain"
	CodeChallengeS256  CodeChallengeMethod = "S256"
)

var CodeChallengeMethods = map[CodeChallengeMethod]struct{}{
	CodeChallengePlain: {},
	CodeChallengeS256:  {},
}

type AuthorizationCode struct {
	Value               string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod CodeChallengeMethod
	ExpiresAfter        time.Time
}

type AccessToken struct {
	Type         TokenType
	Value        string
	ClientID     string
	ExpiresAfter time.Time
}

type Client struct {
	ID                  string
	Public              bool
	Secret              string
	AllowedScopes       map[string]struct{}
	AllowedRedirectURIs map[string]struct{}
}

type Store struct {
	mu                       sync.Mutex
	Clients                  map[string]Client
	IssuedAuthorizationCodes map[string]AuthorizationCode
	IssuedAccessTokens       map[string]AccessToken
}

func (s *Store) GetClientByID(_ context.Context, id string) (Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	client, found := s.Clients[id]
	return client, found
}

func (s *Store) SaveAuthorizationCode(_ context.Context, code AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.IssuedAuthorizationCodes[code.Value] = code
	return nil
}

func (s *Store) InvalidateAuthorizationCode(_ context.Context, code string) (AuthorizationCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	details, found := s.IssuedAuthorizationCodes[code]
	if !found {
		return details, false
	}

	delete(s.IssuedAuthorizationCodes, code)

	return details, true
}

func (s *Store) SaveAccessToken(_ context.Context, token AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.IssuedAccessTokens[token.Value] = token
	return nil
}

type Server struct {
	Store Store
}

func (s *Server) HandleAuthorizationRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return errors.New("only GET and POST methods are allowed")
	}

	query := r.URL.Query()

	_, err := SanitizeIncomingResponseType(ResponseType(query.Get("response_type"))) // REQUIRED.
	if err != nil {
		return err
	}

	_ = query.Get("scope") // OPTIONAL. TODO(kenta): handle scopes

	clientID := query.Get("client_id") // REQUIRED.
	if clientID == "" {
		return errors.New("missing client id")
	}

	client, found := s.Store.GetClientByID(ctx, clientID)
	if !found {
		return fmt.Errorf("client '%s' not registered", clientID)
	}

	targetURI, redirectURI, err := SanitizeIncomingRedirectURI(client, query.Get("redirect_uri")) // OPTIONAL.
	if err != nil {
		return err
	}

	state := query.Get("state") // REQUIRED.
	if state == "" {
		return errors.New("state must be provided")
	}

	nonce := query.Get("nonce") // OPTIONAL.

	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := CodeChallengeMethod(query.Get("code_challenge_method"))
	if err := ValidateIncomingCodeChallengePKCE(client, codeChallenge, codeChallengeMethod); err != nil {
		return err
	}

	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/login?login_challenge=abcdef", http.StatusFound)
		return nil
	}

	value, _, _, err := GenerateOpaqueValue(GlobalSecret)
	if err != nil {
		return err
	}

	code := AuthorizationCode{
		Value:               value,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAfter:        time.Now().UTC().Add(10 * time.Minute),
	}

	if err := s.Store.SaveAuthorizationCode(ctx, code); err != nil {
		return fmt.Errorf("failed to save authorization code: %w", err)
	}

	query = targetURI.Query()
	query.Set("code", code.Value)
	query.Set("state", state)
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	targetURI.RawQuery = query.Encode()

	http.Redirect(w, r, targetURI.String(), http.StatusFound)

	return nil
}

func (s *Server) HandleAccessTokenRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return errors.New("only POST method is allowed")
	}

	_, err := SanitizeIncomingGrantType(GrantType(r.PostFormValue("grant_type"))) // REQUIRED.
	if err != nil {
		return err
	}

	code := r.PostFormValue("code")
	if err := VerifyOpaqueValue(GlobalSecret, code); err != nil {
		return err
	}

	details, found := s.Store.InvalidateAuthorizationCode(ctx, code)
	if !found {
		return fmt.Errorf("unknown authorization code '%s'", code)
	}

	if time.Now().After(details.ExpiresAfter) {
		return errors.New("the authorization code has expired")
	}

	codeVerifier := r.PostFormValue("code_verifier")
	switch details.CodeChallengeMethod {
	case CodeChallengePlain:
		if codeVerifier != details.CodeChallenge {
			return errors.New("bad code verifier")
		}
	case CodeChallengeS256:
		if GenerateCodeChallengePKCE(codeVerifier) != details.CodeChallenge {
			return errors.New("bad code verifier")
		}
	}

	redirectURI := r.PostFormValue("redirect_uri")
	if details.RedirectURI != redirectURI {
		return errors.New("redirect_uri either was not specified, or is mismatched")
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID, clientSecret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	} else {
		if _, exists := r.PostForm["client_id"]; exists {
			return errors.New("cannot specify multiple client authentication methods")
		}
		if _, exists := r.PostForm["client_secret"]; exists {
			return errors.New("cannot specify multiple client authentication methods")
		}
	}

	if details.ClientID != clientID {
		return errors.New("client_id either was not specified, or is mismatched")
	}

	client, found := s.Store.GetClientByID(ctx, clientID)
	if !found {
		return fmt.Errorf("unknown client_id '%s'", clientID)
	}

	if client.Secret != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(clientSecret)); err != nil {
			return fmt.Errorf("client authentication failed: %w", err)
		}
	}

	value, _, _, err := GenerateOpaqueValue(GlobalSecret)
	if err != nil {
		return err
	}

	token := AccessToken{
		Type:         TokenTypeBearer,
		Value:        value,
		ClientID:     clientID,
		ExpiresAfter: time.Now().UTC().Add(30 * time.Minute),
	}

	if err := s.Store.SaveAccessToken(ctx, token); err != nil {
		return fmt.Errorf("failed to save access token: %w", err)
	}

	type Response struct {
		AccessToken  string    `json:"access_token"`
		TokenType    TokenType `json:"token_type"`
		ExpiresIn    int64     `json:"expires_in"`
		RefreshToken string    `json:"refresh_token,omitempty"`
		Scope        string    `json:"scope"`
	}

	res, err := json.Marshal(Response{
		AccessToken: token.Value,
		TokenType:   token.Type,
		ExpiresIn:   (30 * time.Minute).Milliseconds(),
		Scope:       "",
	})
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if _, err = w.Write(res); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}

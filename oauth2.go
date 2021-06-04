package oauth2

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var ErrFlowNotFound = errors.New("flow not found")

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

type LoginFlow struct {
	ID                string     `json:"id"`
	RequestedScope    string     `json:"requested_scope"`
	RequestedAudience string     `json:"requested_audience"`
	ClientID          string     `json:"client_id"`
	RequestURL        string     `json:"request_url"`
	RequestedAt       time.Time  `json:"requested_at"`
	RememberUntil     *time.Time `json:"remember_for"`
	AuthenticatedAt   *time.Time `json:"authenticated_at"`
}

type RegistrationFlow struct {
	ID         string    `json:"id"`
	RequestURL string    `json:"request_url"`
	ExpiresAt  time.Time `json:"expires_at"`
	IssuedAt   time.Time `json:"issued_at"`
}

type VerificationFlow struct {
	ID           string    `json:"id"`
	Code         string    `json:"code"`
	AttemptsLeft uint      `json:"attempts_left"`
	AddressID    string    `json:"address_id"`
	RequestURL   string    `json:"request_url"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
	SentAt       time.Time `json:"sent_at"`
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
	ThirdParty          bool
	AllowedScopes       map[string]struct{}
	AllowedRedirectURIs map[string]struct{}
}

func (c Client) GetRedirectURI() string {
	for redirectURI := range c.AllowedRedirectURIs {
		return redirectURI
	}
	return ""
}

type Store struct {
	mu      sync.Mutex
	Clients map[string]Client

	IssuedAuthorizationCodes map[string]AuthorizationCode
	IssuedAccessTokens       map[string]AccessToken

	LoginFlows        map[string]LoginFlow
	RegistrationFlows map[string]RegistrationFlow
	VerificationFlows map[string]VerificationFlow

	Identities          map[string]Identity
	VerifiableAddresses map[string]VerifiableAddress
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

func (s *Store) CreateLoginFlow(_ context.Context, flow LoginFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.LoginFlows[flow.ID]; exists {
		return errors.New("login flow already exists")
	}
	s.LoginFlows[flow.ID] = flow
	return nil
}

func (s *Store) GetLoginFlow(_ context.Context, flowID string) (LoginFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flow, exists := s.LoginFlows[flowID]
	if !exists {
		return flow, errors.New("login flow not found")
	}

	return flow, nil
}

func (s *Store) UpdateLoginFlow(_ context.Context, flow LoginFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.LoginFlows[flow.ID]
	if !exists {
		return errors.New("login flow not found")
	}
	s.LoginFlows[flow.ID] = flow

	return nil
}

func (s *Store) CreateRegistrationFlow(_ context.Context, flow RegistrationFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.RegistrationFlows[flow.ID]; exists {
		return errors.New("registration flow already exists")
	}
	s.RegistrationFlows[flow.ID] = flow
	return nil
}

func (s *Store) GetRegistrationFlow(_ context.Context, flowID string) (RegistrationFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flow, found := s.RegistrationFlows[flowID]
	if !found {
		return flow, fmt.Errorf("no registration flow under id %s: %w", flowID, ErrFlowNotFound)
	}

	return flow, nil
}

func (s *Store) CreateVerificationFlow(_ context.Context, flow VerificationFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.VerificationFlows[flow.ID]; exists {
		return errors.New("verification flow already exists")
	}
	s.VerificationFlows[flow.ID] = flow
	return nil
}

func (s *Store) GetVerificationFlow(_ context.Context, flowID string) (VerificationFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flow, found := s.VerificationFlows[flowID]
	if !found {
		return flow, fmt.Errorf("no verification flow under id %s: %w", flowID, ErrFlowNotFound)
	}

	return flow, nil
}

func (s *Store) UpdateVerificationFlow(_ context.Context, flow VerificationFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, found := s.VerificationFlows[flow.ID]
	if !found {
		return fmt.Errorf("no verification flow under id %s: %w", flow.ID, ErrFlowNotFound)
	}

	s.VerificationFlows[flow.ID] = flow

	return nil
}

func (s *Store) CreateVerifiableAddress(_ context.Context, address VerifiableAddress) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, found := s.VerifiableAddresses[address.Value]
	if found {
		return errors.New("verifiable address already exists ")
	}

	s.VerifiableAddresses[address.Value] = address

	return nil
}

func (s *Store) GetVerifiableAddress(_ context.Context, addressValue string) (VerifiableAddress, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	address, found := s.VerifiableAddresses[addressValue]
	if !found {
		return address, errors.New("verifiable address not found")
	}

	return address, nil
}

func (s *Store) UpdateVerifiableAddress(_ context.Context, address VerifiableAddress) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, found := s.VerifiableAddresses[address.Value]
	if !found {
		return errors.New("verifiable address not found")
	}
	s.VerifiableAddresses[address.Value] = address

	return nil
}

func (s *Store) CreateIdentity(_ context.Context, identity Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Identities[identity.ID] = identity
	return nil
}

func (s *Store) GetIdentity(_ context.Context, identityID string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	identity, exists := s.Identities[identityID]
	if !exists {
		return identity, errors.New("identity not found")
	}

	return identity, nil
}

func (s *Store) UpdateIdentity(_ context.Context, identity Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.Identities[identity.ID]
	if !exists {
		return errors.New("identity not found")
	}
	s.Identities[identity.ID] = identity
	return nil
}

type Server struct {
	DefaultClientID string
	LoginURL        url.URL
	AuthorizeURL    url.URL
	RegistrationURL url.URL
	VerificationURL url.URL
	Store           Store
}

func (s *Server) HandleAuthorizationRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	query := r.URL.Query()

	_, err := SanitizeIncomingResponseType(ResponseType(query.Get("response_type"))) // REQUIRED.
	if err != nil {
		return err
	}

	scope := query.Get("scope")       // OPTIONAL. TODO(kenta): handle scopes
	audience := query.Get("audience") // OPTIONAL. TODO(kenta): handle audience

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

	state := query.Get("state") // OPTIONAL.
	nonce := query.Get("nonce") // OPTIONAL.

	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := CodeChallengeMethod(query.Get("code_challenge_method"))
	if err := ValidateIncomingCodeChallengePKCE(client, codeChallenge, codeChallengeMethod); err != nil {
		return err
	}

	flow, err := s.Store.GetLoginFlow(ctx, query.Get("flow"))
	if err != nil {
		flow := LoginFlow{
			ID:                ksuid.New().String(),
			RequestedScope:    scope,
			RequestedAudience: audience,
			ClientID:          clientID,
			RequestURL:        r.URL.String(),
			RequestedAt:       time.Now(),
			RememberUntil:     nil,
			AuthenticatedAt:   nil,
		}

		return s.HandleNewLoginFlow(flow, ctx, w, r)
	}

	if flow.AuthenticatedAt == nil {
		redirectTo := s.LoginURL
		query := redirectTo.Query()
		query.Set("flow", flow.ID)
		redirectTo.RawQuery = query.Encode()

		http.Redirect(w, r, redirectTo.String(), http.StatusFound)

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
		if otherClientID := r.PostFormValue("client_id"); otherClientID != "" && clientID != otherClientID {
			return errors.New("mismatch in client_id in http header and post body")
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

type CredentialsType string

const (
	CredentialsTypePassword CredentialsType = "password"
	CredentialsTypeOIDC     CredentialsType = "oidc"
	CredentialsTypeSAML     CredentialsType = "saml"
)

type IdentityState string

const (
	IdentityStateActive   IdentityState = "active"
	IdentityStateInactive IdentityState = "inactive"
)

type VerifiableAddressStatus string

const (
	VerifiableAddressStatusPending   VerifiableAddressStatus = "pending"
	VerifiableAddressStatusCompleted VerifiableAddressStatus = "completed"
)

type Credentials struct {
	ID          string
	Type        CredentialsType
	Identifiers []string
	Details     json.RawMessage
}

type PasswordCredentials struct {
	Hash string `json:"hash"`
	Salt string `json:"salt"`
}

type Identity struct {
	ID          string                          `json:"id"`
	Credentials map[CredentialsType]Credentials `json:"credentials"`
	Traits      json.RawMessage                 `json:"traits"`
	State       IdentityState                   `json:"state"`

	LoginAttemptsLeft      uint      `json:"login_attempts_left"`
	LastFailedLoginAttempt time.Time `json:"last_failed_login_attempt"`
}

type VerifiableAddress struct {
	Value      string
	IdentityID string
	Verified   VerifiableAddressStatus
	VerifiedAt time.Time
}

func (s *Server) HandleNewLoginFlow(flow LoginFlow, ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if err := s.Store.CreateLoginFlow(ctx, flow); err != nil {
		return err
	}

	redirectTo := s.LoginURL
	query := redirectTo.Query()
	query.Set("flow", flow.ID)
	redirectTo.RawQuery = query.Encode()

	http.Redirect(w, r, redirectTo.String(), http.StatusFound)

	return nil
}

func (s *Server) HandleSubmitLoginFlow(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	referrer, err := url.Parse(r.Referer())
	if err != nil {
		return errors.New("bad referrer")
	}

	flow, err := s.Store.GetLoginFlow(ctx, referrer.Query().Get("flow"))
	if err != nil {
		return err
	}

	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	remember := r.PostFormValue("remember") != ""

	address, err := s.Store.GetVerifiableAddress(ctx, email)
	if err != nil {
		return errors.New("no accounts could be found with those credentials")
	}

	identity, err := s.Store.GetIdentity(ctx, address.IdentityID)
	if err != nil {
		return errors.New("no accounts could be found with those credentials")
	}

	credentials, exists := identity.Credentials[CredentialsTypePassword]
	if !exists {
		return errors.New("no accounts could be found with those credentials")
	}

	var details PasswordCredentials
	if err := json.Unmarshal(credentials.Details, &details); err != nil {
		return fmt.Errorf("malformed identity password credentials: %w", err)
	}

	if identity.LoginAttemptsLeft == 0 {
		if time.Now().Sub(identity.LastFailedLoginAttempt) < 24*time.Hour {
			return errors.New("your account has been locked for safety, please wait 24 hours or reset your password")
		}

		identity.LoginAttemptsLeft = 10
	}

	if err := bcrypt.CompareHashAndPassword([]byte(details.Hash), append([]byte(password), []byte(details.Salt)...)); err != nil {
		identity.LoginAttemptsLeft -= 1
		identity.LastFailedLoginAttempt = time.Now()
		if err := s.Store.UpdateIdentity(ctx, identity); err != nil {
			return err
		}
		return fmt.Errorf("incorrect password: %w", err)
	}

	flow.AuthenticatedAt = func(t time.Time) *time.Time { return &t }(time.Now())
	if remember {
		flow.RememberUntil = func(t time.Time) *time.Time { return &t }(flow.AuthenticatedAt.Add(6 * time.Hour))
	}

	redirectTo, err := url.Parse(flow.RequestURL)
	if err != nil {
		identity.LoginAttemptsLeft -= 1
		identity.LastFailedLoginAttempt = time.Now()
		if err := s.Store.UpdateIdentity(ctx, identity); err != nil {
			return err
		}
		return fmt.Errorf("bad redirect url: %w", err)
	}

	if err := s.Store.UpdateLoginFlow(ctx, flow); err != nil {
		identity.LoginAttemptsLeft -= 1
		identity.LastFailedLoginAttempt = time.Now()
		if err := s.Store.UpdateIdentity(ctx, identity); err != nil {
			return err
		}
		return err
	}

	identity.LoginAttemptsLeft = 10
	if err := s.Store.UpdateIdentity(ctx, identity); err != nil {
		return err
	}

	query := redirectTo.Query()
	query.Set("flow", flow.ID)
	redirectTo.RawQuery = query.Encode()

	http.Redirect(w, r, redirectTo.String(), http.StatusFound)

	return nil
}

func (s *Server) HandleNewRegistrationFlow(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	iat := time.Now().UTC()

	flow := RegistrationFlow{
		ID:         ksuid.New().String(),
		RequestURL: r.URL.String(),
		ExpiresAt:  iat.Add(30 * time.Minute),
		IssuedAt:   iat,
	}

	if err := s.Store.CreateRegistrationFlow(ctx, flow); err != nil {
		return err
	}

	redirectTo := s.RegistrationURL
	query := redirectTo.Query()
	query.Set("flow", flow.ID)
	redirectTo.RawQuery = query.Encode()

	http.Redirect(w, r, redirectTo.String(), http.StatusFound)

	return nil
}

func (s *Server) HandleSubmitRegistrationFlow(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	referrer, err := url.Parse(r.Referer())
	if err != nil {
		return errors.New("bad referrer")
	}

	flow, err := s.Store.GetRegistrationFlow(ctx, referrer.Query().Get("flow"))
	if err != nil {
		return err
	}

	if time.Now().After(flow.ExpiresAt) { // Flow expired, redirect to registration page.
		http.Redirect(w, r, s.RegistrationURL.String(), http.StatusFound)
		return nil
	}

	email := r.PostFormValue("email")
	if _, err := s.Store.GetVerifiableAddress(ctx, email); err == nil {
		return errors.New("email already used")
	}

	password := r.PostFormValue("password")
	salt := ksuid.New().String()

	hash, err := bcrypt.GenerateFromPassword(append([]byte(password), salt...), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	details, err := json.Marshal(PasswordCredentials{
		Hash: string(hash),
		Salt: salt,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal password details: %w", err)
	}

	credentials := Credentials{
		ID:      ksuid.New().String(),
		Type:    CredentialsTypePassword,
		Details: details,
	}

	identity := Identity{
		ID:    ksuid.New().String(),
		State: IdentityStateActive,
		Credentials: map[CredentialsType]Credentials{
			CredentialsTypePassword: credentials,
		},
		LoginAttemptsLeft:      10,
		LastFailedLoginAttempt: time.Time{},
	}

	address := VerifiableAddress{
		IdentityID: identity.ID,
		Verified:   VerifiableAddressStatusPending,
		Value:      email,
		VerifiedAt: time.Time{},
	}

	if err := s.Store.CreateIdentity(ctx, identity); err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	if err := s.Store.CreateVerifiableAddress(ctx, address); err != nil {
		return err
	}

	// Registration considered successful. However, account wouldn't be considered
	// to have been created until the user has passed verification. Start the
	// verification flow now.

	return s.HandleNewVerificationFlow(address.Value, ctx, w, r)
}

func (s *Server) HandleNewVerificationFlow(addressID string, ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	iat := time.Now().UTC()

	flow := VerificationFlow{
		ID:           ksuid.New().String(),
		AttemptsLeft: 3,
		AddressID:    addressID,
		RequestURL:   r.URL.String(),
		ExpiresAt:    iat.Add(10 * time.Minute),
		IssuedAt:     iat,
		SentAt:       iat,
	}

	var code [4]byte
	if _, err := io.ReadFull(rand.Reader, code[:]); err != nil {
		return fmt.Errorf("failed to generate verification code: %w", err)
	}
	for i := range code {
		code[i] %= 10
		code[i] += '0'
	}
	flow.Code = string(code[:])

	fmt.Println("issued a verification code:", flow.Code)

	if err := s.Store.CreateVerificationFlow(ctx, flow); err != nil {
		return err
	}

	redirectTo := s.VerificationURL
	query := redirectTo.Query()
	query.Set("flow", flow.ID)
	redirectTo.RawQuery = query.Encode()

	http.Redirect(w, r, redirectTo.String(), http.StatusFound)

	return nil
}

func (s *Server) HandleSubmitVerificationFlow(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	referrer, err := url.Parse(r.Referer())
	if err != nil {
		return errors.New("bad referrer")
	}

	flow, err := s.Store.GetVerificationFlow(ctx, referrer.Query().Get("flow"))
	if err != nil {
		return err
	}

	address, err := s.Store.GetVerifiableAddress(ctx, flow.AddressID)
	if err != nil {
		return err
	}

	if address.Verified == VerifiableAddressStatusCompleted {
		http.Redirect(w, r, "/", http.StatusFound)
		return nil
	}

	now := time.Now()

	if r.PostFormValue("submit") != "" {
		if now.After(flow.ExpiresAt) || flow.AttemptsLeft == 0 {
			return errors.New("a new verification token needs to be issued, click 'Resend Verification Code'")
		}

		if flow.Code == r.PostFormValue("code") {
			address.Verified = VerifiableAddressStatusCompleted
			if err := s.Store.UpdateVerifiableAddress(ctx, address); err != nil {
				return err
			}
		} else {
			flow.AttemptsLeft -= 1

			if err := s.Store.UpdateVerificationFlow(ctx, flow); err != nil {
				return err
			}

			return errors.New("verification code is incorrect")
		}
	} else if r.PostFormValue("refresh") != "" {
		if duration := now.Sub(flow.SentAt); duration < 1*time.Minute { // Verification code may only be sent once every minute.
			return fmt.Errorf("you must wait %s before having a verification code sent again to you", 1*time.Minute-duration)
		}

		if now.After(flow.ExpiresAt) || flow.AttemptsLeft == 0 { // Verification code has expired. Reissue it.
			var code [4]byte
			if _, err := io.ReadFull(rand.Reader, code[:]); err != nil {
				return fmt.Errorf("failed to generate verification code: %w", err)
			}
			for i := range code {
				code[i] %= 10
				code[i] += '0'
			}
			flow.AttemptsLeft = 3
			flow.Code = string(code[:])
			flow.IssuedAt = now.UTC()
			flow.ExpiresAt = now.Add(10 * time.Minute)

			fmt.Println("issuing and resending a new verification code:", flow.Code)
		}

		flow.SentAt = now

		// TODO(kenta): send verification code

		if err := s.Store.UpdateVerificationFlow(ctx, flow); err != nil {
			return err
		}
	} else {
		return errors.New("unknown action")
	}

	redirectTo := s.VerificationURL
	query := redirectTo.Query()
	query.Set("flow", flow.ID)
	redirectTo.RawQuery = query.Encode()

	http.Redirect(w, r, redirectTo.String(), http.StatusFound)

	return nil
}

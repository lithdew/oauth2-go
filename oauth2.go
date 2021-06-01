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

type RegistrationFlow struct {
	ID         string    `json:"id"`
	RequestURL string    `json:"request_url"`
	ExpiresAt  time.Time `json:"expires_at"`
	IssuedAt   time.Time `json:"issued_at"`
	CSRFToken  string    `json:"-"`
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
	CSRFToken    string    `json:"-"`
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

type Store struct {
	mu      sync.Mutex
	Clients map[string]Client

	IssuedAuthorizationCodes map[string]AuthorizationCode
	IssuedAccessTokens       map[string]AccessToken

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

	_, found := s.VerifiableAddresses[address.ID]
	if found {
		return errors.New("verifiable address already exists ")
	}

	s.VerifiableAddresses[address.ID] = address

	return nil
}

func (s *Store) GetVerifiableAddress(_ context.Context, addressID string) (VerifiableAddress, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	address, found := s.VerifiableAddresses[addressID]
	if !found {
		return address, errors.New("verifiable address not found")
	}

	return address, nil
}

func (s *Store) UpdateVerifiableAddress(_ context.Context, address VerifiableAddress) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, found := s.VerifiableAddresses[address.ID]
	if !found {
		return errors.New("verifiable address not found")
	}
	s.VerifiableAddresses[address.ID] = address

	return nil
}

func (s *Store) CreateIdentity(_ context.Context, identity Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Identities[identity.ID] = identity
	return nil
}

type Server struct {
	RegistrationURL url.URL
	VerificationURL url.URL
	Store           Store
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

type VerifiableAddressType string

const (
	VerifiableAddressTypeEmail VerifiableAddressType = "email"
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

type Identity struct {
	ID                  string                          `json:"id"`
	Credentials         map[CredentialsType]Credentials `json:"credentials"`
	Traits              json.RawMessage                 `json:"traits"`
	State               IdentityState                   `json:"state"`
	VerifiableAddresses []VerifiableAddress             `json:"verifiable_addresses"`
}

func (i Identity) IsVerified() bool {
	for _, address := range i.VerifiableAddresses {
		if address.Verified == VerifiableAddressStatusCompleted {
			return true
		}
	}
	return false
}

type VerifiableAddress struct {
	ID         string
	IdentityID string
	Verified   VerifiableAddressStatus
	Value      string
	VerifiedAt time.Time
}

func (s *Server) HandleNewRegistrationFlow(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	iat := time.Now().UTC()

	flow := RegistrationFlow{
		ID:         ksuid.New().String(),
		RequestURL: r.URL.String(),
		ExpiresAt:  iat.Add(30 * time.Minute),
		IssuedAt:   iat,
		CSRFToken:  ksuid.New().String(),
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

	if flow.CSRFToken != r.PostFormValue("csrf_token") {
		return errors.New("csrf token is invalid")
	}

	email := r.PostFormValue("email")

	password := r.PostFormValue("password")
	salt := ksuid.New().Bytes()

	hash, err := bcrypt.GenerateFromPassword(append([]byte(password), salt...), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	details, err := json.Marshal(struct {
		Hash string `json:"hash"`
		Salt string `json:"salt"`
	}{
		Hash: string(hash),
		Salt: string(salt),
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
	}

	address := VerifiableAddress{
		ID:         ksuid.New().String(),
		IdentityID: identity.ID,
		Verified:   VerifiableAddressStatusPending,
		Value:      email,
		VerifiedAt: time.Time{},
	}

	identity.VerifiableAddresses = append(identity.VerifiableAddresses, address)

	if err := s.Store.CreateIdentity(ctx, identity); err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	if err := s.Store.CreateVerifiableAddress(ctx, address); err != nil {
		return err
	}

	// Registration considered successful. However, account wouldn't be considered
	// to have been created until the user has passed verification. Start the
	// verification flow now.

	return s.HandleNewVerificationFlow(address.ID, ctx, w, r)
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
		CSRFToken:    ksuid.New().String(),
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

	if flow.CSRFToken != r.PostFormValue("csrf_token") {
		return errors.New("csrf token is invalid")
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
		}

		flow.SentAt = now

		if err := s.Store.UpdateVerificationFlow(ctx, flow); err != nil {
			return err
		}

		fmt.Println("issuing and resending a new verification code:", flow.Code)

		// TODO(kenta): send verification code

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

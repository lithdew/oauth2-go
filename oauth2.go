package oauth2

import (
	"context"
	"errors"
	"fmt"
	"github.com/segmentio/ksuid"
	"net/http"
	"net/url"
	"sync"
	"time"
)

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

type AuthorizationRequest struct {
	ResponseType string
	ClientID     string
	RedirectURI  url.URL
}

type AuthorizationCode struct {
	ClientID     string
	Value        string
	ExpiresAfter time.Time
}

type Client struct {
	AllowedScopes       map[string]struct{}
	AllowedRedirectURIs map[string]struct{}
}

type Store struct {
	mu                       sync.Mutex
	Clients                  map[string]Client
	IssuedAuthorizationCodes map[string]AuthorizationCode // client id -> authorization code
}

func (s *Store) GetClientByID(_ context.Context, id string) (Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	client, found := s.Clients[id]
	return client, found
}

func (s *Store) SaveAuthorizationCode(_ context.Context, code AuthorizationCode) error {
	s.IssuedAuthorizationCodes[code.ClientID] = code
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

	responseType := ResponseType(query.Get("response_type")) // REQUIRED.
	if _, registered := ResponseTypes[responseType]; !registered {
		return fmt.Errorf("unknown response type '%s'", responseType)
	}
	if responseType == ResponseTypeToken {
		return errors.New("only authorization codes and id tokens may be generated")
	}

	redirectURI := query.Get("redirect_uri") // REQUIRED (OPTIONAL if client has no registered redirect uri's).
	parsedRedirectURI := (*url.URL)(nil)
	if redirectURI != "" {
		var err error

		parsedRedirectURI, err = url.Parse(redirectURI)
		if err != nil {
			return fmt.Errorf("bad redirect uri '%s': %w", redirectURI, err)
		}

		if !parsedRedirectURI.IsAbs() {
			return fmt.Errorf("redirect uri '%s' must be absolute", redirectURI)
		}
	}

	scope := query.Get("scope") // OPTIONAL.
	_ = scope                   // TODO(kenta): handle scopes

	state := query.Get("state") // RECOMMENDED.

	nonce := query.Get("nonce") // OPTIONAL.

	clientID := query.Get("client_id") // REQUIRED.
	if clientID == "" {
		return errors.New("missing client id")
	}

	client, found := s.Store.GetClientByID(ctx, clientID)
	if !found {
		return fmt.Errorf("client with id '%s' not registered", clientID)
	}

	if len(client.AllowedRedirectURIs) != 1 && parsedRedirectURI == nil {
		return errors.New("redirect uri must be specified")
	}

	if len(client.AllowedRedirectURIs) != 0 && parsedRedirectURI != nil {
		if _, allowed := client.AllowedRedirectURIs[redirectURI]; !allowed {
			return fmt.Errorf("redirect uri '%s' is not authorized under client id '%s'", redirectURI, clientID)
		}
	}

	if parsedRedirectURI == nil {
		var err error

		for allowedRedirectURI := range client.AllowedRedirectURIs {
			redirectURI = allowedRedirectURI

			parsedRedirectURI, err = url.Parse(redirectURI)
			if err != nil {
				return fmt.Errorf("client-registered allowed redirect uri '%s' is not valid: %w", redirectURI, err)
			}

			if !parsedRedirectURI.IsAbs() {
				return fmt.Errorf("client-registered redirect uri '%s' is not absolute", redirectURI)
			}

			break
		}
	}

	code := AuthorizationCode{
		ClientID:     clientID,
		Value:        ksuid.New().String(),
		ExpiresAfter: time.Now().UTC().Add(10 * time.Minute),
	}

	if err := s.Store.SaveAuthorizationCode(ctx, code); err != nil {
		return fmt.Errorf("failed to save authorization code: %w", err)
	}

	query = parsedRedirectURI.Query()
	query.Set("code", code.Value)
	if state != "" {
		query.Set("state", state)
	}
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	parsedRedirectURI.RawQuery = query.Encode()

	http.Redirect(w, r, parsedRedirectURI.String(), http.StatusFound)

	return nil
}

package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/segmentio/ksuid"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var ErrFlowNotFound = errors.New("flow not found")

type Store struct {
	mu                sync.Mutex
	RegistrationFlows map[string]RegistrationFlow
}

func (s *Store) CreateRegistrationFlow(ctx context.Context, flow RegistrationFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.RegistrationFlows[flow.ID] = flow
	return nil
}

func (s *Store) GetRegistrationFlow(ctx context.Context, flowID string) (RegistrationFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flow, found := s.RegistrationFlows[flowID]
	if !found {
		return flow, fmt.Errorf("no registration flow under id %s: %w", flowID, ErrFlowNotFound)
	}

	return flow, nil
}

type RegistrationFlow struct {
	ID         string    `json:"id"`
	RequestURL string    `json:"request_url"`
	ExpiresAt  time.Time `json:"expires_at"`
	IssuedAt   time.Time `json:"issued_at"`
	CSRFToken  string    `json:"csrf_token"`
}

type Server struct {
	RegistrationURL url.URL
	Store           Store
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

func (s *Server) HandleGetRegistrationFlow(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	flow, err := s.Store.GetRegistrationFlow(ctx, r.URL.Query().Get("flow"))
	if err != nil {
		return err
	}

	if time.Now().After(flow.ExpiresAt) {
		return errors.New("flow has expired")
	}

	buf, err := json.Marshal(flow)
	if err != nil {
		return fmt.Errorf("failed to marshal registration flow details: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) HandleSubmitRegistrationFlow(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	flow, err := s.Store.GetRegistrationFlow(ctx, r.URL.Query().Get("flow"))
	if err != nil {
		return err
	}

	if time.Now().After(flow.ExpiresAt) {
		return errors.New("flow has expired")
	}

	if flow.CSRFToken != r.PostFormValue("csrf_token") {
		return errors.New("csrf token is invalid")
	}

	http.Redirect(w, r, "/", http.StatusFound)

	return nil
}

package main

import (
	"github.com/lithdew/oauth2-go"
	"net/http"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	server := oauth2.Server{
		Store: oauth2.Store{
			Clients: map[string]oauth2.Client{
				"example": {
					AllowedScopes: map[string]struct{}{},
					AllowedRedirectURIs: map[string]struct{}{
						"http://localhost:8080/callback": {},
					},
				},
			},
			IssuedAuthorizationCodes: map[string]oauth2.AuthorizationCode{},
		},
	}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		check(r.Write(w))
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleAuthorizationRequest(r.Context(), w, r); err != nil {
			_, err = w.Write([]byte(err.Error()))
			check(err)
		}
	})

	check(http.ListenAndServe(":8080", http.DefaultServeMux))
}

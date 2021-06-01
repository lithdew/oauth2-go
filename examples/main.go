package main

import (
	"github.com/lithdew/oauth2-go"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"net/url"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func check2(_ interface{}, err error) { check(err) }

func pluck(a interface{}, err error) interface{} { check(err); return a }

var loginTemplate = template.Must(template.New("login").Parse(`
<form method="post" action="/login">
	<input type="hidden" name="challenge" value="{{ .Challenge }}" />
	<input type="email" id="email" name="email" placeholder="hello@example.com" />
	<input type="password" id="password" name="password" />

	<input type="checkbox" id="remember" name="remember" value="1" />
	<label for="remember">Remember me</label>

	<input type="submit" id="submit" name="submit" value="Login" />
</form>`,
))

var registerTemplate = template.Must(template.New("register").Parse(`
<form method="post" action="/register/submit">
	<input type="hidden" name="csrf_token" value="{{ .CSRFToken }}" />
	<input type="email" id="email" name="email" placeholder="hello@example.com" />
	<input type="password" id="password" name="password" />

	<input type="submit" id="submit" name="submit" value="Register" />
</form>`,
))

var verifyTemplate = template.Must(template.New("verify").Parse(`
You have {{.AttemptsLeft}} attempt(s) left. A new code will be generated if all attempts failed.
<form method="post" action="/verify/submit">
	<input type="hidden" name="csrf_token" value="{{ .CSRFToken }}" />
	<input type="text" id="code" name="code" placeholder="0000" />
	<input type="submit" id="submit" name="submit" value="Verify" />
	<input type="submit" id="refresh" name="refresh" value="Resend Verification Code" />
</form>
`))

func main() {
	server := oauth2.Server{
		RegistrationURL: *pluck(url.Parse("http://localhost:8080/register")).(*url.URL),
		VerificationURL: *pluck(url.Parse("http://localhost:8080/verify")).(*url.URL),
		Store: oauth2.Store{
			Clients: map[string]oauth2.Client{
				"example": {
					ID:            "example",
					Public:        false,
					Secret:        string(pluck(bcrypt.GenerateFromPassword([]byte("foobar"), bcrypt.DefaultCost)).([]byte)),
					AllowedScopes: map[string]struct{}{},
					AllowedRedirectURIs: map[string]struct{}{
						"http://localhost:8080/oauth2/callback": {},
					},
				},
			},

			IssuedAuthorizationCodes: map[string]oauth2.AuthorizationCode{},
			IssuedAccessTokens:       map[string]oauth2.AccessToken{},

			VerificationFlows: map[string]oauth2.VerificationFlow{},
			RegistrationFlows: map[string]oauth2.RegistrationFlow{},

			Identities:          map[string]oauth2.Identity{},
			VerifiableAddresses: map[string]oauth2.VerifiableAddress{},
		},
	}

	http.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) { check(r.Write(w)) })

	http.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleAuthorizationRequest(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleAccessTokenRequest(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/oauth2/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if err := loginTemplate.Execute(w, struct{ Challenge string }{Challenge: "todo"}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		check2(w.Write([]byte("Hello world.")))
	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("flow")
		if id == "" {
			if err := server.HandleNewRegistrationFlow(r.Context(), w, r); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			return
		}

		flow, err := server.Store.GetRegistrationFlow(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		if err := registerTemplate.Execute(w, flow); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/register/submit", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleSubmitRegistrationFlow(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("flow")
		if id == "" {
			http.Error(w, "verification flow id must be specified", http.StatusBadRequest)
			return
		}

		flow, err := server.Store.GetVerificationFlow(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		address, err := server.Store.GetVerifiableAddress(r.Context(), flow.AddressID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if address.Verified == oauth2.VerifiableAddressStatusCompleted {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		if err := verifyTemplate.Execute(w, flow); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/verify/submit", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleSubmitVerificationFlow(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	check(http.ListenAndServe(":8080", http.DefaultServeMux))
}

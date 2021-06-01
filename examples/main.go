package main

import (
	"github.com/go-chi/chi"
	"github.com/justinas/nosurf"
	"github.com/lithdew/oauth2-go"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func check2(_ interface{}, err error) { check(err) }

func pluck(a interface{}, err error) interface{} { check(err); return a }

var loginTemplate = template.Must(template.New("login").Parse(`
<form method="post" action="/login/submit">
	<input type="hidden" name="csrf_token" value="{{ .csrf_token }}" />
	<input type="email" id="email" name="email" placeholder="hello@example.com" />
	<input type="password" id="password" name="password" />

	<input type="checkbox" id="remember" name="remember" value="1" />
	<label for="remember">Remember me</label>

	<input type="submit" id="submit" name="submit" value="Login" />
</form>`,
))

var registerTemplate = template.Must(template.New("register").Parse(`
<form method="post" action="/register/submit">
	<input type="hidden" name="csrf_token" value="{{ .csrf_token }}" />
	<input type="email" id="email" name="email" placeholder="hello@example.com" />
	<input type="password" id="password" name="password" />

	<input type="submit" id="submit" name="submit" value="Register" />
</form>`,
))

var verifyTemplate = template.Must(template.New("verify").Parse(`
You have {{ .attempts_left }} attempt(s) left. A new code will be generated if all attempts failed.
<form method="post" action="/verify/submit">
	<input type="hidden" name="csrf_token" value="{{ .csrf_token }}" />
	<input type="text" id="code" name="code" placeholder="0000" />
	<input type="submit" id="submit" name="submit" value="Verify" />
	<input type="submit" id="refresh" name="refresh" value="Resend Verification Code" />
</form>
`))

func main() {
	server := oauth2.Server{
		LoginURL:        *pluck(url.Parse("http://localhost:8080/login")).(*url.URL),
		RegistrationURL: *pluck(url.Parse("http://localhost:8080/register")).(*url.URL),
		VerificationURL: *pluck(url.Parse("http://localhost:8080/verify")).(*url.URL),
		Store: oauth2.Store{
			Clients: map[string]oauth2.Client{
				"example": {
					ID:            "example",
					Public:        false,
					ThirdParty:    false,
					Secret:        string(pluck(bcrypt.GenerateFromPassword([]byte("foobar"), bcrypt.DefaultCost)).([]byte)),
					AllowedScopes: map[string]struct{}{},
					AllowedRedirectURIs: map[string]struct{}{
						"http://localhost:8080/oauth2/callback": {},
					},
				},
			},

			IssuedAuthorizationCodes: map[string]oauth2.AuthorizationCode{},
			IssuedAccessTokens:       map[string]oauth2.AccessToken{},

			LoginFlows:        map[string]oauth2.LoginFlow{},
			VerificationFlows: map[string]oauth2.VerificationFlow{},
			RegistrationFlows: map[string]oauth2.RegistrationFlow{},

			Identities:          map[string]oauth2.Identity{},
			VerifiableAddresses: map[string]oauth2.VerifiableAddress{},
		},
	}

	r := chi.NewRouter()

	csrf := func(h http.Handler) http.Handler {
		surfing := nosurf.New(h)
		surfing.SetBaseCookie(http.Cookie{
			Path:     "/",
			HttpOnly: true,
			MaxAge:   nosurf.MaxAge,
			//Secure:   true,
			//SameSite: http.SameSiteLaxMode,
		})
		return surfing
	}

	r.Get("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) { check(r.Write(w)) })

	r.Get("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleAuthorizationRequest(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	r.Post("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleAuthorizationRequest(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	r.Post("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleAccessTokenRequest(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) { check2(w.Write([]byte("Hello world."))) })

	r.With(csrf).Get("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("flow") == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		params := map[string]string{"csrf_token": nosurf.Token(r)}

		w.Header().Set("Content-Type", "text/html")
		if err := loginTemplate.Execute(w, params); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	r.With(csrf).Post("/login/submit", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleSubmitLoginFlow(r.Context(), w, r); err != nil {
			referrer, parseErr := url.Parse(r.Referer())
			if parseErr != nil {
				http.Error(w, parseErr.Error(), http.StatusBadRequest)
				return
			}
			query := referrer.Query()
			query.Set("error", err.Error())
			referrer.RawQuery = query.Encode()
			http.Redirect(w, r, referrer.String(), http.StatusFound)
			return
		}
	})

	r.With(csrf).Get("/register", func(w http.ResponseWriter, r *http.Request) {
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

		if time.Now().After(flow.ExpiresAt) {
			http.Redirect(w, r, server.RegistrationURL.String(), http.StatusFound)
			return
		}

		params := map[string]string{"csrf_token": nosurf.Token(r)}

		w.Header().Set("Content-Type", "text/html")
		if err := registerTemplate.Execute(w, params); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	r.With(csrf).Post("/register/submit", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleSubmitRegistrationFlow(r.Context(), w, r); err != nil {
			referrer, parseErr := url.Parse(r.Referer())
			if parseErr != nil {
				http.Error(w, parseErr.Error(), http.StatusBadRequest)
				return
			}
			query := referrer.Query()
			query.Set("error", err.Error())
			referrer.RawQuery = query.Encode()
			http.Redirect(w, r, referrer.String(), http.StatusFound)
			return
		}
	})

	r.With(csrf).Get("/verify", func(w http.ResponseWriter, r *http.Request) {
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

		params := map[string]string{
			"csrf_token":    nosurf.Token(r),
			"attempts_left": strconv.FormatUint(uint64(flow.AttemptsLeft), 10),
		}

		w.Header().Set("Content-Type", "text/html")
		if err := verifyTemplate.Execute(w, params); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	r.With(csrf).Post("/verify/submit", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleSubmitVerificationFlow(r.Context(), w, r); err != nil {
			referrer, parseErr := url.Parse(r.Referer())
			if parseErr != nil {
				http.Error(w, parseErr.Error(), http.StatusBadRequest)
				return
			}
			query := referrer.Query()
			query.Set("error", err.Error())
			referrer.RawQuery = query.Encode()
			http.Redirect(w, r, referrer.String(), http.StatusFound)
			return
		}
	})

	check(http.ListenAndServe(":8080", r))
}

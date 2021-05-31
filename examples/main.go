package main

import (
	"github.com/lithdew/oauth2-go"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var loginTemplate = template.Must(template.New("login").Parse(`
<form method="post" action="/login">
	<input type="hidden" name="challenge" value="{{ .Challenge }}" />
	<input type="text" id="username" name="username" placeholder="kenta" />
	<input type="password" id="password" name="password" />

	<input type="checkbox" id="remember" name="remember" value="1" />
	<label for="remember">Remember me</label>

	<input type="submit" id="submit" name="submit" value="Login" />
</form>

<script type="text/javascript">
</script>`,
))

func main() {
	secret, err := bcrypt.GenerateFromPassword([]byte("foobar"), bcrypt.DefaultCost)
	check(err)

	server := oauth2.Server{
		Store: oauth2.Store{
			Clients: map[string]oauth2.Client{
				"example": {
					ID:            "example",
					Public:        false,
					Secret:        string(secret),
					AllowedScopes: map[string]struct{}{},
					AllowedRedirectURIs: map[string]struct{}{
						"http://localhost:8080/callback": {},
					},
				},
			},
			IssuedAuthorizationCodes: map[string]oauth2.AuthorizationCode{},
			IssuedAccessTokens:       map[string]oauth2.AccessToken{},
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

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := server.HandleAccessTokenRequest(r.Context(), w, r); err != nil {
			_, err = w.Write([]byte(err.Error()))
			check(err)
		}
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		check(loginTemplate.Execute(w, struct{ Challenge string }{Challenge: "todo"}))
	})

	check(http.ListenAndServe(":8080", http.DefaultServeMux))
}

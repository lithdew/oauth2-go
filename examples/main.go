package main

import (
	"github.com/goccy/go-json"
	"github.com/lithdew/oauth2-go"
	"github.com/lithdew/oauth2-go/auth"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io/ioutil"
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
	<input type="text" id="username" name="username" placeholder="kenta" />
	<input type="password" id="password" name="password" />

	<input type="checkbox" id="remember" name="remember" value="1" />
	<label for="remember">Remember me</label>

	<input type="submit" id="submit" name="submit" value="Login" />
</form>

<script type="text/javascript">
</script>`,
))

var registerTemplate = template.Must(template.New("register").Parse(`
<form method="post" action="/auth/register/submit?flow={{ .ID }}">
	<input type="hidden" name="csrf_token" value="{{ .CSRFToken }}" />
	<input type="text" id="username" name="username" placeholder="kenta" />
	<input type="password" id="password" name="password" />

	<input type="submit" id="submit" name="submit" value="Register" />
</form>

<script type="text/javascript">
</script>`,
))

func main() {
	authorization := oauth2.Server{
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
		},
	}

	authentication := auth.Server{
		RegistrationURL: *pluck(url.Parse("http://localhost:8080/register")).(*url.URL),
		Store: auth.Store{
			RegistrationFlows: map[string]auth.RegistrationFlow{},
		},
	}

	http.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) { check(r.Write(w)) })

	http.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		if err := authorization.HandleAuthorizationRequest(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := authorization.HandleAccessTokenRequest(r.Context(), w, r); err != nil {
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
			http.Redirect(w, r, "/auth/register/browser", http.StatusFound)
			return
		}

		res, err := http.Get("http://localhost:8080/auth/register?flow=" + id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var flow auth.RegistrationFlow
		if err := json.Unmarshal(body, &flow); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		if err := registerTemplate.Execute(w, flow); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/auth/register/browser", func(w http.ResponseWriter, r *http.Request) {
		if err := authentication.HandleNewRegistrationFlow(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/auth/register", func(w http.ResponseWriter, r *http.Request) {
		if err := authentication.HandleGetRegistrationFlow(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/auth/register/submit", func(w http.ResponseWriter, r *http.Request) {
		if err := authentication.HandleSubmitRegistrationFlow(r.Context(), w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	check(http.ListenAndServe(":8080", http.DefaultServeMux))
}

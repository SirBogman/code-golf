package routes

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/code-golf/code-golf/session"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var config = oauth2.Config{
	ClientID:     "7f6709819023e9215205",
	ClientSecret: os.Getenv("CLIENT_SECRET"),
	Endpoint:     github.Endpoint,
}

// /callback/{beta,dev} exist because GitHub doesn't support multiple URLs.

// CallbackBeta serves GET /callback/beta
func CallbackBeta(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://beta.code.golf/callback?"+r.URL.RawQuery, http.StatusSeeOther)
}

// CallbackDev serves GET /callback/dev
func CallbackDev(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://localhost/callback?"+r.URL.RawQuery, http.StatusSeeOther)
}

// Callback serves GET /callback
func Callback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("code") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := config.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequestWithContext(
		r.Context(), "GET", "https://api.github.com/user", nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("Authorization", "Bearer "+token.AccessToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	var user struct {
		ID    int
		Login string
	}

	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		panic(err)
	}

	cookie := http.Cookie{
		HttpOnly: true,
		Name:     "__Host-session",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}

	if err := session.Database(r).QueryRow(
		`WITH golfer AS (
		    INSERT INTO users (id, login) VALUES ($1, $2)
		    ON CONFLICT (id) DO UPDATE SET login = excluded.login
		      RETURNING id
		) INSERT INTO sessions (user_id) SELECT * FROM golfer RETURNING id`,
		user.ID, user.Login,
	).Scan(&cookie.Value); err != nil {
		panic(err)
	}

	http.SetCookie(w, &cookie)

	uri := r.FormValue("redirect_uri")
	if uri == "" {
		uri = "/"
	}

	http.Redirect(w, r, uri, http.StatusSeeOther)
}

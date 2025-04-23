package powa

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func NewCookieStore(key string) *sessions.CookieStore {
	store := sessions.NewCookieStore([]byte(key))
	store.Options.HttpOnly = true
	store.Options.Secure = true
	store.Options.SameSite = http.SameSiteLaxMode
	store.MaxAge(0)
	return store
}

func New(mountOn string, opts *ServerOptions) (*Server, error) {
	mux := http.NewServeMux()
	googleAuth, err := NewGoogleAuthProvider(context.Background())
	if err != nil {
		return nil, err
	}

	callbackURL := url.URL{
		Scheme: "https",
		Host:   opts.VirtualHost,
		Path:   path.Join(mountOn, "/callback"),
	}

	conf := &oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		RedirectURL:  callbackURL.String(),
		Endpoint:     googleAuth.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}
	server := &Server{
		mux:            mux,
		a:              NewAuthenticator(conf, googleAuth),
		store:          opts.CookieStore,
		vhost:          opts.VirtualHost,
		mountOn:        mountOn,
		title:          opts.Title,
		allowedDomains: opts.AllowedDomains,
	}
	server.init()

	mux.HandleFunc(path.Join(mountOn, "/start"), server.startAuthHandler)
	mux.HandleFunc(path.Join(mountOn, "/callback"), server.callbackAuthHandler)
	mux.HandleFunc(path.Join(mountOn, "/verify"), server.verifyAuthHandler)
	mux.HandleFunc(path.Join(mountOn, "/sign_in"), server.signInHandler)
	mux.HandleFunc(path.Join(mountOn, "/unauthorized"), server.unauthorizedHandler)

	if server.store == nil {
		return nil, fmt.Errorf("Cookie store is not set")
	}

	return server, nil
}

func (s *Server) AuthorizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		loginSession := ExtractSession(req, s.store)
		if loginSession.Email == "" {
			// not logged in
			session, err := s.store.New(req, gateSessionName)
			if err != nil {
				log.Println("failed to create gate session:", err.Error())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			session.Options.SameSite = http.SameSiteNoneMode
			session.Values["path"] = req.URL.Path
			session.Save(req, w)
			http.Redirect(w, req, path.Join(s.mountOn, "/sign_in"), http.StatusFound)
			return
		} else {
			emailParts := strings.SplitN(loginSession.Email, "@", 2) // ユーザ名に@が使われるパターンは一旦無視
			if !slices.Contains(s.allowedDomains, emailParts[1]) {
				// unauthorized
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, req)
	})
}

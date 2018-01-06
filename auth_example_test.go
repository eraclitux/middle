package middle_test

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/eraclitux/middle"
)

type store struct {
	hash     []byte
	username string
}

func (s *store) Verify(u, p string) bool {
	if s.username != u {
		return false
	}
	if err := bcrypt.CompareHashAndPassword(s.hash, []byte(p)); err != nil {
		return false
	}
	return true
}

func makeAuthorizer(username, passwd string) middle.Authorizer {
	// Never store clear text password!
	h, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return &store{hash: h, username: username}
}

func ExampleAuth() {
	authorizer := makeAuthorizer("admin", "secret")
	http.HandleFunc("/secured", middle.Auth(authorizer, http.HandlerFunc(securedHandler)))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func securedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Secured info...")
}

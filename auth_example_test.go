package middle_test

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/eraclitux/middle"
)

type store struct {
	H []byte
}

func (s *store) GetHash(u string) ([]byte, error) {
	return s.H, nil
}

func createHasher(p string) middle.Hasher {
	h, _ := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return &store{H: h}
}

func ExampleMustAuth() {
	h := createHasher("secret")
	http.HandleFunc("/secured", middle.MustAuth("my-app-id", h, securedHandler))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func securedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Secured info...")
}

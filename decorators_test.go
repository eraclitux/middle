// Copyright (c) 2015 Andrea Masi. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE.txt file.

package middle

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type store struct {
	H []byte
}

func (s *store) GetHash(u string) ([]byte, error) {
	return s.H, nil
}

func createHasher(p string) Hasher {
	h, _ := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return &store{H: h}
}

func TestWithCORS(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello world")
	}
	h := WithCORS(handler)
	testServer := httptest.NewServer(http.HandlerFunc(h))
	defer testServer.Close()
	res, err := http.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := res.Header["Access-Control-Allow-Origin"]; ok {
		if v[0] != "*" {
			t.Fatal("invalid header")
		}
	} else {
		t.Fatal("CORS header not present")
	}
}

func TestMustAuth(t *testing.T) {
	goodPasswd := "XXXYYYzzz"
	authCases := []struct {
		user         string
		passwd       string
		expectedCode int
	}{
		{"pippo", goodPasswd, 200},
		{"pippo", "xxxyyyZZZ", 401},
		{"carl", "", 401},
	}
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(authCookieName)
		if err == nil && cookie != nil {
			http.Error(w, "no cookie found :(", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "you are authenticated...")
	})
	h := MustAuth(createHasher(goodPasswd), innerHandler)
	testServer := httptest.NewServer(h)
	defer testServer.Close()
	for i, r := range authCases {
		req, err := http.NewRequest("GET", testServer.URL, nil)
		if err != nil {
			t.Error(err)
		}
		req.SetBasicAuth(r.user, r.passwd)
		c := http.Client{}
		res, err := c.Do(req)
		if err != nil {
			t.Error(err)
		}
		defer res.Body.Close()
		message, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Error(err)
		}
		if res.StatusCode != r.expectedCode {
			t.Error("expected:", r.expectedCode, "received:", res.Status, "body:", string(message))
			t.Logf("case %d: %+v", i, r)
		}
	}
}

func TestRandomString(t *testing.T) {
	a := randomString(32)
	b := randomString(32)
	if a == b {
		t.Fatal("not random!")
		t.Log("random strings:", a, b)
	}
}

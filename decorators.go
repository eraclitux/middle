// Copyright (c) 2015 Andrea Masi. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE.txt file.

// Package middle exposes functions useful
// building http services.
package middle

import (
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	authCookieName = "session-id"
)

// FIXME drop sessions every x time or memory leak here.
var sessions map[string]struct{} = make(map[string]struct{})

var sessionsMut sync.RWMutex

// Hasher define a way to generalize
// credentials retrieving from different
// backends.
// MUST be concurrency safe.
type Hasher interface {
	// GetHash retrieves hashed password from
	// backend for user u.
	// It returns error if user is not found.
	GetHash(u string) ([]byte, error)
}

// WithCORS adds necessary headers to response
// to permit GET/POST CORS requests.
func WithCORS(fn http.HandlerFunc) http.HandlerFunc {
	// BUG(eraclitux) fully implement CORS.
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fn(w, r)
	}
}

// WithLog calls Println on logger
// with following arguments:
//
// <http method> <remote addr> <requested url>
//
// If X-Real-IP is found in headers it is used as <remote addr>
// with (X-Real-IP) added.
func WithLog(logger *log.Logger, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteAddr := r.Header.Get("X-Real-IP")
		if remoteAddr == "" {
			remoteAddr = r.RemoteAddr
		} else {
			// FIXME write a benchmark to check if is worth string concatenation
			// optimization using []byte.
			remoteAddr += " (X-Real-IP)"
		}
		logger.Println(r.Method, remoteAddr, r.URL)
		fn(w, r)
	}
}

// Auth checks if request is authenticated with basic auth verifying
// that its cookie is present in registered sessions.
// If request if from browser it will prompt for credentials
// with no valid session.
//
// BUG(eraclitux) session storage leaks.
func Auth(hasher Hasher, next http.Handler) http.HandlerFunc {
	// Heavily inspired by:
	// https://github.com/syncthing/syncthing/blob/161326c5489d000972a6846564f0ce12779bd8f2/cmd/syncthing/gui_auth.go
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(authCookieName)
		if err == nil && cookie != nil {
			// FIXME use RWMutex
			sessionsMut.Lock()
			_, ok := sessions[cookie.Value]
			sessionsMut.Unlock()
			if ok {
				next.ServeHTTP(w, r)
				return
			}
		}
		error := func() {
			// Mitigate risk of timing attacks.
			// https://en.wikipedia.org/wiki/Timing_attack
			// FIXME use crypto/rand
			time.Sleep(time.Duration(rand.Intn(100)+100) * time.Millisecond)
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
		username, passwd, ok := r.BasicAuth()
		if !ok {
			error()
			return
		}
		hash, err := hasher.GetHash(username)
		if err != nil {
			error()
			return
		}
		// TODO abstract hash verification putting
		// this into Hasher (renaming this interface).
		if err := bcrypt.CompareHashAndPassword(hash, []byte(passwd)); err != nil {
			error()
			return
		}
		sessionid := randomString(32)
		sessionsMut.Lock()
		sessions[sessionid] = struct{}{}
		sessionsMut.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:   authCookieName,
			Value:  sessionid,
			MaxAge: 0,
		})
		next.ServeHTTP(w, r)
	}
}

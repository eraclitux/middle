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
)

const (
	authCookieName = "session-id"
)

// FIXME drop sessions every x time or memory leak here.
var sessions map[string]struct{} = make(map[string]struct{})

var sessionsMut sync.RWMutex

// Authorizer models credentials verification
// to permit different backends and hash algorithms.
// Implementation MUST be concurrency safe.
type Authorizer interface {
	// Verify uses its backend to verify password
	// for a given username.
	Verify(user, passw string) bool
}

// CORS adds necessary headers to response
// to permit GET/POST CORS requests.
func CORS(next http.Handler) http.HandlerFunc {
	// BUG(eraclitux) fully implement CORS.
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	}
}

// Log calls Println on logger
// with following arguments:
//
// <http method> <remote addr> <requested url>
//
// If X-Real-IP is found in headers it is used as <remote addr>
// with (X-Real-IP) added.
func Log(logger *log.Logger, next http.Handler) http.HandlerFunc {
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
		next.ServeHTTP(w, r)
	}
}

// Auth checks if request is authenticated with basic auth verifying
// that its cookie is present in registered sessions.
// If request if from browser it will prompt for credentials
// with no valid session.
//
// BUG(eraclitux) session storage leaks.
func Auth(authorizer Authorizer, next http.Handler) http.HandlerFunc {
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
		if !authorizer.Verify(username, passwd) {
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

// Package httph esposes helper functions usefull
// when dealing with net/http.
package httph

import (
	"net/http"

	"gopkg.in/mgo.v2"
)

const (
	// MongoSession is used to access shared MongoDb session
	// in SharedData.
	MongoSession = "mongo-session"
)

// SharedData is a threadsafe container that let
// share data between dirrent http handlers.
var SharedData HTTPSharer

// WithCORS is a decorator function that adds relevant headers to response
// to permit CORS requests.
func WithCORS(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fn(w, r)
	}
}

// WithSharedData is a decorator function that initializes SharedData
// for the given http.Request freeing memory when possible.
func WithSharedData(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		SharedData.init(r)
		defer SharedData.drop(r)
		fn(w, r)
	}
}

// WithMongo is a decorator function that let passed HandlerFunc
// to use a session to MongoDB.
func WithMongo(session *mgo.Session, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := session.Copy()
		defer s.Close()
		k := MongoSession
		SharedData.Insert(r, k, s)
		defer SharedData.Delete(r, k)
		fn(w, r)
	}
}

func init() {
	SharedData = newHTTPSharer()
}

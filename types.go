package httph

import (
	"errors"
	"net/http"
	"sync"
)

type httpVars map[*http.Request]map[string]interface{}

var httpVarsLock sync.RWMutex

// HTTPSharer is a thread safe way to share data
// between net/http handlers.
type HTTPSharer interface {
	Insert(r *http.Request, k string, v interface{})
	Get(r *http.Request, k string) (interface{}, bool)
	Delete(r *http.Request, k string) error
	init(r *http.Request)
	drop(r *http.Request)
}

func (m httpVars) init(r *http.Request) {
	httpVarsLock.Lock()
	defer httpVarsLock.Unlock()
	m[r] = map[string]interface{}{}
}

func (m httpVars) Insert(r *http.Request, k string, v interface{}) {
	httpVarsLock.Lock()
	defer httpVarsLock.Unlock()
	if _, ok := m[r]; !ok {
		panic("cannot find *http.Request in HTTPRequestSetter, use Init() and defer Drop()")
	}
	m[r][k] = v
}

func (m httpVars) Get(r *http.Request, k string) (interface{}, bool) {
	httpVarsLock.RLock()
	defer httpVarsLock.RUnlock()
	if _, ok := m[r]; !ok {
		return nil, false
	}
	v, ok := m[r][k]
	if !ok {
		return nil, false
	}
	return v, true
}

func (m httpVars) Delete(r *http.Request, k string) error {
	httpVarsLock.Lock()
	defer httpVarsLock.Unlock()
	n, found := m[r]
	if !found {
		m[r] = map[string]interface{}{}
		return errors.New("request key not found")
	}
	delete(n, k)
	return nil
}
func (m httpVars) drop(r *http.Request) {
	httpVarsLock.Lock()
	defer httpVarsLock.Unlock()
	delete(m, r)
}

// newHTTPSharer returns a thread safe type for sharing data
// between net/http handlers.
func newHTTPSharer() HTTPSharer {
	m := make(httpVars)
	return m
}

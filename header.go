package middle

import "net/http"

// HeaderJSON sets http header for a json response.
func HeaderJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
}

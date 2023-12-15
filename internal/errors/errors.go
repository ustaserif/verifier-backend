package errors

import "net/http"

// RequestErrorHandlerFunc is a Request Error Handler that can be injected in oapi-codegen to handler errors in requests
func RequestErrorHandlerFunc(w http.ResponseWriter, _ *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusBadRequest)
}

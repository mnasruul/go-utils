package http_resps

import (
	"encoding/json"
	"github.com/mnasruul/go-utils/rest_errors"
	"net/http"
)

func RespondJson(w http.ResponseWriter, statusCode int, body interface{}){
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(body)
}

func RespondError(w http.ResponseWriter, err rest_errors.RestErr) {
	RespondJson(w, err.Status(), err)
}
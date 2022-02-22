package util

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"agola.io/agola/internal/errors"
)

func HTTPResponse(w http.ResponseWriter, code int, res interface{}) error {
	w.Header().Set("Content-Type", "application/json")

	if res != nil {
		resj, err := json.Marshal(res)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return errors.WithStack(err)
		}
		w.WriteHeader(code)
		_, err = w.Write(resj)
		return errors.WithStack(err)
	}

	w.WriteHeader(code)
	return nil
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func ErrorResponseFromError(err error) *ErrorResponse {
	if err == nil {
		return nil
	}

	var derr *APIError
	if errors.As(err, &derr) {
		return &ErrorResponse{Code: string(derr.Code), Message: derr.Message}
	}

	// on generic error return an error response without any code
	return &ErrorResponse{}
}

func HTTPError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}

	response := ErrorResponseFromError(err)
	resj, merr := json.Marshal(response)
	if merr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}

	code := http.StatusInternalServerError

	var derr *APIError
	if errors.As(err, &derr) {
		switch derr.Kind {
		case ErrBadRequest:
			code = http.StatusBadRequest
		case ErrNotExist:
			code = http.StatusNotFound
		case ErrForbidden:
			code = http.StatusForbidden
		case ErrUnauthorized:
			code = http.StatusUnauthorized
		case ErrInternal:
			code = http.StatusInternalServerError
		}
	}

	w.WriteHeader(code)
	_, _ = w.Write(resj)

	return true
}

func ErrFromRemote(resp *http.Response) error {
	if resp == nil {
		return nil
	}
	if resp.StatusCode/100 == 2 {
		return nil
	}

	response := &ErrorResponse{}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.WithStack(err)
	}

	// Re-populate error response body so it can be parsed by the caller if needed
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(data))

	if err := json.Unmarshal(data, &response); err != nil {
		return errors.Errorf("unknown api error (status: %d)", resp.StatusCode)
	}

	kind := ErrInternal
	switch resp.StatusCode {
	case http.StatusBadRequest:
		kind = ErrBadRequest
	case http.StatusNotFound:
		kind = ErrNotExist
	case http.StatusForbidden:
		kind = ErrForbidden
	case http.StatusUnauthorized:
		kind = ErrUnauthorized
	case http.StatusInternalServerError:
		kind = ErrInternal
	}

	return NewRemoteError(kind, response.Code, response.Message)
}

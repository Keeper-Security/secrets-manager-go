package core

import (
	"errors"
	"fmt"
)

// ErrThrottled is returned (wrapped) by PostQuery when the Keeper backend throttles requests
// (HTTP 403 {"error":"throttled"}) and the SDK has exhausted its automatic retries
// (maxThrottleRetries). Callers can detect it with errors.Is(err, ErrThrottled).
var ErrThrottled = errors.New("request throttled by Keeper backend: retries exhausted")

// KeeperHTTPError is returned by PostQuery (and thus GetSecrets, GetFolders, etc.)
// whenever the Keeper API responds with a non-200 status code.
//
// Callers that need to branch on the HTTP status code should use errors.As:
//
//	var khe *core.KeeperHTTPError
//	if errors.As(err, &khe) {
//	    switch khe.StatusCode {
//	    case 401, 403:
//	        // handle auth failure
//	    case 429:
//	        // handle rate limit
//	    }
//	}
type KeeperHTTPError struct {
	// StatusCode is the HTTP status code returned by the server (e.g. 403, 502).
	StatusCode int
	// ResultCode is the machine-readable error code from the JSON envelope
	// (the "result_code" or "error" field). Empty when the body was not JSON.
	ResultCode string
	// Message is the human-readable explanation from the JSON envelope.
	// Empty when the body was not JSON.
	Message string
	// Body holds the raw response body when the server did not return a
	// parseable JSON error envelope. Nil for structured JSON errors.
	Body []byte
}

func (e *KeeperHTTPError) Error() string {
	if len(e.Body) > 0 && e.ResultCode == "" {
		return fmt.Sprintf("HTTPStatus=%d HTTPError: %s", e.StatusCode, string(e.Body))
	}
	return fmt.Sprintf("HTTPStatus=%d Error: %s, message=%s", e.StatusCode, e.ResultCode, e.Message)
}

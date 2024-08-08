package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}
	apiKey, err := GetAPIKey(headers)
	if apiKey != "" || err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected '', %v; got '%s', %v", ErrNoAuthHeaderIncluded, apiKey, err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Basic abc123")

	apiKey, err := GetAPIKey(headers)
	if apiKey != "" || err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected '', 'malformed authorization header'; got '%s', %v", apiKey, err)
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey myapikey123")

	apiKey, err := GetAPIKey(headers)
	if apiKey != "myapikey123" || err != nil {
		t.Errorf("expected 'myapikey123', nil; got '%s', %v", apiKey, err)
	}
}

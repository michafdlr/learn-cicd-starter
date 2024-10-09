package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey2(t *testing.T) {
	tests := []struct {
		name        string
		headerInput http.Header
		expected    []struct {
			apiKey string
			err    error
		}
	}{
		{name: "no auth header", headerInput: http.Header{}, expected: []struct {
			apiKey string
			err    error
		}{{apiKey: "", err: ErrNoAuthHeaderIncluded}}},
		{name: "malformed auth header", headerInput: http.Header{"Authorization": []string{"ApiKey"}}, expected: []struct {
			apiKey string
			err    error
		}{{apiKey: "", err: errors.New("malformed authorization header")}}},
		{name: "correct auth header", headerInput: http.Header{"Authorization": []string{"ApiKey test"}}, expected: []struct {
			apiKey string
			err    error
		}{{apiKey: "test", err: nil}}},
	}

	for _, tc := range tests {
		apiKey, err := GetAPIKey(tc.headerInput)
		if apiKey != tc.expected[0].apiKey {
			t.Errorf("Test %s failed: expected %s, got %s", tc.name, tc.expected[0].apiKey, apiKey)
		}
		if err != nil && tc.expected[0].err == nil {
			t.Errorf("Test %s failed: expected no error, got %v", tc.name, err)
		}
	}
}

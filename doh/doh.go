package doh

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nicholasbergesen/dns/dns"
)

const (
	// Content types as defined in RFC 8484
	ContentTypeDNSMessage = "application/dns-message"
	DNSParamName          = "dns"
)

// Base64URLDecode decodes a base64url encoded string to bytes
// RFC 8484 requires base64url encoding (RFC 4648 Section 5)
func Base64URLDecode(encoded string) ([]byte, error) {
	// Pad string if necessary
	switch len(encoded) % 4 {
	case 2:
		encoded += "=="
	case 3:
		encoded += "="
	}

	// Replace base64url characters with base64 characters
	encoded = strings.ReplaceAll(encoded, "-", "+")
	encoded = strings.ReplaceAll(encoded, "_", "/")

	return base64.StdEncoding.DecodeString(encoded)
}

func Base64URLEncode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)

	// Replace base64 characters with base64url characters
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")

	// Remove padding
	encoded = strings.TrimRight(encoded, "=")

	return encoded
}

// DNS query is passed as base64url-encoded parameter
func HandleGETRequest(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	dnsParam := r.URL.Query().Get(DNSParamName)
	if dnsParam == "" {
		http.Error(w, "Missing dns parameter", http.StatusBadRequest)
		return nil, fmt.Errorf("missing dns parameter")
	}

	queryBytes, err := Base64URLDecode(dnsParam)
	if err != nil {
		http.Error(w, "Invalid dns parameter encoding", http.StatusBadRequest)
		return nil, fmt.Errorf("invalid dns parameter encoding: %v", err)
	}

	return queryBytes, nil
}

// DNS query is in the request body as binary data
func HandlePOSTRequest(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
		return nil, fmt.Errorf("invalid content type: %s", contentType)
	}

	queryBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}

	if len(queryBytes) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return nil, fmt.Errorf("empty request body")
	}

	return queryBytes, nil
}

func SendDNSResponse(w http.ResponseWriter, responseBytes []byte) {
	w.Header().Set("Content-Type", ContentTypeDNSMessage)
	w.Header().Set("Cache-Control", "max-age=300")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

func ValidateDNSQuery(queryBytes []byte) error {
	if len(queryBytes) < dns.HEADER_LENGTH {
		return fmt.Errorf("query too short: %d bytes, minimum %d bytes required", len(queryBytes), dns.HEADER_LENGTH)
	}

	header := dns.ParseHeader(queryBytes)

	if header.QR {
		return fmt.Errorf("received response instead of query")
	}

	if header.QDCount == 0 {
		return fmt.Errorf("query must have at least one question")
	}

	return nil
}

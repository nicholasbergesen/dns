package doh

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nicholasbergesen/dns/dns"
)

// Test base64url encoding/decoding
func TestBase64URLEncoding(t *testing.T) {
	testData := []byte("Hello, World!")
	
	// Encode
	encoded := Base64URLEncode(testData)
	
	// Decode
	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	if !bytes.Equal(testData, decoded) {
		t.Fatalf("Data mismatch: expected %v, got %v", testData, decoded)
	}
}

// Test base64url decoding with RFC 8484 example
func TestBase64URLDecodingRFC8484Example(t *testing.T) {
	// Example from RFC 8484: "q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	// This represents a DNS query for www.example.com
	encoded := "q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	
	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode RFC example: %v", err)
	}
	
	// Should be a valid DNS query
	if len(decoded) < dns.HEADER_LENGTH {
		t.Fatalf("Decoded data too short: %d bytes", len(decoded))
	}
	
	// Parse the header
	header := dns.ParseHeader(decoded)
	if header.QR {
		t.Fatalf("Expected query, got response")
	}
	
	if header.QDCount != 1 {
		t.Fatalf("Expected 1 question, got %d", header.QDCount)
	}
}

// Test GET request handling
func TestHandleGETRequest(t *testing.T) {
	// Create a simple DNS query for testing
	query := createTestDNSQuery()
	encoded := Base64URLEncode(query)
	
	// Create HTTP request
	req := httptest.NewRequest("GET", "/dns-query?dns="+url.QueryEscape(encoded), nil)
	w := httptest.NewRecorder()
	
	// Handle the request
	queryBytes, err := HandleGETRequest(w, req)
	if err != nil {
		t.Fatalf("Failed to handle GET request: %v", err)
	}
	
	// Validate the result
	if !bytes.Equal(query, queryBytes) {
		t.Fatalf("Query mismatch: expected %v, got %v", query, queryBytes)
	}
}

// Test GET request with missing parameter
func TestHandleGETRequestMissingParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/dns-query", nil)
	w := httptest.NewRecorder()
	
	_, err := HandleGETRequest(w, req)
	if err == nil {
		t.Fatal("Expected error for missing dns parameter")
	}
	
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d", w.Code)
	}
}

// Test POST request handling
func TestHandlePOSTRequest(t *testing.T) {
	query := createTestDNSQuery()
	
	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	w := httptest.NewRecorder()
	
	queryBytes, err := HandlePOSTRequest(w, req)
	if err != nil {
		t.Fatalf("Failed to handle POST request: %v", err)
	}
	
	if !bytes.Equal(query, queryBytes) {
		t.Fatalf("Query mismatch: expected %v, got %v", query, queryBytes)
	}
}

// Test POST request with wrong content type
func TestHandlePOSTRequestWrongContentType(t *testing.T) {
	query := createTestDNSQuery()
	
	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	_, err := HandlePOSTRequest(w, req)
	if err == nil {
		t.Fatal("Expected error for wrong content type")
	}
	
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("Expected status 415, got %d", w.Code)
	}
}

// Test DNS query validation
func TestValidateDNSQuery(t *testing.T) {
	// Valid query
	query := createTestDNSQuery()
	err := ValidateDNSQuery(query)
	if err != nil {
		t.Fatalf("Valid query failed validation: %v", err)
	}
	
	// Too short query
	shortQuery := []byte{0x00, 0x01}
	err = ValidateDNSQuery(shortQuery)
	if err == nil {
		t.Fatal("Expected error for short query")
	}
	
	// Response instead of query
	response := createTestDNSQuery()
	// Set QR bit to 1 (response)
	response[2] |= 0x80
	err = ValidateDNSQuery(response)
	if err == nil {
		t.Fatal("Expected error for response instead of query")
	}
}

// Test sending DNS response
func TestSendDNSResponse(t *testing.T) {
	response := createTestDNSQuery()
	
	w := httptest.NewRecorder()
	SendDNSResponse(w, response)
	
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}
	
	contentType := w.Header().Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		t.Fatalf("Expected content type %s, got %s", ContentTypeDNSMessage, contentType)
	}
	
	if !bytes.Equal(response, w.Body.Bytes()) {
		t.Fatal("Response body mismatch")
	}
}

// Helper function to create a simple DNS query for testing
func createTestDNSQuery() []byte {
	// Create a simple DNS query for "example.com" A record
	header := dns.Header{
		ID:      0x1234,
		QR:      false, // Query
		Opcode:  0,     // Standard query
		AA:      false,
		TC:      false,
		RD:      true, // Recursion desired
		RA:      false,
		Z:       0,
		RCODE:   0,
		QDCount: 1, // One question
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}
	
	question := dns.Question{
		QName:  "example.com",
		QType:  1, // A record
		QClass: 1, // IN (Internet)
	}
	
	query := header.ToBytes()
	query = append(query, question.ToBytes()...)
	
	return query
}
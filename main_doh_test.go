package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/nicholasbergesen/dns/dns"
	"github.com/nicholasbergesen/dns/doh"
)

// Test DOH GET request integration
func TestDOHGETIntegration(t *testing.T) {
	// Create a simple DNS query
	query := createSimpleDNSQuery()
	encoded := doh.Base64URLEncode(query)
	
	// Create HTTP client that accepts self-signed certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
	
	// Make GET request to DOH endpoint
	url := "https://localhost:8443/dns-query?dns=" + encoded
	resp, err := client.Get(url)
	if err != nil {
		t.Skipf("DOH server not running, skipping integration test: %v", err)
		return
	}
	defer resp.Body.Close()
	
	// Check response
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
	
	contentType := resp.Header.Get("Content-Type")
	if contentType != doh.ContentTypeDNSMessage {
		t.Fatalf("Expected content type %s, got %s", doh.ContentTypeDNSMessage, contentType)
	}
}

// Test DOH POST request integration
func TestDOHPOSTIntegration(t *testing.T) {
	// Create a simple DNS query
	query := createSimpleDNSQuery()
	
	// Create HTTP client that accepts self-signed certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
	
	// Make POST request to DOH endpoint
	req, err := http.NewRequest("POST", "https://localhost:8443/dns-query", bytes.NewReader(query))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", doh.ContentTypeDNSMessage)
	req.Header.Set("Accept", doh.ContentTypeDNSMessage)
	
	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("DOH server not running, skipping integration test: %v", err)
		return
	}
	defer resp.Body.Close()
	
	// Check response
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
	
	contentType := resp.Header.Get("Content-Type")
	if contentType != doh.ContentTypeDNSMessage {
		t.Fatalf("Expected content type %s, got %s", doh.ContentTypeDNSMessage, contentType)
	}
}

// Helper function to create a simple DNS query
func createSimpleDNSQuery() []byte {
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
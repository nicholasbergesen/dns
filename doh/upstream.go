package doh

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nicholasbergesen/dns/dns"
)

const (
	// Default DOH upstream servers
	DefaultDOHUpstream = "https://dns.google/dns-query"
	CloudflareDOH     = "https://cloudflare-dns.com/dns-query"
	
	// HTTP client timeout
	DefaultTimeout = 5 * time.Second
)

// DOHUpstream represents a DNS over HTTPS upstream resolver
type DOHUpstream struct {
	URL        string
	HTTPClient *http.Client
}

// NewDOHUpstream creates a new DOH upstream resolver
func NewDOHUpstream(url string) *DOHUpstream {
	return &DOHUpstream{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: DefaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

// QueryDOH sends a DNS query to the DOH upstream server using POST method
func (u *DOHUpstream) QueryDOH(queryBytes []byte) ([]byte, error) {
	// Create POST request with DNS query in body
	req, err := http.NewRequest("POST", u.URL, bytes.NewReader(queryBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	// Set required headers
	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	req.Header.Set("Accept", ContentTypeDNSMessage)
	req.Header.Set("User-Agent", "dns-server-doh/1.0")
	
	// Make the request
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream server returned status %d", resp.StatusCode)
	}
	
	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("unexpected content type from upstream: %s", contentType)
	}
	
	// Read response body
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	// Validate response
	if len(responseBytes) < dns.HEADER_LENGTH {
		return nil, fmt.Errorf("response too short: %d bytes", len(responseBytes))
	}
	
	return responseBytes, nil
}

// QueryDOHGET sends a DNS query to the DOH upstream server using GET method
func (u *DOHUpstream) QueryDOHGET(queryBytes []byte) ([]byte, error) {
	// Encode query as base64url
	encoded := Base64URLEncode(queryBytes)
	
	// Create GET request with DNS query as parameter
	req, err := http.NewRequest("GET", u.URL+"?"+DNSParamName+"="+encoded, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	// Set required headers
	req.Header.Set("Accept", ContentTypeDNSMessage)
	req.Header.Set("User-Agent", "dns-server-doh/1.0")
	
	// Make the request
	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream server returned status %d", resp.StatusCode)
	}
	
	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("unexpected content type from upstream: %s", contentType)
	}
	
	// Read response body
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	// Validate response
	if len(responseBytes) < dns.HEADER_LENGTH {
		return nil, fmt.Errorf("response too short: %d bytes", len(responseBytes))
	}
	
	return responseBytes, nil
}
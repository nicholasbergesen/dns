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
	DefaultDOHUpstream = "https://dns.google/dns-query"
	CloudflareDOH      = "https://cloudflare-dns.com/dns-query"
	DefaultTimeout     = 5 * time.Second
)

type DOHUpstream struct {
	URL        string
	HTTPClient *http.Client
}

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

func (u *DOHUpstream) QueryDOH(queryBytes []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", u.URL, bytes.NewReader(queryBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	req.Header.Set("Accept", ContentTypeDNSMessage)
	req.Header.Set("User-Agent", "dns-server-doh/1.0")

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream server returned status %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("unexpected content type from upstream: %s", contentType)
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if len(responseBytes) < dns.HEADER_LENGTH {
		return nil, fmt.Errorf("response too short: %d bytes", len(responseBytes))
	}

	return responseBytes, nil
}

func (u *DOHUpstream) QueryDOHGET(queryBytes []byte) ([]byte, error) {
	encoded := Base64URLEncode(queryBytes)

	req, err := http.NewRequest("GET", u.URL+"?"+DNSParamName+"="+encoded, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Accept", ContentTypeDNSMessage)
	req.Header.Set("User-Agent", "dns-server-doh/1.0")

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream server returned status %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("unexpected content type from upstream: %s", contentType)
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if len(responseBytes) < dns.HEADER_LENGTH {
		return nil, fmt.Errorf("response too short: %d bytes", len(responseBytes))
	}

	return responseBytes, nil
}

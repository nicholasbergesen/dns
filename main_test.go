package main

import (
	"strings"
	"testing"

	"github.com/nicholasbergesen/dns/dns"
)

// Opcode 8, not supported
func TestNoOpeCodeEight(t *testing.T) {
	message := dns.Message{}
	bytes := []byte("³í        srtbmsncom   ")
	message.Header = dns.ParseHeader(bytes)
	t.Logf("Bytes: %d", len(bytes))
	t.Logf("ID: %d", message.Header.ID)
	handleDNSRequest(nil, nil, bytes)
}

// Regular name no compression
func TestReadToZero(t *testing.T) {
	// 1 F 3 I S I 4 A R P A 0
	// 10 triling A's in array
	bytes := []byte([]uint8{0x01, 0x46, 0x03, 0x49, 0x53, 0x49, 0x04, 0x41, 0x52, 0x50, 0x41, 0x00, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41})
	offset := 0
	name := dns.ReadDomainName(bytes, &offset)
	t.Logf("Name: %s", name)
}

// Regular name with compression
func TestReadCompressedMessage(t *testing.T) {
	// 1 F 3 I S I 4 A R P A 0 3 F O O
	// 0xD4 is pointer to position 20 with 11 MSB bits to represent compression position
	// 0x41 are padding values to adjust the size of the array.
	// Real values are index 20-30 and 40-44 in the byte array.
	bytes := []byte([]uint8{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x01, 0x46, 0x03, 0x49, 0x53, 0x49, 0x04, 0x41, 0x52, 0x50, 0x41, 0x00, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x3, 0x46, 0x4F, 0x4F, 0xC0, 0x14})
	offset := 40
	name := dns.ReadDomainName(bytes, &offset)
	t.Logf("Name: %s", name)
}

// Z 2, not supported, should always be 0
func TestFailedRequest(t *testing.T) {
	message := dns.Message{}
	bytes := []byte("P        www netflixcom  A ")
	message.Header = dns.ParseHeader(bytes)
	t.Logf("Bytes: %d", len(bytes))
	t.Logf("ID: %d", message.Header.ID)
	handleDNSRequest(nil, nil, bytes)
}
// Test parsing of SVCB/HTTPS records to ensure they don't show corrupted characters
func TestSVCBRecordParsing(t *testing.T) {
	// Simulated SVCB record with binary RData that should not be parsed as domain name
	// This simulates the problematic record from the logs
	bytes := []byte{
		// Minimal DNS message with SVCB record
		0x00, 0x01, // ID
		0x80, 0x00, // Flags (response)
		0x00, 0x00, // QDCount
		0x00, 0x01, // ANCount
		0x00, 0x00, // NSCount  
		0x00, 0x00, // ARCount
		// Answer record starts here
		0x04, 0x5f, 0x64, 0x6e, 0x73, // "_dns"
		0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, // "resolver" 
		0x04, 0x61, 0x72, 0x70, 0x61, // "arpa"
		0x00, // end of name
		0x00, 0x40, // Type 64 (SVCB)
		0x00, 0x01, // Class IN
		0x00, 0x01, 0x51, 0x80, // TTL
		0x00, 0x16, // RDLength (22 bytes)
		// RData - binary data that should not be parsed as domain name
		0x00, 0x01, 0x02, 0x68, 0x32, 0x02, 0x68, 0x33,
		0x04, 0x2f, 0x64, 0x6e, 0x73, 0x2d, 0x71, 0x75,
		0x65, 0x72, 0x79, 0x7b, 0x3f, 0x64,
	}
	
	offset := 12 // Skip header
	record, err := dns.ParseResourceRecord(bytes, &offset)
	if err != nil {
		t.Fatalf("Failed to parse resource record: %v", err)
	}
	
	t.Logf("Record Name: %s", record.Name)
	t.Logf("Record Type: %s", dns.QTypeMap[record.Type])
	t.Logf("RData: %s", record.RDataUncompressed)
	
	// Verify that RData is displayed as hex instead of corrupted characters
	if record.Type == 64 { // SVCB
		if !strings.Contains(record.RDataUncompressed, "hex:") {
			t.Errorf("SVCB record should display RData as hex, got: %s", record.RDataUncompressed)
		}
		if strings.Contains(record.RDataUncompressed, "♥") || strings.Contains(record.RDataUncompressed, "♠") {
			t.Errorf("SVCB record contains corrupted characters: %s", record.RDataUncompressed)
		}
	}
}

func TestParseResourceRecordWithMalformedData(t *testing.T) {
	// Test with data that has insufficient bytes for RDLength
	malformedBytes := []byte{
		// Name: _dns.resolver.arpa.
		0x04, 0x5f, 0x64, 0x6e, 0x73, 0x08, 0x72, 0x65,
		0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x04, 0x61,
		0x72, 0x70, 0x61, 0x00,
		// Type: SVCB (64)
		0x00, 0x40,
		// Class: IN (1)
		0x00, 0x01,
		// TTL
		0x00, 0x01, 0x51, 0x80,
		// RDLength claiming 100 bytes but data is much shorter
		0x00, 0x64, // 100 bytes claimed
		// Only 5 bytes of actual data
		0x00, 0x01, 0x02, 0x68, 0x32,
	}
	
	offset := 0
	
	// This should now return an error instead of panicking
	record, err := dns.ParseResourceRecord(malformedBytes, &offset)
	if err == nil {
		t.Errorf("Expected error when parsing malformed data, but got none. Record: %+v", record)
	} else {
		t.Logf("ParseResourceRecord correctly returned error: %v", err)
	}
	
	// Test with insufficient data for fixed fields
	shortBytes := []byte{
		0x04, 0x74, 0x65, 0x73, 0x74, 0x00, // name "test"
		0x00, 0x01, // type
		// Missing class, TTL, and RDLength
	}
	
	offset = 0
	record, err = dns.ParseResourceRecord(shortBytes, &offset)
	if err == nil {
		t.Errorf("Expected error when parsing data with insufficient fixed fields, but got none. Record: %+v", record)
	} else {
		t.Logf("ParseResourceRecord correctly returned error for insufficient data: %v", err)
	}
}

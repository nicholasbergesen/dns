package dns

import (
	"testing"
)

// Opcode 8, not supported
func TestNoOpeCodeEight(t *testing.T) {
	message := Message{}
	bytes := []byte("³í        srtbmsncom   ")
	message.Header = ParseHeader(bytes)
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
	name := ReadDomainName(bytes, &offset)
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
	name := ReadDomainName(bytes, &offset)
	t.Logf("Name: %s", name)
}

// Z 2, not supported, should always be 0
func TestFailedRequest(t *testing.T) {
	message := Message{}
	bytes := []byte("P        www netflixcom  A ")
	message.Header = ParseHeader(bytes)
	t.Logf("Bytes: %d", len(bytes))
	t.Logf("ID: %d", message.Header.ID)
	handleDNSRequest(nil, nil, bytes)
}

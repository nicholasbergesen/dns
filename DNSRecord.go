package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type DNSResourceRecord struct {
	Name              string
	Type              uint16
	Class             uint16
	TTL               uint32
	CreationDate      time.Time
	RDLength          uint16
	RData             []byte
	RDataUncompressed string
}

func (r *DNSResourceRecord) ToBytes() []byte {
	data := []byte{}

	for _, part := range strings.Split(r.Name, ".") {
		if part == "" {
			continue
		}
		data = append(data, byte(len(part)))
		data = append(data, []byte(part)...)
	}
	data = append(data, 0)

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	ttlBytes := make([]byte, 4)
	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, r.Type)
	binary.BigEndian.PutUint16(classBytes, r.Class)
	binary.BigEndian.PutUint32(ttlBytes, r.TTL)
	binary.BigEndian.PutUint16(rdLengthBytes, r.RDLength)

	data = append(data, typeBytes...)
	data = append(data, classBytes...)
	data = append(data, ttlBytes...)
	data = append(data, rdLengthBytes...)
	data = append(data, r.RData...)

	return data
}

func ParseResourceRecord(data []byte, offset int) (DNSResourceRecord, int) {
	record := DNSResourceRecord{}

	record.Name, offset = readDomainName(data, offset)

	record.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	record.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	record.TTL = binary.BigEndian.Uint32(data[offset+4 : offset+8])
	record.CreationDate = time.Now().UTC()
	record.RDLength = binary.BigEndian.Uint16(data[offset+8 : offset+10])
	offset += 10
	record.RData = data[offset : offset+int(record.RDLength)]

	if QTypeMap[record.Type] == "A" {
		record.RDataUncompressed = byteArrayToString(record.RData)
		offset += int(record.RDLength)
	} else {
		record.RDataUncompressed, offset = readDomainName(data, offset)
	}

	return record, offset
}

// readDomainName reads a domain name from the byte slice with support for message compression
func readDomainName(data []byte, offset int) (string, int) {
	var nameParts []string
	if offset >= len(data) {
		fmt.Printf("OOPS! offset exceeded data Length, looks like there's a bug\n")
		return strings.Join(nameParts, "."), offset
	}

	length := int(data[offset]) //gets int 0-255 value of byte
	if length == 0 {
		offset++
		return strings.Join(nameParts, "."), offset
	}

	// Check for the compression pointer (first two bits are 1s)
	// Actual value will never be greater than 00111111, first 2 msb are used to indicate compression
	// By doing bitwise & with 0xC0 (11000000) we can check if the first two bits are 1s if the results is 11000000
	if length&0xC0 == 0xC0 {
		// Read the offset of the compressed name, value is the loation of of the byte array to continue reading from
		ptrOffset := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF) // 0x3FF (1100000000000000) removes first 2 bits from 16 bit biary number
		offset += 2                                                               //Move the main pointer forward after reading the compression poisition (2 bytes long)

		// Recursively read the domain name from the pointer offset
		compressedName, _ := readDomainName(data, ptrOffset)
		nameParts = append(nameParts, compressedName)
		return compressedName, offset
	}

	offset++
	nameParts = append(nameParts, string(data[offset:offset+length]))
	offset += length

	if (offset + 1) <= len(data) {
		nextName, nextOffset := readDomainName(data, offset)
		offset = nextOffset
		nameParts = append(nameParts, nextName)
	}

	return strings.Join(nameParts, "."), offset
}

func byteArrayToString(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	parts := make([]string, 4)
	for i := 0; i < len(data); i++ {
		parts[i] = strconv.Itoa(int(data[i]))
	}
	return strings.Join(parts, ".")
}

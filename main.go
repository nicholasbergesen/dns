package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Cache
var cache = make(map[string]DNSMessage, 10000)

type DNSMessage struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSResourceRecord
}

func (m *DNSMessage) ToBytes() []byte {
	bytes := m.Header.ToBytes()
	for _, question := range m.Questions {
		bytes = append(bytes, question.ToBytes()...)
	}
	for _, answer := range m.Answers {
		bytes = append(bytes, answer.ToBytes()...)
	}

	return bytes
}

func (m *DNSMessage) UpstreamBytes() []byte {
	bytes := m.Header.ToBytes()
	for _, question := range m.Questions {
		bytes = append(bytes, question.ToBytes()...)
	}

	return bytes
}

// DNSHeader represents the DNS packet header
type DNSHeader struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCODE   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

var RCodeMap = map[uint8]string{
	0:  "NoError",  // No error condition
	1:  "FormErr",  // Format error
	2:  "ServFail", // Server failure
	3:  "NXDomain", // Non-Existent Domain
	4:  "NotImp",   // Not Implemented
	5:  "Refused",  // Query refused
	6:  "YXDomain", // Name Exists when it should not
	7:  "YXRRSet",  // RR Set Exists when it should not
	8:  "NXRRSet",  // RR Set that should exist does not
	9:  "NotAuth",  // Server Not Authoritative for zone
	10: "NotZone",  // Name not contained in zone
	// 11-15 are reserved for future use
}

// DNSQuestion represents a question section in the DNS message
type DNSQuestion struct {
	QName       string
	QNameLength int
	QType       uint16
	QClass      uint16
}

var QRMap = map[bool]string{
	true:  "Response",
	false: "Request",
}

var blocked = map[string]bool{
	"apple.com":      true,
	"www.apple.com":  true,
	"www.apple.com.": true,
}

var QTypeMap = map[uint16]string{
	1:   "A",
	2:   "NS",
	3:   "MD", // Obsolete
	4:   "MF", // Obsolete
	5:   "CNAME",
	6:   "SOA",
	7:   "MB",   // Experimental
	8:   "MG",   // Experimental
	9:   "MR",   // Experimental
	10:  "NULL", // Experimental
	11:  "WKS",
	12:  "PTR",
	13:  "HINFO",
	14:  "MINFO",
	15:  "MX",
	16:  "TXT",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA", // Obsolete
	255: "ANY",
}

var QClassMap = map[uint16]string{
	1:   "IN",  // Internet
	2:   "CS",  // CSNET (obsolete)
	3:   "CH",  // CHAOS
	4:   "HS",  // Hesiod
	255: "ANY", // Any class
}

// DNSResourceRecord represents a resource record in the DNS message
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

// ParseHeader parses a DNS header from a byte slice
func ParseHeader(data []byte) DNSHeader {
	header := DNSHeader{}
	header.ID = binary.BigEndian.Uint16(data[0:2])

	flags := binary.BigEndian.Uint16(data[2:4])
	header.QR = (flags & 0x8000) != 0
	header.Opcode = uint8((flags >> 11) & 0x0F)
	header.AA = (flags & 0x0400) != 0
	header.TC = (flags & 0x0200) != 0
	header.RD = (flags & 0x0100) != 0
	header.RA = (flags & 0x0080) != 0
	header.Z = uint8((flags >> 4) & 0x7)
	header.RCODE = uint8(flags & 0x0F)

	header.QDCount = binary.BigEndian.Uint16(data[4:6])
	header.ANCount = binary.BigEndian.Uint16(data[6:8])
	header.NSCount = binary.BigEndian.Uint16(data[8:10])
	header.ARCount = binary.BigEndian.Uint16(data[10:12])

	return header
}

// ToBytes converts the DNSHeader struct back into a byte slice
func (h *DNSHeader) ToBytes() []byte {
	data := make([]byte, HEADER_LENGTH)

	binary.BigEndian.PutUint16(data[0:2], h.ID)

	var flags uint16
	if h.QR {
		flags |= 0x8000
	}
	flags |= (uint16(h.Opcode) & 0x0F) << 11
	if h.AA {
		flags |= 0x0400
	}
	if h.TC {
		flags |= 0x0200
	}
	if h.RD {
		flags |= 0x0100
	}
	if h.RA {
		flags |= 0x0080
	}
	flags |= (uint16(h.Z) & 0x7) << 4
	flags |= uint16(h.RCODE) & 0x0F

	binary.BigEndian.PutUint16(data[2:4], flags)
	binary.BigEndian.PutUint16(data[4:6], h.QDCount)
	binary.BigEndian.PutUint16(data[6:8], h.ANCount)
	binary.BigEndian.PutUint16(data[8:10], h.NSCount)
	binary.BigEndian.PutUint16(data[10:12], h.ARCount)

	return data
}

// ParseQuestion parses the question section from a byte slice
func ParseQuestion(data []byte, offset int) (DNSQuestion, int) {
	question := DNSQuestion{}
	startOffset := offset
	// Read the QName (domain name)
	var qnameParts []string
	for {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		offset++
		qnameParts = append(qnameParts, string(data[offset:offset+length]))
		offset += length
	}
	question.QNameLength = offset - startOffset
	question.QName = strings.Join(qnameParts, ".")

	// Read QType and QClass
	question.QType = binary.BigEndian.Uint16(data[offset : offset+2])
	question.QClass = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4

	return question, offset
}

// ToBytes converts the DNSQuestion struct back into a byte slice
func (q *DNSQuestion) ToBytes() []byte {
	data := []byte{}

	// Encode QName
	for _, part := range strings.Split(q.QName, ".") {
		if part == "" {
			continue
		}
		data = append(data, byte(len(part)))
		data = append(data, []byte(part)...)
	}
	data = append(data, 0) // End of QName

	// Encode QType and QClass
	qType := make([]byte, 2)
	qClass := make([]byte, 2)
	binary.BigEndian.PutUint16(qType, q.QType)
	binary.BigEndian.PutUint16(qClass, q.QClass)

	data = append(data, qType...)
	data = append(data, qClass...)

	return data
}

// ParseResourceRecord parses a resource record from a byte slice
func ParseResourceRecord(data []byte, offset int) (DNSResourceRecord, int) {
	record := DNSResourceRecord{}

	// Read the Name (domain name) using message compression
	record.Name, offset = readDomainName(data, offset)

	// Read Type, Class, TTL, RDLength, and RData
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

func bytesToFile(data []byte, offset int) {
	fi, err := os.OpenFile("bytes.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer fi.Close()

	_, err = fi.Write([]byte(fmt.Sprintf("ParseResourceRecord:%d:%x\n", offset, data)))

	if err != nil {
		log.Fatalf("Failed to write bytes to file: %v", err)
	}
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

// ToBytes converts the DNSResourceRecord struct back into a byte slice
func (r *DNSResourceRecord) ToBytes() []byte {
	data := []byte{}

	// Encode Name
	for _, part := range strings.Split(r.Name, ".") {
		if part == "" {
			continue
		}
		data = append(data, byte(len(part)))
		data = append(data, []byte(part)...)
	}
	data = append(data, 0) // End of Name

	// Encode Type, Class, TTL, RDLength, and RData
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

func handleDNSRequest(conn *net.UDPConn, addr *net.UDPAddr, msg []byte) {
	// Parse the DNS header
	message := DNSMessage{}
	message.Header = ParseHeader(msg)
	fmt.Printf("Received DNS Query ID: %d\n", message.Header.ID)

	if message.Header.Opcode > 2 {
		fmt.Printf("  [%d] Opcode %d not supported\n", message.Header.ID, message.Header.Opcode)
		return
	}

	if message.Header.Z != 0 {
		fmt.Printf("  [%d] Z must be zero but value is %d\n", message.Header.ID, message.Header.Z)
		return
	}

	// Parse the DNS question
	offset := HEADER_LENGTH
	for i := 0; i < int(message.Header.QDCount); i++ {
		question, newOffset := ParseQuestion(msg, offset)
		fmt.Printf("  [%d] Handling question for: Name: %s Type: %s TypeLiteral: %d Class: %s \n", message.Header.ID, question.QName, QTypeMap[question.QType], question.QType, QClassMap[question.QClass])
		message.Questions = append(message.Questions, question)
		offset = newOffset
	}

	// Check if the DNS query is in the cache
	qName := message.Questions[0].QName
	cacheValue, ok := cache[qName]

	if ok {
		fmt.Printf("  [%d] Cache hit for %s\n", cacheValue.Header.ID, qName)
		if len(cacheValue.Answers) > 0 && time.Now().UTC().After(cacheValue.Answers[0].CreationDate.Add(time.Duration(cacheValue.Answers[0].TTL)*time.Second)) {
			delete(cache, qName)
			fmt.Printf("  [%d] Cache entry expired, fetching from foreign server for %s\n", cacheValue.Header.ID, qName)
		} else {
			// Send the response back to the client
			_, err := conn.WriteToUDP(cacheValue.ToBytes(), addr)
			if err != nil {
				log.Printf("Failed to send DNS response to client: %v", err)
			}
			return
		}
	}

	_, isBlocked := blocked[message.Questions[0].QName]
	response := make([]byte, 512)
	n := len(message.ToBytes())
	if isBlocked {
		fmt.Printf("Blocked domain: %s\n", message.Questions[0].QName)
		message.Answers = append(message.Answers, DNSResourceRecord{
			Name:              message.Questions[0].QName,
			Type:              message.Questions[0].QType,
			TTL:               1000,
			Class:             message.Questions[0].QClass,
			CreationDate:      time.Now(),
			RDLength:          4,
			RData:             []byte{0x7F, 0x00, 0x00, 0x02},
			RDataUncompressed: "",
		})
		message.Header.ANCount = 1
		response = message.ToBytes()
	} else {
		// Forward the request to the upstream DNS server
		upstreamAddr, err := net.ResolveUDPAddr("udp", UPSTREAM)
		if err != nil {
			log.Fatalf("Failed to resolve upstream DNS server address: %v", err)
		}
		upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
		if err != nil {
			log.Fatalf("Failed to connect to upstream DNS server: %v", err)
		}
		defer upstreamConn.Close()

		// Send the request to the upstream DNS server
		_, err = upstreamConn.Write(message.UpstreamBytes())
		if err != nil {
			log.Printf("Failed to send DNS request to upstream server: %v", err)
			return
		}

		// Receive the response from the upstream DNS server
		n, _, err = upstreamConn.ReadFromUDP(response)
		if err != nil {
			log.Printf("Failed to receive DNS response from upstream server: %v", err)
			return
		}
	}

	responseHeader := ParseHeader((response[:HEADER_LENGTH]))
	fmt.Printf("  [%d] Received DNS %s ID from upstream.\n", responseHeader.ID, QRMap[responseHeader.QR])
	fmt.Printf("  [%d] %s\n", responseHeader.ID, RCodeMap[(responseHeader.RCODE)])
	if responseHeader.RD {
		fmt.Printf("  [%d] Recursion desired\n", responseHeader.ID)
	}
	fmt.Printf("  [%d] Results QDCount (Expect 1):%d ANCount:%d NSCount:%d ARCount:%d \n", responseHeader.ID, responseHeader.QDCount, responseHeader.ANCount, responseHeader.NSCount, responseHeader.ARCount)
	responseOffset := HEADER_LENGTH

	for i := 0; i < int(responseHeader.QDCount); i++ {
		responseQuestion, newOffset := ParseQuestion(response, responseOffset)
		fmt.Printf("  [%d] Question for: Name: %s Type: %s Class: %s \n", responseHeader.ID, responseQuestion.QName, QTypeMap[responseQuestion.QType], QClassMap[responseQuestion.QClass])
		responseOffset = newOffset
	}

	for i := 0; i < int(responseHeader.ANCount); i++ {
		record, newOffset := ParseResourceRecord(response, responseOffset)
		fmt.Printf("  [%d] AN Answer for: Name: %s Type: %s Class: %s TTL: %d RDLength: %d RData: %s\n", responseHeader.ID, record.Name, QTypeMap[record.Type], QClassMap[record.Class], record.TTL, record.RDLength, record.RDataUncompressed)
		message.Answers = append(message.Answers, record)
		responseOffset = newOffset
	}

	for i := 0; i < int(responseHeader.NSCount); i++ {
		record, newOffset := ParseResourceRecord(response, responseOffset)
		fmt.Printf("  [%d] NS Answer for: Name: %s Type: %s Class: %s TTL: %d RDLength: %d RData: %s\n", responseHeader.ID, record.Name, QTypeMap[record.Type], QClassMap[record.Class], record.TTL, record.RDLength, record.RDataUncompressed)
		message.Answers = append(message.Answers, record)
		responseOffset = newOffset
	}

	for i := 0; i < int(responseHeader.ARCount); i++ {
		record, newOffset := ParseResourceRecord(response, responseOffset)
		fmt.Printf("  [%d] ARC Answer for: Name: %s Type: %s Class: %s TTL: %d RDLength: %d RData: %s\n", responseHeader.ID, record.Name, QTypeMap[record.Type], QClassMap[record.Class], record.TTL, record.RDLength, record.RDataUncompressed)
		message.Answers = append(message.Answers, record)
		responseOffset = newOffset
	}

	if !ok {
		cache[qName] = message
	}

	// Send the response back to the client
	_, err := conn.WriteToUDP(response[:n], addr)
	if err != nil {
		log.Printf("Failed to send DNS response to client: %v", err)
		return
	}
}

const UPSTREAM = "8.8.8.8:53" // Google's public DNS server
const PORT = ":53"
const HEADER_LENGTH = 12

func main() {
	// Resolve UDP address for the DNS server
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0"+PORT)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	// Start listening on the UDP address
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS server started on %s", PORT)

	for {
		// Buffer to store incoming DNS requests
		buffer := make([]byte, 512)

		// Read incoming DNS request
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read DNS request: %v", err)
			continue
		}
		//logRequest(buffer[:n])

		// Handle the DNS request in a separate goroutine
		go handleDNSRequest(conn, addr, buffer[:n])
	}
}

func logRequest(buffer []byte) {
	fi, err := os.OpenFile("request.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Failed to open file request.txt")
		return
	}
	defer fi.Close()

	_, err = fi.Write(buffer)
	fi.WriteString("###")
	if err != nil {
		log.Println("Failed to write to request.txt")
	}
}

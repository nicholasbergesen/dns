package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

// Cache
var cache = make(map[string]DNSMessage, 10000)

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

var QRMap = map[bool]string{
	true:  "Response",
	false: "Request",
}

var blocked = map[string]bool{
	// "apple.com":      true,
	// "www.apple.com":  true,
	// "www.apple.com.": true,
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

const UPSTREAM = "8.8.8.8:53" // Google's public DNS server
const PORT = ":53"
const HEADER_LENGTH = 12

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0"+PORT)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS server started on %s", PORT)

	for {
		buffer := make([]byte, 512)

		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read DNS request: %v", err)
			continue
		}

		go handleDNSRequest(conn, addr, buffer[:n])
	}
}

func handleDNSRequest(conn *net.UDPConn, addr *net.UDPAddr, msg []byte) {
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

	offset := HEADER_LENGTH
	for i := 0; i < int(message.Header.QDCount); i++ {
		question, newOffset := ParseQuestion(msg, offset)
		fmt.Printf("  [%d] Handling question for: Name: %s Type: %s TypeLiteral: %d Class: %s \n", message.Header.ID, question.QName, QTypeMap[question.QType], question.QType, QClassMap[question.QClass])
		message.Questions = append(message.Questions, question)
		offset = newOffset
	}

	qName := message.Questions[0].QName
	cacheValue, ok := cache[qName]

	if ok {
		if len(cacheValue.Answers) > 0 && time.Now().UTC().After(cacheValue.Answers[0].CreationDate.Add(time.Duration(cacheValue.Answers[0].TTL)*time.Second)) {
			delete(cache, qName)
			fmt.Printf("  [%d] Cache entry expired, fetching from foreign server for %s\n", cacheValue.Header.ID, qName)
		} else {
			cachedBytes := cacheValue.ToBytes()
			copy(cachedBytes[:2], msg[:2])
			cacheValue.Header = ParseHeader(cachedBytes)
			fmt.Printf("  [%d] Cache hit for %s\n", cacheValue.Header.ID, qName)
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

		_, err = upstreamConn.Write(message.UpstreamBytes())
		if err != nil {
			log.Printf("Failed to send DNS request to upstream server: %v", err)
			return
		}

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

	_, err := conn.WriteToUDP(response[:n], addr)
	if err != nil {
		log.Printf("Failed to send DNS response to client: %v", err)
		return
	}
}

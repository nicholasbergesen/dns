package main

import (
	"bufio"
	"io/fs"
	"net"
	"os"
	"strings"

	"github.com/nicholasbergesen/dns/dns"
	"github.com/nicholasbergesen/dns/log"
)

var cache = make(map[string]dns.Message, 10000)
var blocked []string

const UPSTREAM = "8.8.8.8:53" // Google's public DNS server
const PORT = ":53"

var logger = log.Log{FileName: "dns-{date}.log", ShowIncConsole: true}

func main() {
	logger.FormatDate()
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0"+PORT)
	if err != nil {
		logger.Write("Failed to resolve UDP address: %v", err)
		return
	}

	blocked = LoadBlockedUrls()

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Write("Failed to start DNS server: %v", err)
		return
	}
	defer conn.Close()

	logger.Write("DNS server started on %s", PORT)

	for {
		buffer := make([]byte, 512)

		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logger.Write("Failed to read DNS request: %v", err)
			continue
		}

		go handleDNSRequest(conn, addr, buffer[:n])
	}
}

func handleDNSRequest(conn *net.UDPConn, addr *net.UDPAddr, msg []byte) {
	message := dns.Message{}
	message.Header = dns.ParseHeader(msg)
	offset := dns.HEADER_LENGTH
	logger.Write("Received %s from client ID: %d\n", strings.ToLower((dns.QRMap[message.Header.QR])), message.Header.ID)

	if message.Header.Opcode > 2 {
		logger.Write("  [%d] Opcode %d not supported\n", message.Header.ID, message.Header.Opcode)
		return
	}

	if message.Header.Z != 0 {
		logger.Write("  [%d] Z must be zero but value is %d\n", message.Header.ID, message.Header.Z)
		return
	}

	for i := 0; i < int(message.Header.QDCount); i++ {
		question := dns.ParseQuestion(msg, &offset)
		logger.Write("  [%d] Handling question for: Name: %s Type: %s TypeLiteral: %d Class: %s \n", message.Header.ID, question.QName, dns.QTypeMap[question.QType], question.QType, dns.QClassMap[question.QClass])

		message.Questions = append(message.Questions, question)

		if question.QType == 65 || question.QType == 28 { //HTTP, AAAA
			logger.Write("  [%d] Refuse HTTP request for domain: %s\n", message.Header.ID, question.QName)
			message.Header.RCODE = 5 // Refused
			_, err := conn.WriteToUDP(message.ToBytes(), addr)
			if err != nil {
				logger.Write("Failed to send DNS response to client: %v", err)
			}
			return
		}

		for i := 0; i < len(blocked); i++ {
			if blocked[i] == question.QName {
				logger.Write("  [%d] Blocked domain: %s\n", message.Header.ID, question.QName)
				message.Header.RCODE = 3 // NXDomain
				_, err := conn.WriteToUDP(message.ToBytes(), addr)
				if err != nil {
					logger.Write("Failed to send DNS response to client: %v", err)
				}
				return
			}
		}
	}

	qName := message.Questions[0].QName
	cacheValue, isInCache := cache[qName]

	if isInCache {
		if cacheValue.IsExpired() {
			delete(cache, qName)
			logger.Write("  [%d] Cache entry expired, fetching from foreign server for %s\n", cacheValue.Header.ID, qName)
		} else {
			cacheValue.Header.ID = message.Header.ID
			logger.Write("  [%d] Cache hit for %s\n", cacheValue.Header.ID, qName)
			_, err := conn.WriteToUDP(cacheValue.ToBytes(), addr)
			if err != nil {
				logger.Write("Failed to send DNS response to client: %v", err)
			}
			return
		}
	}

	response, n := GetUpstreamResponse(message)

	responseHeader := dns.ParseHeader((response[:dns.HEADER_LENGTH]))
	logger.Write("  [%d] Received %s %s from upstream server.\n", responseHeader.ID, dns.RCodeMap[(responseHeader.RCODE)], strings.ToLower((dns.QRMap[responseHeader.QR])))
	logger.Write("  [%d] Results QDCount (Expect 1):%d ANCount:%d NSCount:%d ARCount:%d \n", responseHeader.ID, responseHeader.QDCount, responseHeader.ANCount, responseHeader.NSCount, responseHeader.ARCount)

	if responseHeader.RCODE == 0 {
		for i := 0; i < int(responseHeader.ANCount); i++ {
			record := dns.ParseResourceRecord(response, &offset)
			message.Answers = append(message.Answers, record)
			logger.Write("  [%d]   AN Answer for: Name: %s Type: %s Class: %s TTL: %d RDLength: %d RData: %s\n", responseHeader.ID, record.Name, dns.QTypeMap[record.Type], dns.QClassMap[record.Class], record.TTL, record.RDLength, record.RDataUncompressed)
		}

		for i := 0; i < int(responseHeader.NSCount); i++ {
			var record = dns.ParseResourceRecord(response, &offset)
			message.Answers = append(message.Answers, record)
			logger.Write("  [%d]   NS Answer for: Name: %s Type: %s Class: %s TTL: %d RDLength: %d RData: %s\n", responseHeader.ID, record.Name, dns.QTypeMap[record.Type], dns.QClassMap[record.Class], record.TTL, record.RDLength, record.RDataUncompressed)
		}

		for i := 0; i < int(responseHeader.ARCount); i++ {
			var record = dns.ParseResourceRecord(response, &offset)
			message.Answers = append(message.Answers, record)
			logger.Write("  [%d]   ARC Answer for: Name: %s Type: %s Class: %s TTL: %d RDLength: %d RData: %s\n", responseHeader.ID, record.Name, dns.QTypeMap[record.Type], dns.QClassMap[record.Class], record.TTL, record.RDLength, record.RDataUncompressed)
		}
	}

	if !isInCache {
		cache[qName] = message
	}

	_, err := conn.WriteToUDP(response[:n], addr)
	if err != nil {
		logger.Write("Failed to send DNS response to client: %v", err)
		return
	}
}

func GetUpstreamResponse(message dns.Message) ([]byte, int) {
	// Forward the request to the upstream DNS server
	upstreamAddr, err := net.ResolveUDPAddr("udp", UPSTREAM)
	if err != nil {
		logger.Write("Failed to resolve upstream DNS server address: %v", err)
		return nil, 0
	}
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		logger.Write("Failed to connect to upstream DNS server: %v", err)
		return nil, 0
	}
	defer upstreamConn.Close()

	_, err = upstreamConn.Write(message.UpstreamBytes())
	response := make([]byte, 512)
	if err != nil {
		logger.Write("Failed to send DNS request to upstream server: %v", err)
		return response, 0
	}
	n, _, err := upstreamConn.ReadFromUDP(response)
	if err != nil {
		logger.Write("Failed to receive DNS response from upstream server: %v", err)
		return response, 0
	}

	return response, n
}

func LoadBlockedUrls() []string {
	var lines []string
	file, err := os.OpenFile("block.txt", os.O_RDONLY, fs.ModeAppend)
	defer file.Close()

	if err != nil {
		logger.Write("No block.txt found\n")
		return lines
	}

	reader := bufio.NewReader(file)
	logger.Write("Items loaded from block.txt\n")
	for {
		line, _, err := reader.ReadLine()
		logger.Write("%s\n", line)

		if err != nil || line == nil {
			break
		}

		lines = append(lines, string(line))
	}
	return lines
}

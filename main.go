package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nicholasbergesen/dns/dns"
	"github.com/nicholasbergesen/dns/doh"
	"github.com/nicholasbergesen/dns/log"
)

var cache = make(map[string]dns.Message, 10000)
var cacheMutex sync.RWMutex
var blocked []string
var blockedMutex sync.RWMutex

const UPSTREAM = "8.8.8.8:53" // Google's public DNS server
const DOH_PATH = "/dns-query"
const MAX_CACHE_SIZE = 100000

var logger = log.Log{FileName: "dns-{date}.log", ShowIncConsole: true}
var dohUpstream = doh.NewDOHUpstream(doh.DefaultDOHUpstream)

var (
	udpPort   = flag.String("udp-port", ":53", "UDP port for traditional DNS")
	httpsPort = flag.String("https-port", ":8443", "HTTPS port for DOH")
	enableDOH = flag.Bool("enable-doh", true, "Enable DNS over HTTPS")
	enableUDP = flag.Bool("enable-udp", true, "Enable traditional UDP DNS")
)

func main() {
	flag.Parse()

	logger.FormatDate()
	var exPath string
	ex, err := os.Executable()
	if err != nil {
		logger.Write("Failed to get executable path: %v\n", err)
		exPath = "."
	} else {
		exPath = filepath.Dir(ex)
	}
	logger.Write("Running from %s\n", exPath)

	blockedUrls := LoadBlockedUrls()
	blockedMutex.Lock()
	blocked = blockedUrls
	blockedMutex.Unlock()

	if *enableUDP {
		go startUDPServer()
	}

	if *enableDOH {
		startHTTPSServer()
	} else if !*enableUDP {
		logger.Write("Neither UDP nor DOH enabled, exiting\n")
		return
	} else {
		select {}
	}
}

func startUDPServer() {
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0"+*udpPort)
	if err != nil {
		logger.Write("Failed to resolve UDP address: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Write("Failed to start DNS server: %v", err)
		return
	}
	defer conn.Close()

	logger.Write("DNS server started on %s\n", *udpPort)

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

func startHTTPSServer() {
	mux := http.NewServeMux()
	mux.HandleFunc(DOH_PATH, handleDOHRequest)

	cert := generateSelfSignedCert()
	
	// Check if certificate generation failed
	if len(cert.Certificate) == 0 {
		logger.Write("Failed to generate certificate, DOH server cannot start\n")
		return
	}

	server := &http.Server{
		Addr:    "0.0.0.0" + *httpsPort,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}

	logger.Write("DOH server starting on %s%s\n", *httpsPort, DOH_PATH)

	err := server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Write("Failed to start DOH server: %v", err)
	}
}

func generateSelfSignedCert() tls.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Write("Failed to generate private key: %v", err)
		// Return empty certificate and let the caller handle the error
		return tls.Certificate{}
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"DNS Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		logger.Write("Failed to create certificate: %v", err)
		return tls.Certificate{}
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	os.WriteFile("server.crt", certPEM, 0644)
	os.WriteFile("server.key", keyPEM, 0600)

	logger.Write("Generated self-signed certificate for HTTPS\n")

	return cert
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

		if isBlocked(question.QName) {
			logger.Write("  [%d] Blocked domain: %s\n", message.Header.ID, question.QName)
			message.Header.RCODE = 3 // NXDomain
			_, err := conn.WriteToUDP(message.ToBytes(), addr)
			if err != nil {
				logger.Write("Failed to send DNS response to client: %v", err)
			}
			return
		}
	}

	// Check if we have any questions to process
	if len(message.Questions) == 0 {
		logger.Write("  [%d] No questions in request\n", message.Header.ID)
		return
	}

	qName := message.Questions[0].QName
	cacheValue, isInCache := getCacheEntry(qName)

	if isInCache {
		if cacheValue.IsExpired() {
			deleteCacheEntry(qName)
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
		setCacheEntry(qName, message)
	}

	_, err := conn.WriteToUDP(response[:n], addr)
	if err != nil {
		logger.Write("Failed to send DNS response to client: %v", err)
		return
	}
}

func GetUpstreamResponse(message dns.Message) ([]byte, int) {
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

	// Set timeout for upstream operations
	upstreamConn.SetDeadline(time.Now().Add(5 * time.Second))

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

func handleDOHRequest(w http.ResponseWriter, r *http.Request) {
	var queryBytes []byte
	var err error

	switch r.Method {
	case "GET":
		queryBytes, err = doh.HandleGETRequest(w, r)
		if err != nil {
			logger.Write("DOH GET request error: %v", err)
			return
		}
	case "POST":
		queryBytes, err = doh.HandlePOSTRequest(w, r)
		if err != nil {
			logger.Write("DOH POST request error: %v", err)
			return
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err = doh.ValidateDNSQuery(queryBytes)
	if err != nil {
		logger.Write("Invalid DOH DNS query: %v", err)
		http.Error(w, "Invalid DNS query", http.StatusBadRequest)
		return
	}

	message := dns.Message{}
	message.Header = dns.ParseHeader(queryBytes)
	offset := dns.HEADER_LENGTH
	logger.Write("Received DOH %s from client ID: %d\n", strings.ToLower(dns.QRMap[message.Header.QR]), message.Header.ID)

	if message.Header.Opcode > 2 {
		logger.Write("  [%d] Opcode %d not supported\n", message.Header.ID, message.Header.Opcode)
		http.Error(w, "Opcode not supported", http.StatusNotImplemented)
		return
	}

	if message.Header.Z != 0 {
		logger.Write("  [%d] Z must be zero but value is %d\n", message.Header.ID, message.Header.Z)
		http.Error(w, "Invalid Z field", http.StatusBadRequest)
		return
	}

	for i := 0; i < int(message.Header.QDCount); i++ {
		question := dns.ParseQuestion(queryBytes, &offset)
		logger.Write("  [%d] Handling DOH question for: Name: %s Type: %s TypeLiteral: %d Class: %s \n", message.Header.ID, question.QName, dns.QTypeMap[question.QType], question.QType, dns.QClassMap[question.QClass])

		message.Questions = append(message.Questions, question)

		if isBlocked(question.QName) {
			logger.Write("  [%d] Blocked domain: %s\n", message.Header.ID, question.QName)
			message.Header.RCODE = 3
			doh.SendDNSResponse(w, message.ToBytes())
			return
		}
	}

	// Check if we have any questions to process
	if len(message.Questions) == 0 {
		logger.Write("  [%d] No questions in DOH request\n", message.Header.ID)
		http.Error(w, "No questions in request", http.StatusBadRequest)
		return
	}

	qName := message.Questions[0].QName
	cacheValue, isInCache := getCacheEntry(qName)

	if isInCache {
		if cacheValue.IsExpired() {
			deleteCacheEntry(qName)
			logger.Write("  [%d] Cache entry expired, fetching from DOH upstream for %s\n", cacheValue.Header.ID, qName)
		} else {
			cacheValue.Header.ID = message.Header.ID
			logger.Write("  [%d] Cache hit for %s\n", cacheValue.Header.ID, qName)
			doh.SendDNSResponse(w, cacheValue.ToBytes())
			return
		}
	}

	response, err := dohUpstream.QueryDOH(queryBytes)
	if err != nil {
		logger.Write("Failed to query DOH upstream: %v", err)
		http.Error(w, "Upstream query failed", http.StatusBadGateway)
		return
	}

	responseHeader := dns.ParseHeader(response[:dns.HEADER_LENGTH])
	logger.Write("  [%d] Received %s %s from DOH upstream server.\n", responseHeader.ID, dns.RCodeMap[responseHeader.RCODE], strings.ToLower(dns.QRMap[responseHeader.QR]))
	logger.Write("  [%d] Results QDCount (Expect 1):%d ANCount:%d NSCount:%d ARCount:%d \n", responseHeader.ID, responseHeader.QDCount, responseHeader.ANCount, responseHeader.NSCount, responseHeader.ARCount)

	if responseHeader.RCODE == 0 {
		respOffset := dns.HEADER_LENGTH
		for i := 0; i < int(responseHeader.QDCount); i++ {
			dns.ParseQuestion(response, &respOffset)
		}
		for i := 0; i < int(responseHeader.ANCount); i++ {
			record := dns.ParseResourceRecord(response, &respOffset)
			message.Answers = append(message.Answers, record)
			logger.Write("  [%d]   AN Answer for: Name: %s Type: %s Class: %s TTL: %d RDLength: %d RData: %s\n", responseHeader.ID, record.Name, dns.QTypeMap[record.Type], dns.QClassMap[record.Class], record.TTL, record.RDLength, record.RDataUncompressed)
		}
	}

	if !isInCache {
		message.Header = responseHeader
		setCacheEntry(qName, message)
	}

	doh.SendDNSResponse(w, response)
}

func LoadBlockedUrls() []string {
	var lines []string
	file, err := os.OpenFile("block.txt", os.O_RDONLY, fs.ModeAppend)
	if err != nil {
		logger.Write("No block.txt found\n")
		return lines
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	logger.Write("Loading items from block.txt\n")
	for {
		line, _, err := reader.ReadLine()

		if err != nil || line == nil {
			break
		}

		lines = append(lines, string(line))
	}
	logger.Write("%d block urls loaded\n", len(lines))
	return lines
}

// Safe cache operations with size management
func getCacheEntry(key string) (dns.Message, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	val, exists := cache[key]
	return val, exists
}

func setCacheEntry(key string, message dns.Message) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	
	// If cache is full, remove oldest entries (simple LRU approximation)
	if len(cache) >= MAX_CACHE_SIZE {
		// Remove first entry found (not true LRU but prevents unbounded growth)
		for k := range cache {
			delete(cache, k)
			break
		}
	}
	cache[key] = message
}

func deleteCacheEntry(key string) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	delete(cache, key)
}

func isBlocked(domain string) bool {
	blockedMutex.RLock()
	defer blockedMutex.RUnlock()
	for i := 0; i < len(blocked); i++ {
		if blocked[i] == domain {
			return true
		}
	}
	return false
}

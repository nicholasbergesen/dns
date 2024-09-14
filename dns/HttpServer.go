package dns

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type HttpServer struct{}

func (s *HttpServer) Start() {
	logger.FormatDate()
	blocked = LoadBlockedUrls()
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	logger.Write("Running from %s\n", exPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/dns-query", handleDnsGetQuery)

	httpServer := &http.Server{
		Addr:           ":8080",
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		Handler:        mux,
		MaxHeaderBytes: 1 << 20,
	}

	httpServer.ListenAndServe()
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	logger.Write("Root request received\n")
	w.WriteHeader(http.StatusBadRequest)
}

func handleDnsGetQuery(w http.ResponseWriter, r *http.Request) {
	logger.Write("GET request received\n")

	// 1. Get DNS Param
	// 2. Decode from base64
	// 3. Parse DNS Message

	dnsQueryBase64 := r.URL.Query().Get("dns")
	if dnsQueryBase64 == "" {
		w.WriteHeader(http.StatusBadRequest)
		logger.Write("No DNS query found\n")
		return
	}

	dnsQuery, err := base64.StdEncoding.DecodeString(dnsQueryBase64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logger.Write("Error decoding DNS query %s\n", err)
		return
	}

	logger.Write("DNS query: %s\n", dnsQuery)

	// acceptHeader := r.Header.Get("accept")
	// if acceptHeader != "application/dns-message" {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	logger.Write("Invalid accept header %s\n", acceptHeader)
	// 	return
	// }

	w.Write([]byte("Hello, World!"))
}

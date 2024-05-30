package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var reExploit = regexp.MustCompile(`\${.*}`)

type Logger struct {
	logFile string
	mu      sync.Mutex
}

type LogEntry struct {
	Type                string      `json:"type"`
	Timestamp           int64       `json:"timestamp"`
	Protocol            string      `json:"protocol"`
	App                 string      `json:"app"`
	Name                string      `json:"name"`
	UUID                string      `json:"UUID"`
	CorrelationID       string      `json:"correlation_id,omitempty"`
	DestPort            int         `json:"dest_port,omitempty"`
	SrcIP               string      `json:"src_ip,omitempty"`
	SrcPort             int         `json:"src_port,omitempty"`
	Request             string      `json:"request,omitempty"`
	DestIP              string      `json:"dest_ip,omitempty"`
	Payload             string      `json:"payload,omitempty"`
	DeobfuscatedPayload string      `json:"deobfuscated_payload,omitempty"`
	Exception           string      `json:"exception,omitempty"`
	Extend              interface{} `json:"extend,omitempty"`
}

func (l *Logger) log(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now().UnixNano() / int64(time.Millisecond)
	entry.App = "log4potgo"
	entry.Name = "log4potgo"
	entry.Protocol = "HTTP"
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	f, err := os.OpenFile(l.logFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		log.Printf("Failed to write to log file: %v", err)
	}
}

func (l *Logger) logStart() {
	l.log(LogEntry{Type: "start"})
}

func (l *Logger) logRequest(LocalAddr string, ipAddress string, request string, headers http.Header, uuid string) {
	clientIP, clientPort, _ := net.SplitHostPort(ipAddress)
	portInt, _ := strconv.Atoi(clientPort)

	DestIP, DestPort, _ := net.SplitHostPort(LocalAddr)
	DestPortInt, _ := strconv.Atoi(DestPort)

	l.log(LogEntry{
		Type:          "request",
		CorrelationID: uuid,
		DestIP:        DestIP,
		DestPort:      DestPortInt,
		SrcIP:         clientIP,
		SrcPort:       portInt,
		Request:       request,
		Extend:        headers,
		UUID:          "<UUID>",
	})
}

func (l *Logger) logExploit(location, payload, deobfuscatedPayload, uuid string) {
	l.log(LogEntry{
		Type:          "exploit",
		CorrelationID: uuid,
		// Location:            location,
		Payload:             payload,
		DeobfuscatedPayload: deobfuscatedPayload,
	})
}

func (l *Logger) logException(e error, uuid string) {
	l.log(LogEntry{
		Type:          "exception",
		Exception:     e.Error(),
		CorrelationID: uuid,
	})
}

func (l *Logger) logEnd() {
	l.log(LogEntry{Type: "end"})
}

type Server struct {
	logger       *Logger
	serverHeader string
	response     []byte
	contentType  string
}

func newServer(logger *Logger, serverHeader string, response []byte, contentType string) *Server {
	return &Server{
		logger:       logger,
		serverHeader: serverHeader,
		response:     response,
		contentType:  contentType,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uuid := fmt.Sprintf("%d", time.Now().UnixNano())

	s.logger.logRequest(r.Host, r.RemoteAddr, r.Method, r.Header, uuid)

	w.Header().Set("Content-Type", s.contentType)
	if s.serverHeader != "" {
		w.Header().Set("Server", s.serverHeader)
	}
	w.Write(s.response)

	s.findExploit("request", r.Method, uuid)
	for header, values := range r.Header {
		for _, value := range values {
			s.findExploit(fmt.Sprintf("header-%s", header), value, uuid)
		}
	}
}

func (s *Server) findExploit(location, content, uuid string) {
	if m := reExploit.FindString(content); m != "" {
		deobfuscatedExploit := deobfuscate(m)
		s.logger.logExploit(location, m, deobfuscatedExploit, uuid)
	}
}

func deobfuscate(payload string) string {
	// This is a placeholder for the actual deobfuscation logic.
	return payload
}

func main() {
	var (
		port         = flag.String("port", "8080", "Listening port")
		logFile      = flag.String("log", "log4pot.log", "Log file")
		responseFile = flag.String("response", "responses/default.json", "File used as response")
		contentType  = flag.String("content-type", "application/json", "Content type of response")
		serverHeader = flag.String("server-header", "", "Replace the default server header")
	)
	flag.Parse()

	logger := &Logger{logFile: *logFile}
	logger.logStart()
	defer logger.logEnd()

	response, err := ioutil.ReadFile(*responseFile)
	if err != nil {
		log.Fatalf("Failed to read response file: %v", err)
	}

	server := newServer(logger, *serverHeader, response, *contentType)

	http.Handle("/", server)
	log.Printf("Starting server on port %s", *port)
	if err := http.ListenAndServe(":"+*port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

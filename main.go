package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/google/logger"
	"github.com/spf13/viper"
)

// Logger struct for logging events
type Logger struct {
	logger *logger.Logger
}

// NewLogger creates a new Logger object
func NewLogger(logPath string) *Logger {
	l := logger.NewLogger("log4pot")
	l.SetOutput(os.Stdout)
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer f.Close()
		l.SetOutput(io.MultiWriter(os.Stdout, f))
	}

	return &Logger{logger: l}
}

// LogEvent logs an event with the specified level and message
func (l *Logger) LogEvent(level logger.Level, message string, fields map[string]interface{}) {
	l.logger.Log(level, message, fields)
}

// LogRequest logs a request event
func (l *Logger) LogRequest(request *http.Request, uuid string) {
	fields := map[string]interface{}{
		"correlation_id": uuid,
		"src_ip":         request.RemoteAddr,
		"src_port":       request.RemotePort,
		"request":        request.Method + " " + request.RequestURI,
		"protocol":       "http",
		"app":           "log4pot",
		"name":          "log4pot",
		"UUID":          uuid,
	}

	if request.TLS != nil {
		fields["tls"] = true
	}

	for _, header := range request.Header {
		fields["header-"+header.Key] = header.Value
	}

	l.LogEvent(logger.Info, "Request received", fields)
}

// LogExploit logs an exploit event
func (l *Logger) LogExploit(location, payload, deobfuscatedPayload string, uuid string) {
	fields := map[string]interface{}{
		"correlation_id":  uuid,
		"location":        location,
		"payload":         payload,
		"deobfuscated_payload": deobfuscatedPayload,
	}

	l.LogEvent(logger.Warning, "Exploit detected", fields)
}

// LogPayload logs a payload event
func (l *Logger) LogPayload(uuid string, fields map[string]interface{}) {
	fields["correlation_id"] = uuid
	l.LogEvent(logger.Info, "Payload downloaded", fields)
}

// LogException logs an exception event
func (l *Logger) LogException(err error, uuid string) {
	fields := map[string]interface{}{
		"correlation_id": uuid,
		"exception":      err.Error(),
	}

	l.LogEvent(logger.Error, "Exception occurred", fields)
}

// LogEnd logs an end event
func (l *Logger) LogEnd() {
	l.LogEvent(logger.Info, "Log4Pot stopped")
}

// HTTPRequestHandler handles incoming HTTP requests
type HTTPRequestHandler struct {
	logger   *Logger
	deobfuscator func(string) string
	payloader *Payloader
}

// ServeHTTP implements the http.Handler interface
func (h *HTTPRequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uuid := uuid.NewString()

	h.logger.LogRequest(r, uuid)

	exploitPattern := regexp.MustCompile("\\${.*}")
	for _, header := range r.Header {
		if m := exploitPattern.MatchString(header.Value); m {
			exploit := header.Value
			deobfuscatedExploit := h.deobfuscator(exploit)

			h.logger.LogExplo

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Logger 结构体用于日志记录
type Logger struct {
	logFile *os.File
}

// NewLogger 创建一个新的Logger实例
func NewLogger(logFilePath string) *Logger {
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	return &Logger{logFile}
}

// Log 记录日志信息
func (l *Logger) Log(logtype, message string, kwargs map[string]string) {
	unixTime := time.Now().Unix()
	logData := map[string]interface{}{
		"type":      logtype,
		"timestamp": unixTime * 1000,
		"protocol":  "http",
		"app":       "log4pot",
		"name":      "log4pot",
		"UUID":      "<UUID>",
	}
	for k, v := range kwargs {
		logData[k] = v
	}
	jsonData, _ := json.Marshal(logData)
	l.logFile.WriteString(string(jsonData) + "\n")
	l.logFile.Sync()
}

// Close 关闭日志文件
func (l *Logger) Close() {
	l.logFile.Close()
}

// RequestHandler 是处理HTTP请求的结构体
type RequestHandler struct {
	logger       *Logger
	deobfuscator func(string) string
}

// ServeHTTP 实现http.Handler接口
func (h *RequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.logger.Log("request", "A request was received", map[string]string{
		"request": r.RequestURI,
		"src_ip":  r.RemoteAddr,
	})

	// 检查是否存在exploit模式
	if matchesExploit(r.RequestURI) {
		exploit := extractExploit(r.RequestURI)
		deobfuscatedExploit := h.deobfuscator(exploit)
		h.logger.Log("exploit", "Exploit detected", map[string]string{
			"payload":      exploit,
			"deobfuscated": deobfuscatedExploit,
		})
	}

	// 发送响应
	response, err := ioutil.ReadFile("responses/default.json")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func matchesExploit(content string) bool {
	return regexp.MustCompile(`\${.*}`).FindString(content) != ""
}

func extractExploit(content string) string {
	return regexp.MustCompile(`\${.*}`).FindString(content)
}

func deobfuscate(exploit string) string {
	// 这里只是一个示例，实际的解混淆逻辑需要根据具体情况实现
	return strings.Replace(exploit, "${", "", 1)
}

func main() {
	var port string
	var certFile string
	var keyFile string

	flag.StringVar(&port, "port", ":9000", "Listening port")
	flag.StringVar(&certFile, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFile, "key", "", "TLS key file")
	flag.Parse()

	logger := NewLogger("log4pot.log")

	handler := &RequestHandler{
		logger:       logger,
		deobfuscator: deobfuscate,
	}

	server := &http.Server{
		Addr:    port,
		Handler: handler,
	}

	if certFile != "" && keyFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		listener, err := tls.Listen("tcp", port, server)
		if err != nil {
			logger.Log("error", err.Error(), nil)
			os.Exit(1)
		}
		fmt.Printf("Started Log4Pot server on port %s with TLS.\n", port)
		err = server.ServeTLS(listener, certFile, keyFile)
	} else {
		listener, err := net.Listen("tcp", port)
		if err != nil {
			logger.Log("error", err.Error(), nil)
			os.Exit(1)
		}
		fmt.Printf("Started Log4Pot server on port %s.\n", port)
		err = server.Serve(listener)
	}
	if err != nil {
		logger.Log("error", err.Error(), nil)
	}

	logger.Close()
}

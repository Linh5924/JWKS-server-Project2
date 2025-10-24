package main

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite3", "./test_keys.db")
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)`)
	db.Exec("DELETE FROM keys")
	saveKeyToDB(generateKeyPair(time.Now().Add(time.Hour)))
	saveKeyToDB(generateKeyPair(time.Now().Add(-time.Hour)))
}

func teardownTestDB(t *testing.T) {
	if db != nil {
		db.Close()
	}
	os.Remove("./test_keys.db")
}

func TestJWKSHandler(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	w := httptest.NewRecorder()
	jwksHandler(w, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if w.Code != 200 {
		t.Fatal("Expected 200")
	}

	var jwks JWKS
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) == 0 {
		t.Error("No keys")
	}
	if jwks.Keys[0].Kty != "RSA" || jwks.Keys[0].N == "" {
		t.Error("Invalid JWK")
	}
}

func TestJWKSHandlerMethods(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	for _, m := range []string{"POST", "PUT", "DELETE"} {
		w := httptest.NewRecorder()
		jwksHandler(w, httptest.NewRequest(m, "/", nil))
		if w.Code != 405 {
			t.Error("Should be 405")
		}
	}
}

func TestJWKSHandlerError(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Close()
	w := httptest.NewRecorder()
	jwksHandler(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 500 {
		t.Error("Should be 500 on db error")
	}
	setupTestDB(t)
}

func TestAuthHandler(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	w := httptest.NewRecorder()
	authHandler(w, httptest.NewRequest("POST", "/auth", nil))
	if w.Code != 200 {
		t.Fatal("Expected 200")
	}

	token, _, _ := new(jwt.Parser).ParseUnverified(w.Body.String(), jwt.MapClaims{})
	if token.Header["kid"] == nil {
		t.Error("No kid")
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["sub"] != "user123" {
		t.Error("Wrong sub")
	}
}

func TestAuthHandlerExpired(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	w := httptest.NewRecorder()
	authHandler(w, httptest.NewRequest("POST", "/auth?expired=true", nil))
	if w.Code != 200 {
		t.Fatal("Expected 200")
	}

	token, _, _ := new(jwt.Parser).ParseUnverified(w.Body.String(), jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)
	if int64(claims["exp"].(float64)) > time.Now().Unix() {
		t.Error("Should be expired")
	}
}

func TestAuthHandlerMethods(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	for _, m := range []string{"GET", "PUT", "DELETE"} {
		w := httptest.NewRecorder()
		authHandler(w, httptest.NewRequest(m, "/", nil))
		if w.Code != 405 {
			t.Error("Should be 405")
		}
	}
}

func TestAuthHandlerNoValidKey(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Exec("DELETE FROM keys WHERE exp > ?", time.Now().Unix())
	w := httptest.NewRecorder()
	authHandler(w, httptest.NewRequest("POST", "/auth", nil))
	if w.Code != 500 {
		t.Error("Should be 500 when no valid key")
	}
}

func TestAuthHandlerNoExpiredKey(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Exec("DELETE FROM keys WHERE exp <= ?", time.Now().Unix())
	w := httptest.NewRecorder()
	authHandler(w, httptest.NewRequest("POST", "/auth?expired=true", nil))
	if w.Code != 500 {
		t.Error("Should be 500 when no expired key")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	kp := generateKeyPair(time.Now().Add(time.Hour))
	if kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Error("Keys nil")
	}
	if kp.PrivateKey.N.BitLen() != 2048 {
		t.Error("Wrong size")
	}
}

func TestToJWK(t *testing.T) {
	kp := generateKeyPair(time.Now().Add(time.Hour))
	kp.Kid = "test"
	jwk := kp.toJWK()
	if jwk.Kty != "RSA" || jwk.Kid != "test" {
		t.Error("Invalid")
	}
}

func TestSaveKeyToDB(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Exec("DELETE FROM keys")
	saveKeyToDB(generateKeyPair(time.Now().Add(time.Hour)))
	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if count != 1 {
		t.Error("Not saved")
	}
}

func TestLoadKeyFromDB(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	var kid int
	db.QueryRow("SELECT kid FROM keys LIMIT 1").Scan(&kid)
	key, err := loadKeyFromDB(kid)
	if err != nil || key == nil {
		t.Error("Load failed")
	}
}

func TestLoadKeyFromDBInvalidKid(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	_, err := loadKeyFromDB(99999)
	if err == nil {
		t.Error("Should error on invalid kid")
	}
}

func TestGetValidKey(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	key, err := getValidKey()
	if err != nil || key == nil {
		t.Error("Failed")
	}
	if key.Expiry.Before(time.Now()) {
		t.Error("Expired")
	}
}

func TestGetValidKeyError(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Exec("DELETE FROM keys WHERE exp > ?", time.Now().Unix())
	_, err := getValidKey()
	if err == nil {
		t.Error("Should error")
	}
}

func TestGetExpiredKey(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	key, err := getExpiredKey()
	if err != nil || key == nil {
		t.Error("Failed")
	}
	if key.Expiry.After(time.Now()) {
		t.Error("Not expired")
	}
}

func TestGetExpiredKeyError(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Exec("DELETE FROM keys WHERE exp <= ?", time.Now().Unix())
	_, err := getExpiredKey()
	if err == nil {
		t.Error("Should error")
	}
}

func TestGetAllValidKeys(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	saveKeyToDB(generateKeyPair(time.Now().Add(2 * time.Hour)))
	keys, err := getAllValidKeys()
	if err != nil || len(keys) < 2 {
		t.Error("Failed")
	}
}

func TestGetAllValidKeysError(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Close()
	_, err := getAllValidKeys()
	if err == nil {
		t.Error("Should error")
	}
	setupTestDB(t)
}

func TestGetAllValidKeysEmptyResult(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	db.Exec("DELETE FROM keys WHERE exp > ?", time.Now().Unix())
	keys, err := getAllValidKeys()
	if err != nil {
		t.Error("Should not error")
	}
	if len(keys) != 0 {
		t.Error("Should be empty")
	}
}

func TestInitializeKeys(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", "./test_init.db")
	defer os.Remove("./test_init.db")

	testDB.Exec(`CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)`)
	orig := db
	db = testDB
	initializeKeys()

	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if count != 2 {
		t.Error("Wrong count")
	}

	initializeKeys()
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if count != 2 {
		t.Error("Duplicated")
	}

	db.Close()
	db = orig
}

func TestDatabasePersistence(t *testing.T) {
	testDB, _ := sql.Open("sqlite3", "./test_persist.db")
	defer os.Remove("./test_persist.db")

	testDB.Exec(`CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)`)
	orig := db
	db = testDB
	saveKeyToDB(generateKeyPair(time.Now().Add(time.Hour)))
	testDB.Close()

	testDB, _ = sql.Open("sqlite3", "./test_persist.db")
	db = testDB
	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if count != 1 {
		t.Error("Not persisted")
	}
	db.Close()
	db = orig
}

func TestJWKSWithMultipleKeys(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	for i := 0; i < 3; i++ {
		saveKeyToDB(generateKeyPair(time.Now().Add(time.Hour * time.Duration(i+2))))
	}

	w := httptest.NewRecorder()
	jwksHandler(w, httptest.NewRequest("GET", "/", nil))

	var jwks JWKS
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) < 3 {
		t.Error("Not enough keys")
	}
}

func TestContentTypes(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	w := httptest.NewRecorder()
	jwksHandler(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Error("Wrong type")
	}

	w = httptest.NewRecorder()
	authHandler(w, httptest.NewRequest("POST", "/auth", nil))
	if w.Header().Get("Content-Type") != "text/plain" {
		t.Error("Wrong type")
	}
}

func TestJWTStructure(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	w := httptest.NewRecorder()
	authHandler(w, httptest.NewRequest("POST", "/auth", nil))
	if len(strings.Split(w.Body.String(), ".")) != 3 {
		t.Error("Invalid JWT")
	}
}

func TestExpiredNotInJWKS(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	w := httptest.NewRecorder()
	jwksHandler(w, httptest.NewRequest("GET", "/", nil))
	var jwks JWKS
	json.Unmarshal(w.Body.Bytes(), &jwks)

	for _, key := range jwks.Keys {
		var exp int64
		db.QueryRow("SELECT exp FROM keys WHERE kid = ?", key.Kid).Scan(&exp)
		if time.Unix(exp, 0).Before(time.Now()) {
			t.Error("Expired in JWKS")
		}
	}
}

func TestGetAllValidKeysLoop(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	for i := 0; i < 5; i++ {
		saveKeyToDB(generateKeyPair(time.Now().Add(time.Hour * time.Duration(i+1))))
	}

	keys, _ := getAllValidKeys()
	if len(keys) < 5 {
		t.Error("Loop not working")
	}

	for _, k := range keys {
		if k.Kid == "" || k.PrivateKey == nil {
			t.Error("Invalid key in loop")
		}
	}
}

func TestPEMEncodingDecoding(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB(t)

	original := generateKeyPair(time.Now().Add(time.Hour))
	saveKeyToDB(original)

	var kid int
	db.QueryRow("SELECT kid FROM keys ORDER BY kid DESC LIMIT 1").Scan(&kid)

	loaded, err := loadKeyFromDB(kid)
	if err != nil {
		t.Error("PEM decode failed")
	}

	if loaded.PrivateKey.N.Cmp(original.PrivateKey.N) != 0 {
		t.Error("PEM encoding/decoding mismatch")
	}
}

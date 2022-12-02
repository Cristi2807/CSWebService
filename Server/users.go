package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"hash"
	"io"
	"net/http"
	"os"
	"time"
)

type User struct {
	PasswordHash string    `json:"passwordHash"`
	TokenHash    string    `json:"tokenHash"`
	ValidUntil   time.Time `json:"validUntil"`
}

var users = make(map[string]User)

func loadUsers() {
	file, _ := os.ReadFile("users.json")

	_ = json.Unmarshal(file, &users)
}

func saveUsers() {
	file, _ := json.MarshalIndent(users, "", " ")

	os.WriteFile("users.json", file, 0644)

}

// Hash

func HashPassword(password string) (string, error) {
	bytes1, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes1), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//Check Login

func checkLogin(w http.ResponseWriter, username string, tokenHash string) bool {

	if _, ok := users[username]; !ok {
		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Invalid Username!",
			},
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return false
	}

	if tokenHash == "" {
		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Please log in firstly!",
			},
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return false
	}

	if tokenHash != users[username].TokenHash {
		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Session Token corrupted. Log in again!",
			},
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return false
	}

	if time.Now().Sub(users[username].ValidUntil) > 0 {
		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Your current session expired. Log in again!",
			},
		)

		users[username] = User{PasswordHash: users[username].PasswordHash,
			TokenHash:  "",
			ValidUntil: time.Now()}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return false
	}

	return true
}

//RSA

func EncryptOAEP(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

func DecryptOAEP(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}

func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	// This method requires a random number of bits.
	privateKey1, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	// The public key is part of the PrivateKey struct
	return privateKey1, &privateKey1.PublicKey
}

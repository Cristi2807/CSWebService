package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
)

var publicKey *rsa.PublicKey
var privateKey *rsa.PrivateKey

func getPublicKey(w http.ResponseWriter, r *http.Request) {

	publicKeyMarshalled, _ := json.Marshal(*publicKey)

	w.WriteHeader(http.StatusAccepted)
	w.Header().Set("Content-Type", "application/json")
	w.Write(publicKeyMarshalled)
}

func startServer() {
	router := mux.NewRouter()

	router.HandleFunc("/publicKey", getPublicKey).Methods(http.MethodGet)

	router.HandleFunc("/users", createAccount).Methods(http.MethodPost)
	router.HandleFunc("/users", loginAccount).Methods(http.MethodPut)
	router.HandleFunc("/users", logoutAccount).Methods(http.MethodDelete)

	router.HandleFunc("/", handleRequestCyphers).Methods(http.MethodPost)

	fmt.Println("Server started")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}

}

func createAccount(w http.ResponseWriter, r *http.Request) {

	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	decMessage, _ := DecryptOAEP(sha256.New(), rand.Reader, privateKey, body, nil)

	type Cell struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var cell Cell

	json.Unmarshal(decMessage, &cell)

	if _, ok := users[cell.Username]; !ok {

		passHash, _ := HashPassword(cell.Password)

		users[cell.Username] = User{
			PasswordHash: passHash,
		}

		saveUsers()

		fmt.Println("New account", cell, "created!")

		w.WriteHeader(http.StatusCreated)
		return
	}

	dataMarshalled, _ := json.Marshal(
		struct {
			Error string `json:"error"`
		}{
			"Username taken!",
		},
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	w.Write(dataMarshalled)
}

func loginAccount(w http.ResponseWriter, r *http.Request) {

	tokenStr := r.Header.Get("OTPToken")

	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	decMessage, _ := DecryptOAEP(sha256.New(), rand.Reader, privateKey, body, nil)

	type Cell struct {
		Username  string        `json:"username"`
		Password  string        `json:"password"`
		OTPPass   string        `json:"OTPPass"`
		PublicKey rsa.PublicKey `json:"publicKey"`
	}

	var cell Cell

	json.Unmarshal(decMessage, &cell)

	if tokenStr != "" && ValidateOTPToken(tokenStr, cell.OTPPass) == nil {
		fmt.Println("Account", cell.Username, "is logged in!")

		tokenString, _ := GenerateJWT(cell.Username, "user")

		cipherText, _ := EncryptOAEP(sha256.New(), rand.Reader, &cell.PublicKey, []byte(tokenString), nil)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(cipherText)

		return
	}

	if tokenStr != "" {
		err := ValidateOTPToken(tokenStr, cell.OTPPass)

		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				err.Error(),
			},
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return
	}

	if _, ok := users[cell.Username]; !ok {
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

		return
	}

	if CheckPasswordHash(cell.Password, users[cell.Username].PasswordHash) == false {
		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Wrong Password!",
			},
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return
	}

	if tokenStr == "" {
		tokenString := GenerateOTPToken(cell.Username)

		cipherText, _ := EncryptOAEP(sha256.New(), rand.Reader, &cell.PublicKey, []byte(tokenString), nil)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write(cipherText)

		return
	}

}

func logoutAccount(w http.ResponseWriter, r *http.Request) {

	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	decMessage, _ := DecryptOAEP(sha256.New(), rand.Reader, privateKey, body, nil)

	type Cell struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var cell Cell

	json.Unmarshal(decMessage, &cell)

	if _, ok := users[cell.Username]; !ok {
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

		return
	}

	if CheckPasswordHash(cell.Password, users[cell.Username].PasswordHash) == false {
		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Wrong Password!",
			},
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return
	}

	fmt.Println("Account", cell.Username, "is logged out!")

	w.WriteHeader(http.StatusOK)
}

func handleRequestCyphers(w http.ResponseWriter, r *http.Request) {

	tokenStr := r.Header.Get("Token")

	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	decMessage, _ := DecryptOAEP(sha256.New(), rand.Reader, privateKey, body, nil)

	type Cell struct {
		CypherRequest Request       `json:"cypherRequest"`
		PublicKey     rsa.PublicKey `json:"publicKey"`
	}

	var cell Cell

	json.Unmarshal(decMessage, &cell)

	if !checkLogin(w, tokenStr, cell.CypherRequest.Cypher) {
		return
	}

	cipherText, _ := EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&cell.PublicKey,
		[]byte(getCypherUsage(cell.CypherRequest)),
		nil)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(cipherText)
}

func main() {

	privateKey, publicKey = generateKeyPair(2048)

	loadUsers()

	go startServer()

	select {}
}

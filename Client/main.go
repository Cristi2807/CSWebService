package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

var publicKey *rsa.PublicKey
var privateKey *rsa.PrivateKey
var serverPublicKey *rsa.PublicKey
var TOKEN string

func saveToken() {
	file, _ := json.MarshalIndent(TOKEN, "", " ")

	_ = os.WriteFile("token.json", file, 0644)
}

func loadToken() {
	file, _ := os.ReadFile("token.json")

	_ = json.Unmarshal(file, &TOKEN)
}

func createAccount(userName string, password string) {

	type Cell struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var cell Cell

	cell.Username = userName
	cell.Password = password

	cellMarshalled, _ := json.Marshal(cell)

	cipherText, _ := EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, cellMarshalled, nil)

	rBody := bytes.NewBuffer(cipherText)

	req, _ := http.Post("http://localhost:8080/users", "application/json", rBody)

	if req.StatusCode == http.StatusCreated {
		fmt.Println("Account", cell, "created successfully!")
	} else {

		type Cell struct {
			Error string `json:"error"`
		}

		var cellError Cell

		json.NewDecoder(req.Body).Decode(&cellError)

		fmt.Println(cellError)
	}

}

func loginAccount(userName string, password string) {

	type Cell struct {
		Username  string        `json:"username"`
		Password  string        `json:"password"`
		PublicKey rsa.PublicKey `json:"publicKey"`
	}

	var cell Cell

	cell.Username = userName
	cell.Password = password
	cell.PublicKey = *publicKey

	cellMarshalled, _ := json.Marshal(cell)

	cipherText, _ := EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, cellMarshalled, nil)

	rBody := bytes.NewBuffer(cipherText)

	req, _ := http.NewRequest(http.MethodPut, "http://localhost:8080/users", rBody)
	resp, _ := http.DefaultClient.Do(req)

	if resp.StatusCode == http.StatusOK {

		body, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		decMessage, _ := DecryptOAEP(sha256.New(), rand.Reader, privateKey, body, nil)

		TOKEN = string(decMessage)

		saveToken()

		fmt.Println("Account", cell.Username, "logged in successfully!")
	} else {

		type Cell struct {
			Error string `json:"error"`
		}

		var cellError Cell

		json.NewDecoder(resp.Body).Decode(&cellError)

		fmt.Println(cellError)
	}

}

func logoutAccount(userName string, password string) {

	type Cell struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var cell Cell

	cell.Username = userName
	cell.Password = password

	cellMarshalled, _ := json.Marshal(cell)

	cipherText, _ := EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, cellMarshalled, nil)

	rBody := bytes.NewBuffer(cipherText)

	req, _ := http.NewRequest(http.MethodDelete, "http://localhost:8080/users", rBody)
	resp, _ := http.DefaultClient.Do(req)

	if resp.StatusCode == http.StatusOK {

		TOKEN = ""

		saveToken()

		fmt.Println("Account", cell.Username, "logged out successfully!")
	} else {

		type Cell struct {
			Error string `json:"error"`
		}

		var cellError Cell

		json.NewDecoder(resp.Body).Decode(&cellError)

		fmt.Println(cellError)
	}

}

func sendRequestCypher(cypherType CypherType, method string, message string, key int, strKey string) string {

	type Cell struct {
		CypherRequest Request       `json:"cypherRequest"`
		PublicKey     rsa.PublicKey `json:"publicKey"`
	}

	var cell Cell

	var cypherReq Request

	cell.PublicKey = *publicKey

	cypherReq.Cypher = cypherType
	cypherReq.Text = message
	cypherReq.Key = key
	cypherReq.Method = method
	cypherReq.StringKey = strKey

	cell.CypherRequest = cypherReq

	cellMarshalled, _ := json.Marshal(cell)

	cipherText, _ := EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, cellMarshalled, nil)

	rBody := bytes.NewBuffer(cipherText)

	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8080", rBody)
	req.Header.Set("Token", TOKEN)
	resp, _ := http.DefaultClient.Do(req)

	if resp.StatusCode == http.StatusOK {

		body, _ := io.ReadAll(resp.Body)
		defer req.Body.Close()

		decMessage, _ := DecryptOAEP(sha256.New(), rand.Reader, privateKey, body, nil)

		return string(decMessage)

	} else {
		type Cell struct {
			Error string `json:"error"`
		}

		var cellError Cell

		json.NewDecoder(resp.Body).Decode(&cellError)

		fmt.Println(cellError)
	}

	return ""
}

func main() {

	loadToken()

	privateKey, publicKey = generateKeyPair(2048)

	getPublicKey()

	//createAccount("cristi", "12345678")

	//loginAccount("cristi", "12345678")

	//logoutAccount("cristi", "12345678")

	fmt.Println(sendRequestCypher(
		Vigenere,
		"decrypt",
		"GBTDXGBUXQFFNDPRFMGFIJFURP",
		0,
		"NULLPointer",
	))

}

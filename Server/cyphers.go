package main

import "strings"

type CypherType string

const (
	Caesar = CypherType(rune(iota))
	CaesarPerm
	Vigenere
)

type Request struct {
	Cypher    CypherType `json:"cypher"`
	Text      string     `json:"text"`
	Method    string     `json:"method"`
	Key       int        `json:"key"`
	StringKey string     `json:"stringKey"`
}

func getCypherUsage(cypherRequest Request) string {

	switch cypherRequest.Cypher {
	case Caesar:
		switch cypherRequest.Method {
		case "encrypt":
			return encryptCaesar(cypherRequest.Text, cypherRequest.Key)
		case "decrypt":
			return decryptCaesar(cypherRequest.Text, cypherRequest.Key)
		}
	case CaesarPerm:
		switch cypherRequest.Method {
		case "encrypt":
			return encryptCaesarPerm(cypherRequest.Text, cypherRequest.Key, cypherRequest.StringKey)
		case "decrypt":
			return decryptCaesarPerm(cypherRequest.Text, cypherRequest.Key, cypherRequest.StringKey)
		}

	case Vigenere:
		switch cypherRequest.Method {
		case "encrypt":
			return encryptVigenere(cypherRequest.Text, cypherRequest.StringKey)
		case "decrypt":
			return decryptVigenere(cypherRequest.Text, cypherRequest.StringKey)
		}

	}

	return ""
}

func encryptCaesar(text string, key int) string {

	var encryptedMessage string

	text = strings.ToUpper(text)

	for _, i1 := range text {
		if i1 != 32 && i1 >= 65 && i1 <= 90 {
			encryptedMessage += string(rune(mod(int(i1)-65+key, 26) + 65))
		}
	}

	return encryptedMessage
}

func decryptCaesar(text string, key int) string {

	var decryptedMessage string

	text = strings.ToUpper(text)

	for _, i1 := range text {
		if i1 != 32 {
			decryptedMessage += string(rune(mod(int(i1)-65-key, 26) + 65))
		}
	}

	return decryptedMessage
}

func encryptCaesarPerm(text string, key int, strKey string) string {

	strKey = strings.ToUpper(strKey)
	text = strings.ToUpper(text)

	var encryptedMessage string

	// Obtain permutation key unique letters
	for i := 0; i < len(strKey); i++ {
		charReplaced := strKey[i]
		strKey = strings.ReplaceAll(strKey, string(strKey[i]), "*")
		strKey = strKey[:i] + string(charReplaced) + strKey[i+1:]
	}
	strKey = strings.ReplaceAll(strKey, "*", "")

	alphabet := strKey

	//Fill the remaining letters of alphabet
	for i := 65; i < 91; i++ {
		if strings.Index(alphabet, string(rune(i))) == -1 {
			alphabet = alphabet + string(rune(i))
		}
	}

	for _, i2 := range text {
		if i2 != 32 {
			encryptedMessage += string(alphabet[mod(strings.Index(alphabet, string(i2))+key, 26)])
		}
	}

	return encryptedMessage
}

func decryptCaesarPerm(text string, key int, strKey string) string {

	strKey = strings.ToUpper(strKey)
	text = strings.ToUpper(text)

	var decryptedMessage string

	// Obtain permutation key unique letters
	for i := 0; i < len(strKey); i++ {
		charReplaced := strKey[i]
		strKey = strings.ReplaceAll(strKey, string(strKey[i]), "*")
		strKey = strKey[:i] + string(charReplaced) + strKey[i+1:]
	}
	strKey = strings.ReplaceAll(strKey, "*", "")

	alphabet := strKey

	//Fill the remaining letters of alphabet
	for i := 65; i < 91; i++ {
		if strings.Index(alphabet, string(rune(i))) == -1 {
			alphabet = alphabet + string(rune(i))
		}
	}

	for _, i2 := range text {
		if i2 != 32 {
			decryptedMessage += string(alphabet[mod(strings.Index(alphabet, string(i2))-key, 26)])
		}
	}

	return decryptedMessage

}

func encryptVigenere(text string, strKey string) string {

	text = strings.ToUpper(text)
	text = strings.ReplaceAll(text, " ", "")
	strKey = strings.ToUpper(strKey)

	var encryptedMessage string

	for i, i1 := range text {
		if i1 != 32 && i1 >= 65 && i1 <= 90 {
			encryptedMessage += string(rune(mod(int(i1)-65+int(strKey[mod(i, len(strKey))])-65, 26) + 65))
		}
	}

	return encryptedMessage
}

func decryptVigenere(text string, strKey string) string {

	text = strings.ToUpper(text)
	strKey = strings.ToUpper(strKey)

	var decryptedMessage string

	for i, i1 := range text {
		decryptedMessage += string(rune(mod(int(i1)-int(strKey[mod(i, len(strKey))]), 26) + 65))
	}

	return decryptedMessage
}

func mod(a int, b int) int {
	return (b + (a % b)) % b
}

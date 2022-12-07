package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"hash"
	"io"
	rn "math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type User struct {
	PasswordHash string `json:"passwordHash"`
}

type JWTClaim struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var users = make(map[string]User)

var keyJWT = []byte("$2a$14$GGZuMlctthtXauMvN3YQweZGvJhPPLx6wcUjJGOxTOnAOB9pwD/a6")

var keyOTP = []byte("14$GGZuMlctthtXauMvN3YQweZGvJhPPLx6wcUjJGOxTOnAOB9pw")

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

func checkLogin(w http.ResponseWriter, tokenStr string) bool {

	if tokenStr == "" {
		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Please sign in or sign up!",
			},
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(dataMarshalled)

		return false
	}

	err := ValidateToken(tokenStr)

	if err != nil {

		if strings.Index(err.Error(), "token is expired by") != -1 {
			dataMarshalled, _ := json.Marshal(
				struct {
					Error string `json:"error"`
				}{
					"Current session expired. Log in again!",
				},
			)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			w.Write(dataMarshalled)

			return false
		}

		dataMarshalled, _ := json.Marshal(
			struct {
				Error string `json:"error"`
			}{
				"Token corrupted. Log in again!",
			},
		)

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

//JSON Web Token

func GenerateJWT(username string) (tokenString string, err error) {
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &JWTClaim{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(keyJWT)
	return
}

func ValidateToken(signedToken string) (err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return keyJWT, nil
		},
	)
	if err != nil {
		return
	}
	claims, ok := token.Claims.(*JWTClaim)

	if !ok {
		err = errors.New("couldn't parse claims")
		return
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return
	}
	return
}

// OTP Token

type OTPClaim struct {
	Username  string `json:"username"`
	ExpiresAt int64  `json:"expiresAt"`
}

func GenerateOTPToken(username string) (tokenString string) {

	var claims OTPClaim

	claims.Username = username
	claims.ExpiresAt = time.Now().Add(time.Minute).Unix()

	claimsMarshalled, _ := json.Marshal(claims)

	claimsBase64 := base64.StdEncoding.EncodeToString(claimsMarshalled)

	var bs []byte

	s1 := rn.NewSource(time.Now().UnixNano())
	r1 := rn.New(s1)
	randomInt := 100000 + r1.Intn(900000)
	fmt.Println("OTP for user", claims.Username, "is", randomInt)

	bs = append(bs, claimsMarshalled...)
	bs = append(bs, []byte(strconv.Itoa(randomInt))...)
	bs = append(bs, keyOTP...)

	h := sha256.New()
	h.Write(bs)

	bs1 := h.Sum(nil)

	bsBase64 := base64.StdEncoding.EncodeToString(bs1)

	return claimsBase64 + "." + bsBase64
}

func ValidateOTPToken(signedToken string, passcode string) (err error) {

	claimsBase64 := signedToken[0:strings.Index(signedToken, ".")]
	hashBase64 := signedToken[(strings.Index(signedToken, ".") + 1):]

	var claims OTPClaim

	claimsMarshalled, _ := base64.StdEncoding.DecodeString(claimsBase64)

	json.Unmarshal(claimsMarshalled, &claims)

	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return
	}

	var bs []byte

	bs = append(bs, claimsMarshalled...)
	bs = append(bs, []byte(passcode)...)
	bs = append(bs, keyOTP...)

	h := sha256.New()
	h.Write(bs)

	bs1 := h.Sum(nil)

	bsBase64 := base64.StdEncoding.EncodeToString(bs1)

	if hashBase64 != bsBase64 {
		err = errors.New("OTP invalid")
		return
	}

	return nil
}

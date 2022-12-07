# Cryptography and Security Laboratory Work Nr.5

### Course: Cryptography & Security
### Author: Boris Cristian

----

## Objectives:

1. Take what I have at the moment from previous laboratory works and put it in a web service.
2. My services should have implemented basic authentication and MFA.
3. My web app needs to simulate user authorization.
4. As a service my application provides, I should use the classical ciphers.


## Implementation description

### Secure Web Service

In my web service I implement several endpoints which authenticate, authorize users and make use of classical ciphers returning encrypted/decrypted text. 

#### Creating an account
By creating an account, the client is doing a POST request to /users route of server, encrypting the username and password JSON using server's public key.
Once the server decrypts the JSON with its private key, it checks whether a user with such username already exists, and if not then it adds in his local 
users.json the username and passwordHash.

#### Log in and 2FA(OTP)
In order to log in, client makes a PUT request to /users route of server, the request containing the user's username and password. 
Once again, the request body is encrypted with server public key, and the response is encrypted with client public key. 
If the username and password are correct, then a 1-minute-valid-token is generated, containing the username, time when it expires in Base64, 
and the hash of the username+ expireTime + 6-digit-code + serverSignature.
The OTP Token is sent to the client, and now the user is making another request containing the 6-digit-code together with the OTPToken. 
The server is now checking whether the expireTime of OTPToken is not less than time.Now, and if so , it further checks whether the hash of the 
username+expireTime+6-digit-codeEnteredbyUser+serverSignature is the same as in the Token sent earlier. If so, it means that the OTP entered was correct.

Now, as a response the user gets a JWT Token active for a session of 30mins, containing the expireTime, username and role.

#### Using Classical Cyphers and Authorization
All the requests from user are again encrypted, and they contain the JWT Token in the header, and in the body the user's JSON on cyphers like: cypherType,
message,method (encrypt/decrypt), key. Once server is serving the client, it firstly checks the validity of the JWT Token (including expireTime, signature),
and then proceeds to the request itself. In the current web service, the Authorization was hard to show, but I implemented it as the normal user cannot make use
of Caesar with Permuation Cypher. It means that on checking the JWT Token, if the role is "user", and cypherType is CaesarPerm then the response to user is 
StatusForbidden, else the request is handled by functions that indeed encrypt or decrypt data.

In this way, I achieved the isolation of the functions that encrypt/decrypt data properly.

### Code Snippets

#### 2FA One-Time-Passcode 

```go
func GenerateOTPToken(username string) (tokenString string) {

...

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

...

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
```

#### Implementing Authentication

```go
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
```

#### Implementing Authorization

```go
token, _ := jwt.ParseWithClaims(
		tokenStr,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return keyJWT, nil
		},
	)

	claims, _ := token.Claims.(*JWTClaim)

	if claims.Role == "user" && cypherType == CaesarPerm {
		w.WriteHeader(http.StatusForbidden)

		return false

	}
```

## Conclusions / Screenshots / Results

This Laboratory Work Nr.5 was indeed interesting and important for me, as I studied deeper about JSON Web Token structure and usage, and I implemented
it in my API. After I understood how JWT works, I created my own model of 2FA with OTP, also using Token with claims and hash+ serverSignature.
Using hash for storing users' password on server-side was a good idea that I had from the beginning. Encrypting the requests' body
with Public Key Cryptography was necessary in my opinion, in order not to expose my app to Man-in-the-Middle attack. This way, login credentials together 
with Classical Cyphers requests are encrypted, so only client and server can make use of the information sent.
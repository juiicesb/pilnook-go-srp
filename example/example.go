package main

import (
	"crypto/subtle"
	"fmt"
	"github.com/juiicesb/pilnook-go-srp"
)

func main() {
	bits := 1024
	// password
	pass := []byte("$Qazwsx12*")
	// username
	i := []byte("admin@admin.com")

	// Random Salt
	s, err := srp.New(bits)
	if err != nil {
		panic(err)
	}
	// Password Verifier
	v, err := s.Verifier(i, pass)
	if err != nil {
		panic(err)
	}

	ih, vh := v.Encode()

	// Store ih, vh in durable storage
	fmt.Printf("Verifier Store (Blake-2b-256):\n (ih Username Hash) %s => (vh PW Verifier) %s\n\n", ih, vh)

	c, err := s.NewClient(i, pass)
	if err != nil {
		panic(err)
	}

	// client credentials (public key and identity) to send to server
	creds := c.Credentials()

	fmt.Println("Client send credentials to server\n")

	// CRED ARE SEND TO SERVER

	fmt.Printf("Client Begin; <I, A> --> Server:\n (I Username : A g^a %% N) %s\n\n", creds)

	// SERVER SIDE

	fmt.Println("Server receives data\n")

	// Begin the server by parsing the received client public key and identity.
	// ih: username hash
	// A: g^a % N
	ih, A, err := srp.ServerBegin(creds)
	if err != nil {
		panic(err)
	}

	fmt.Println("Server lookups user in DB and fetch salt, verifier, etc:\n")

	// Now, pretend to lookup the user db using "I" as the key and
	// fetch salt, verifier etc.
	s, v, err = srp.MakeSRPVerifier(vh)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Server Begin; <v, A>:\n   %s\n   %x\n\n", vh, A.Bytes())
	srv, err := s.NewServer(v, A)
	if err != nil {
		panic(err)
	}

	// Generate the credentials to send to client
	fmt.Println("Server generates credentials and sends it to the client\n")
	creds = srv.Credentials()

	// Send the server public key and salt to client
	fmt.Printf("Server Begin; <s, B> --> Client:\n   %s\n\n", creds)

	// client processes the server creds and generates
	// a mutual authenticator; the authenticator is sent
	// to the server as proof that the client derived its keys.
	fmt.Println("client processes the server creds and generates")
	fmt.Println("a mutual authenticator; the authenticator is sent")
	fmt.Println("to the server as proof that the client derived its keys.\n")
	cauth, err := c.Generate(creds)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Client Authenticator: M --> Server\n   %s\n\n", cauth)

	// Receive the proof of authentication from client
	fmt.Println("Server receive the proof of authentication from client, process it and sends back a proof of authentication\n")
	proof, ok := srv.ClientOk(cauth)
	if !ok {
		panic("client auth failed")
	}

	// Send proof to the client
	fmt.Printf("Server Authenticator: M' --> Client\n   %s\n\n", proof)

	// Verify the server's proof
	fmt.Println("Client receive the proof of authentication from Server and process it\n")
	if !c.ServerOk(proof) {
		panic("server auth failed")
	}

	// Now, we have successfully authenticated the client to the
	// server and vice versa.

	fmt.Println("Now, we have successfully authenticated the client to the server and vice versa\n")

	kc := c.RawKey()
	ks := srv.RawKey()

	if 1 != subtle.ConstantTimeCompare(kc, ks) {
		panic("Keys are different!")
	}

	fmt.Printf("Client Key: %x\nServer Key: %x\n", kc, ks)
}

// EOF

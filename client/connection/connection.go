// this part of the program ahndles all the connection stuff,
// there is a lot going on here
package connection

import (
	"bufio"
	"bytes"
	"chat/client/aesEncrypt"
	"chat/client/clientRsa"
	"chat/client/diffie"
	"chat/client/keyStorage"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// construct the struct so every message look the same and can be converted into json
type msg struct {
	SessionId  string   `json:"SessionId"` // the yellow on the right is the name in json
	From       string   `json:"from"`
	To         string   `json:"to"`
	Time       string   `json:"timeSent"`
	Version    string   `json:"version"`
	System     int      `json:"system"`
	Value      string   `json:"value"`
	HashString string   `json:"hashString"`
	Hash       [32]byte `json:"hash"`
	Signature  []byte   `json:"Signature"`
}

// this part defines all the types of the global variables
var (
	sender                     string
	receiver                   string
	initDiffie                 bool
	privKey                    string
	diffiePrivKey              *big.Int
	diffieOtherPubKey          *big.Int
	readBuff                   = make([]byte, 4096)
	diffieSharedSecret         *big.Int
	diffieSharedSecretBytes    []byte
	oldDiffieSharedSecret      *big.Int
	oldDiffieSharedSecretBytes []byte
	diffiePrime                *big.Int
	SessionId                  *big.Int
	privateRsa                 *rsa.PrivateKey
)

// this function reads the message from the terminal and sends it to the server
func readMessage(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	scanner := bufio.NewScanner(os.Stdin)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)

	go func() {
		<-sigChan
		currentTime := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
		constructMessage(12, "close conn", conn, currentTime)
	}()

	for scanner.Scan() {
		userMessage := scanner.Text()

		currentTime := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
		constructMessage(0, userMessage, conn, currentTime)
	}
}

// this function combines all the the data into a struct
func constructMessage(system int, content string, conn net.Conn, time string) {
	if len(diffieSharedSecretBytes) >= 1 {
		var err error
		content, err = aesEncrypt.EncryptAES(diffieSharedSecretBytes, content)
		if err != nil {
			log.Fatal("Error encrypting msg")
		}
	}

	input := fmt.Sprint(sender, receiver, time, "1.0", system, content)
	hash := sha256.Sum256([]byte(input))
	hashString := hex.EncodeToString(hash[:])

	signedHash := signHash(hash[:])

	var message msg
	if len(SessionId.String()) >= 1 {
		message = msg{
			SessionId:  SessionId.String(),
			From:       sender,
			To:         receiver,
			Time:       time,
			Version:    "1.0",
			System:     system,
			Value:      content,
			HashString: hashString,
			Hash:       hash,
			Signature:  signedHash,
		}
	} else {
		message = msg{
			SessionId:  SessionId.String(),
			From:       sender,
			To:         receiver,
			Time:       time,
			Version:    "1.0",
			System:     system,
			Value:      content,
			HashString: hashString,
			Hash:       hash,
			Signature:  signedHash,
		}

	}
	encodedMessage, err := json.Marshal(message) // here the struct is getting converted into json
	if err != nil {
		fmt.Println("Error while convering to json: ", err)
		return
	}

	sendMessage(conn, string(encodedMessage))
}

// this simpl efunction send the message to the server
func sendMessage(conn net.Conn, message string) {
	fmt.Fprintln(conn, message)
}

// this function gets the messages from the connection if needed it needs to be decrypted form aes-cbc
func getMessage(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		message := scanner.Text()
		var receivedMsg msg

		// Decode the JSON data into the struct
		err := json.Unmarshal([]byte(message), &receivedMsg)
		if err != nil {
			fmt.Println("Error decoding JSON:", err)
			return
		}

		check := hashCheck(receivedMsg)

		if check {
			if receivedMsg.System >= 20 {
				sysMsgHandler(receivedMsg, conn)
			} else {
				if len(diffieSharedSecretBytes) >= 1 { // if there is a shared secret it knows it needs to decrypt the message
					value, err := aesEncrypt.DecryptAES(diffieSharedSecretBytes, receivedMsg.Value)
					if err != nil {
						log.Fatal("Error decrypting msg")
					}
					fmt.Println(value)
				} else {
					fmt.Println(receivedMsg.Value)
				}

			}
		} else {
			log.Fatal("integrity error")
		}

	}
}

// this function initialises the user when it knows enough it send it to the server
func initUser(conn net.Conn) {
	fmt.Print("Give up yout username: ")
	fmt.Scanln(&sender)
	fmt.Println("You are:", sender)

	fmt.Print("Who do you want to send to?: ")
	fmt.Scanln(&receiver)
	fmt.Println("You are sending to: ", receiver)

	currentTime := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))

	rsaExcange(conn)
	constructMessage(11, privKey, conn, currentTime)

	info := conn.LocalAddr().String()
	constructMessage(10, info, conn, currentTime)
}

// this function lets you connect to the server and initates the get and read message function
func StartConn() {
	fmt.Print("Enter the address to connect (e.g., 123.123.123.123:8080): ")
	var address string
	fmt.Scanln(&address)

	var wg sync.WaitGroup

	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
	} else {
		fmt.Println("connected to:", conn.RemoteAddr())
		initUser(conn)
		defer conn.Close()

		wg.Add(2)
		go getMessage(conn, &wg)
		go readMessage(conn, &wg)
	}

	// Wait for both goroutines to finish
	wg.Wait()
}

// this function hanldes the diffie hellman excange between the two clients
func diffieExchange(receivedMsg msg, conn net.Conn, init bool, read bool) {
	if init {
		currentTime := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
		var randomBits *big.Int
		var err error
		for {

			randomBits, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if err != nil {
				log.Fatal(err)
			}

			randomBitsBytes, err := bigIntToBytes(randomBits)
			if err != nil {
				log.Fatal("could not convert to byte")
			}

			if !keyStorage.KeyExists("./ping", receiver, string(randomBitsBytes)) {
				break
			}
		}
		SessionId = randomBits

		constructMessage(30, "Hello, I init diffie, next message p, g and pubKey", conn, currentTime)
		prime, g, err := diffie.GeneratePrime()
		if err != nil {
			log.Fatal("Error while genereting prime or g: ", err)
		}
		private := diffie.GeneratePrivateKey(prime)
		diffiePrivKey = private
		diffiePrime = prime
		publicKey := diffie.GeneratePublicKey(diffiePrivKey, prime, g)
		messagePrimeG := fmt.Sprintf("Prime: %s, g: %s, publicKey: %s", prime, g, publicKey)
		currentTime = fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
		constructMessage(30, messagePrimeG, conn, currentTime)
	} else if read {
		tokens := strings.Split(receivedMsg.Value, ":")

		diffieOtherPubKey = convertToBigInt(tokens[1])
		diffieSharedSecret = diffie.CalcShareKey(diffieOtherPubKey, diffiePrivKey, diffiePrime)
		key, err := bigIntToBytes(diffieSharedSecret)
		if err != nil {
			log.Fatal("error while transforming encryption key")
		}
		diffieSharedSecretBytes = key
		generateSHA256(diffieSharedSecretBytes)

		err = keyStorage.UploadData("./ping", receiver, SessionId.String(), diffieSharedSecret.String())
		if err != nil {
			log.Fatal(err)
		}
	} else {
		tokens := strings.Split(receivedMsg.Value, ",")

		var finalTokens []string

		for i := range tokens {
			finalToken := strings.Split(tokens[i], ":")
			finalTokens = append(finalTokens, finalToken[1])

		}
		diffiePrime = convertToBigInt(finalTokens[0])
		g := convertToBigInt(finalTokens[1])
		diffieOtherPubKey = convertToBigInt(finalTokens[2])

		diffiePrivKey = diffie.GeneratePrivateKey(diffiePrime)
		pubKey := diffie.GeneratePublicKey(diffiePrivKey, diffiePrime, g)

		content := fmt.Sprintf("Public key: %s", pubKey)
		currentTime := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
		constructMessage(31, content, conn, currentTime)
		diffieSharedSecret = diffie.CalcShareKey(diffieOtherPubKey, diffiePrivKey, diffiePrime)
		key, err := bigIntToBytes(diffieSharedSecret)
		if err != nil {
			log.Fatal("error while transforming encryption key")
		}
		diffieSharedSecretBytes = key
		generateSHA256(diffieSharedSecretBytes)

		err = keyStorage.UploadData("./ping", receiver, SessionId.String(), diffieSharedSecret.String())
		if err != nil {
			log.Fatal(err)
		}
	}

}

// this function excanges the rsa certificate with the server if it does not exist yet
// there is one per receiver
func rsaExcange(conn net.Conn) {
	file := fmt.Sprintf("./%s.rsa", sender)
	if _, err := os.Stat(file); err == nil {
		// file exists
		f, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}

		defer f.Close()

		n, err := f.Read(readBuff)
		if err != nil {
			log.Fatal(err)
		}
		privKey = string(readBuff[:n])

		file := fmt.Sprintf("./%s.rsa", sender)
		privateRsa = clientRsa.ReadPrivateKeyFromFile(file)
	} else {
		pub, private := clientRsa.GenerateRsa(sender)
		pubString := fmt.Sprintf("%s", pub)
		privKey = pubString
		privateRsa = private
	}
}

// this function handles all the system messages
func sysMsgHandler(receivedMsg msg, conn net.Conn) {
	if receivedMsg.System >= 20 {
		pubKey := clientRsa.ReadPublicKeyFromFile("./server.pub")
		wrong := verifySignature(pubKey, receivedMsg.Hash[:], receivedMsg.Signature)
		if wrong == nil {
			if receivedMsg.System == 20 {
				fmt.Println("the following message is unread:")
				if len(receivedMsg.SessionId) >= 1 {
					var err error
					oldDiffieSharedSecretBytes, err = keyStorage.GetValueForKeyInBucket("./ping", receiver, receivedMsg.SessionId)
					if err != nil {
						log.Fatal(err)
					}
					oldDiffieSharedSecret = convertToBigInt(string(oldDiffieSharedSecretBytes))
					content, err := aesEncrypt.DecryptAES(oldDiffieSharedSecretBytes, receivedMsg.Value)
					if err != nil {
						log.Fatal("Error encrypting msg")
					}
					fmt.Println(content)
				}

				if receivedMsg.System <= 9 {
					fmt.Println("received:")
					fmt.Println(receivedMsg.Value)
				}
			}
		} else {
			fmt.Println("!!! WARNING: someone tried to impersonate the server !!!")
		}
		if receivedMsg.System == 21 {
			diffieExchange(receivedMsg, conn, true, false)
		}

	} else if receivedMsg.System == 30 && strings.HasPrefix(receivedMsg.Value, "Prime:") {
		diffieExchange(receivedMsg, conn, false, false)
	} else if receivedMsg.System == 31 {
		diffieExchange(receivedMsg, conn, false, true)
	}
}

// this function converts a string into a big int
func convertToBigInt(number string) *big.Int {
	number = strings.Trim(number, " ")
	n := new(big.Int)
	n, ok := n.SetString(number, 10)
	if !ok {
		log.Fatal(ok)
	}
	return n
}

// this function converts a big in into bytes
func bigIntToBytes(value *big.Int) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(value)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// this function converts the data into the global function
func generateSHA256(data []byte) error {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	hashInBytes := hash.Sum(nil)

	diffieSharedSecretBytes = hashInBytes

	return nil
}

// this function lets you sign hashes with rsa
func signHash(hash []byte) []byte {
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateRsa, crypto.SHA256, hash)
	if err != nil {
		log.Fatal(err)
	}

	return signature
}

// this function veryfies the signature using rsa
func verifySignature(publicKey *rsa.PublicKey, hash, signature []byte) error {
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
}

// this function checks the hashes of a messag to check for a possible man in the middle attack
func hashCheck(received msg) bool {
	input := fmt.Sprint(received.From, received.To, received.Time, received.Version, received.System, received.Value)
	hash := sha256.Sum256([]byte(input))
	hashString := hex.EncodeToString(hash[:])

	if hashString != received.HashString {
		log.Print("Hashes do not match, integrity error")
		fmt.Println("own hash: ", hashString)
		fmt.Println("read string: ", received.HashString)
		return false
	} else {
		return true
	}
}

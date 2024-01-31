// this part of the program handles all the messaging part
package messageHandeler

import (
	"bufio"
	"chat/server/db"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// the same struct as in the client side for pure consistancy
type msg struct {
	SessionId  string   `json:"SessionId"`
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

// small ini mini struct to keep track of the user and their ip
type client struct {
	User string
	Ip   string
}

// define all the global vars
var (
	connected    = make(map[int]net.Conn)
	readBuff     = make([]byte, 4096)
	hostSender   client
	hostReceiver client
	privKey      *rsa.PrivateKey
)

// this function handles the connection between the server and the client and client
func HandleConnection(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	privKey = readPrivKey()

	// Read the entire JSON string from the connection
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		message := scanner.Text()

		// Create a new instance of the msg struct to decode into
		var receivedMsg msg

		// Decode the JSON data into the struct
		err := json.Unmarshal([]byte(message), &receivedMsg)
		if err != nil {
			fmt.Println("Error decoding JSON:", err)
			return
		}

		if receivedMsg.System != 0 {
			println("Got system message")
			if receivedMsg.System == 12 {
				fmt.Println("Client requested to close the connection.")
				id := db.GetUserId(receivedMsg.From)
				delete(connected, id)
				return
			} else {
				handleSystemMessage(receivedMsg, conn)
			}
		} else {

			hash := sha256.New()
			hash.Write([]byte(receivedMsg.From))
			hashInBytes := hash.Sum(nil)
			hashString := hex.EncodeToString(hashInBytes)

			pubKey := db.GetPubKey(hashString)

			err = verifySignature(pubKey, receivedMsg.Hash[:], receivedMsg.Signature)

			if err == nil {
				fmt.Println("verified")
				receiverId := db.GetUserId(receivedMsg.To)

				val, ok := connected[receiverId]
				if ok {
					fmt.Println("user Found")
					sendThru(val, receivedMsg)
				} else {
					db.UploadMsg(db.Msg(receivedMsg))
				}
				// id := db.GetUserId(receivedMsg.To)
				// sendThru(connected[id], receivedMsg)
				fmt.Printf(" %+v\n", receivedMsg.Value)
			} else {
				fmt.Println("Not the right person")
			}
		}
	}

	// Check for any errors during scanning
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading:", err)
	}
}

// this function send the messages thru to the other 'receiving' client
func sendThru(conn net.Conn, message msg) {
	encodedMessage, err := json.Marshal(message)
	if err != nil {
		fmt.Println("Error while convering to json: ", err)
		return
	}

	fmt.Fprintln(conn, string(encodedMessage))
}

// name speaks for itself but this function handles the system messages
func handleSystemMessage(messageReceived msg, conn net.Conn) {
	if messageReceived.System == 10 {
		id := db.GetUserId(messageReceived.From)

		fmt.Println("Got id: ", id)

		connected[id] = conn

		unreadMessage := db.CheckMsg(messageReceived.From)

		if unreadMessage {
			messages := db.GetMessage(messageReceived.From)

			time := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
			content := "You have unread messages, next messages will be the saved ones:"

			input := fmt.Sprint("server", messageReceived.From, time, "1.0", 20, content)
			hash := sha256.Sum256([]byte(input))
			hashString := hex.EncodeToString(hash[:])

			sign := signHash(hash[:])

			unread := msg{
				From:       "server",
				To:         messageReceived.From,
				Time:       time,
				Version:    "1.0",
				System:     20,
				Value:      content,
				Hash:       hash,
				HashString: hashString,
				Signature:  sign,
			}

			sendThru(conn, unread)

			for _, messageInList := range messages {
				sendThru(conn, msg(messageInList))
			}

			db.DeleteMsgs(messageReceived.From)
		} else {
			time := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
			content := "No unread messages"

			input := fmt.Sprint("server", messageReceived.From, time, "1.0", 21, content)
			hash := sha256.Sum256([]byte(input))
			hashString := hex.EncodeToString(hash[:])

			sign := signHash(hash[:])

			unread := msg{
				From:       "server",
				To:         messageReceived.From,
				Time:       time,
				Version:    "1.0",
				System:     21,
				Value:      content,
				Hash:       hash,
				HashString: hashString,
				Signature:  sign,
			}

			sendThru(conn, unread)
		}

	} else if messageReceived.System == 30 || messageReceived.System == 31 {
		id := db.GetUserId(messageReceived.To)

		val, ok := connected[id]
		if ok {
			fmt.Println("user found and online")
			sendThru(val, messageReceived)
		} else {
			db.UploadMsg(db.Msg(messageReceived))
		}
	} else if messageReceived.System == 11 {
		db.UploadPubKey(db.Msg(messageReceived))
	} else {
		fmt.Println("Error while handeling system message")
		os.Exit(1)
	}
}

// this function verifies the signatues of the signed hashes
func verifySignature(publicKey *rsa.PublicKey, hash, signature []byte) error {
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
}

// this function signes the hashes using rsa
func signHash(hash []byte) []byte {
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash)
	if err != nil {
		log.Fatal(err)
	}

	return signature
}

// this function read the privat key from the strored file hardcoded on the server
func readPrivKey() *rsa.PrivateKey {
	// Read the private key file
	if _, err := os.Stat("./privateKey.pem"); err == nil {
		// file exists
		f, err := os.Open("./privateKey.pem")
		if err != nil {
			log.Fatal(err)
		}

		defer f.Close()

		n, err := f.Read(readBuff)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode([]byte(readBuff[:n]))
		if block == nil {
			log.Fatal("failed to decode PEM block from private key file")
		}

		// Parse the DER-encoded private key
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		return privateKey
	} else {
		log.Fatal("error with getting rsa")
	}
	return nil
}

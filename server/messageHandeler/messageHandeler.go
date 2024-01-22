package messageHandeler

import (
	"bufio"
	"chat/server/db"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type msg struct {
	SessionId string `json:"SessionId"`
	From      string `json:"from"`
	To        string `json:"to"`
	Time      string `json:"timeSent"`
	Version   string `json:"version"`
	System    int    `json:"system"`
	Value     string `json:"value"`
	Hash      string `json:"hash"`
	Signature string `json:"Signature"`
}

type client struct {
	User string
	Ip   string
}

var connected = make(map[int]net.Conn)

var hostSender client
var hostReceiver client

func HandleConnection(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

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

		if strings.ToLower(receivedMsg.Value) == "exit" {
			fmt.Println("Client requested to close the connection.")
			id := db.GetUserId(receivedMsg.From)
			delete(connected, id)
			return
		}

		if receivedMsg.System != 0 {
			println("Got system message")
			handleSystemMessage(receivedMsg, conn)
		} else {

			hash := sha256.New()
			hash.Write([]byte(receivedMsg.From))
			hashInBytes := hash.Sum(nil)
			hashString := hex.EncodeToString(hashInBytes)

			pubKey := db.GetPubKey(hashString)

			verifySignature(pubKey)

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
		}

	}

	// Check for any errors during scanning
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading:", err)
	}
}

func sendThru(conn net.Conn, message msg) {
	encodedMessage, err := json.Marshal(message)
	if err != nil {
		fmt.Println("Error while convering to json: ", err)
		return
	}
	fmt.Println(encodedMessage)
	fmt.Fprintln(conn, string(encodedMessage))
}

func handleSystemMessage(messageReceived msg, conn net.Conn) {
	if messageReceived.System == 10 {
		id := db.GetUserId(messageReceived.From)

		fmt.Println("Got id: ", id)

		connected[id] = conn

		unreadMessage := db.CheckMsg(messageReceived.From)

		fmt.Println(unreadMessage)

		if unreadMessage {
			messages := db.GetMessage(messageReceived.From)

			time := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
			content := "You have unread messages, next messages will be the saved ones:"

			input := fmt.Sprint(messageReceived.From, messageReceived.To, time, "1.0", 3, content)
			hash := sha256.New()
			hash.Write([]byte(input))
			hashInBytes := hash.Sum(nil)
			hashString := hex.EncodeToString(hashInBytes)

			unread := msg{
				From:     messageReceived.From,
				To:       messageReceived.To,
				Time:     time,
				Version:  "1.0",
				System:   20,
				Value:    content,
				CheckSum: hashString,
			}

			sendThru(conn, unread)

			for _, messageInList := range messages {
				sendThru(conn, msg(messageInList))
			}

			db.DeleteMsgs(messageReceived.From)
		} else {
			time := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
			content := "No unread messages"

			input := fmt.Sprint(messageReceived.From, messageReceived.To, time, "1.0", 21, content)
			hash := sha256.New()
			hash.Write([]byte(input))
			hashInBytes := hash.Sum(nil)
			hashString := hex.EncodeToString(hashInBytes)

			unread := msg{
				From:     messageReceived.From,
				To:       messageReceived.To,
				Time:     time,
				Version:  "1.0",
				System:   21,
				Value:    content,
				CheckSum: hashString,
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
	} else if messageReceived.System == 5 {
		db.UploadPubKey(db.Msg(messageReceived))
	} else {
		fmt.Println("Error while handeling system message")
		os.Exit(1)
	}
}

func verifySignature(publicKey *rsa.PublicKey, hash, signature []byte) error {
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
}

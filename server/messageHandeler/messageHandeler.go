package messageHandeler

import (
	"bufio"
	"chat/server/db"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type msg struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Time     string `json:"timeSent"`
	Version  string `json:"version"`
	System   int    `json:"system"`
	Value    string `json:"value"`
	CheckSum string `json:"checkSum"`
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
			id := db.GetUserId(receivedMsg.To)
			sendThru(connected[id], receivedMsg)
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
	if messageReceived.System == 1 {
		id := db.GetUserId(messageReceived.From)

		fmt.Println("Got id: ", id)

		connected[id] = conn

		receiverId := db.GetUserId(messageReceived.To)

		val, ok := connected[receiverId]
		if ok {
			fmt.Println("user Found")
			sendThru(val, messageReceived)
		} else {
			db.UploadMsg(db.Msg(messageReceived))
		}

	} else {
		fmt.Println("Error while handeling system message")
		os.Exit(1)
	}
}

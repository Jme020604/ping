package connection

import (
	"bufio"
	"chat/client/diffie"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
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

var (
	sender   string
	receiver string
)

func readMessage(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		userMessage := scanner.Text()
		if userMessage == "close" {
			wg.Done()
		} else {
			currentTime := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
			constructMessage(0, userMessage, conn, currentTime)
		}
	}
}

func constructMessage(system int, content string, conn net.Conn, time string) {
	input := fmt.Sprint(sender, receiver, time, "1.0", system, content)
	hash := sha256.New()
	hash.Write([]byte(input))
	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)
	message := msg{
		From:     sender,
		To:       receiver,
		Time:     time,
		Version:  "1.0",
		System:   system,
		Value:    content,
		CheckSum: hashString,
	}

	fmt.Println(message)

	encodedMessage, err := json.Marshal(message)
	if err != nil {
		fmt.Println("Error while convering to json: ", err)
		return
	}

	fmt.Println("the encoded json: ", string(encodedMessage))

	sendMessage(conn, string(encodedMessage))
}

func sendMessage(conn net.Conn, message string) {
	fmt.Fprintln(conn, message)
}

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
		fmt.Println(receivedMsg)
	}
}

func diffieExchange(conn net.Conn) (*big.Int, *big.Int) {
	prime, g, err := diffie.GeneratePrime()
	if err != nil {
		fmt.Printf("Error while generating prime and/or g: %s", err)
		return nil, nil
	}

	fmt.Fprintln(conn, prime)
	fmt.Fprintln(conn, g)

	return prime, g
}

func initUser(conn net.Conn) {
	fmt.Print("Give up yout username: ")
	fmt.Scanln(&sender)
	fmt.Println("You are:", sender)

	fmt.Print("Who do you want to send to?: ")
	fmt.Scanln(&receiver)
	fmt.Println("You are sending to: ", receiver)
	info := conn.LocalAddr().String()
	currentTime := fmt.Sprint(time.Now().Format("1-2-2006 15:4:5"))
	constructMessage(1, info, conn, currentTime)
}

func StartConn() {
	fmt.Print("Enter the address to connect (e.g., localhost:8080): ")
	var address string
	fmt.Scanln(&address)

	var wg sync.WaitGroup

	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		//server(&wg)
	} else {
		fmt.Println("connected to:", conn.RemoteAddr())
		//privateKey := diffie.GeneratePrivateKey()
		//fmt.Printf("Private Key: %s", privateKey)
		initUser(conn)
		defer conn.Close()

		wg.Add(1)
		go getMessage(conn, &wg)
		go readMessage(conn, &wg)
	}

	// Wait for both goroutines to finish
	wg.Wait()
}

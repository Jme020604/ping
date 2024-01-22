package db

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/go-sql-driver/mysql"
)

type Msg struct {
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

var db *sql.DB
var cfg = mysql.Config{
	User:                 "pingProgram",
	Passwd:               "SLY3McJJaH3TQKSrTC%@",
	Net:                  "tcp",
	Addr:                 "127.0.0.1:8889",
	DBName:               "ping",
	Collation:            "utf8mb4_general_ci",
	InterpolateParams:    true,
	ParseTime:            true,
	AllowNativePasswords: true,
}

func GetUserId(user string) int {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT id FROM login WHERE username = ?", user)
	if err != nil {
		fmt.Printf("id %q: %v", user, err)
	}

	defer rows.Close()

	var ids []int

	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			fmt.Printf("id %q: %v", user, err)
		}
		ids = append(ids, id)
	}

	rightId := ids[0]

	return rightId
}

func UploadMsg(message Msg) {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	username := message.To

	hash := makeMsgDb(username)

	insertSQL := fmt.Sprintf("INSERT INTO `%s` (`from`, `to`, `time`, `version`, `system`, `value`, `hash`, `signature`) VALUES (?, ?, ?, ?, ?, ?, ?);", hash)

	rows, err := db.Query(insertSQL, message.From, message.To, message.Time, message.Version, message.System, message.Value, message.Hash, message.Signature)
	if err != nil {
		fmt.Println(err)
	}

	defer rows.Close()

}

func makeMsgDb(user string) string {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	hash := sha256.New()
	hash.Write([]byte(user))
	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	createSql := fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`(`from` VARCHAR(256) NOT NULL, `to` VARCHAR(256) NOT NULL, `time` VARCHAR(30) NOT NULL, `version` VARCHAR(5) NOT NULL, `system` int NOT NULL, `value` TEXT NOT NULL, `hash` VARCHAR(512) NOT NULL);", hashString)

	rows, err := db.Query(createSql)
	if err != nil {
		fmt.Println(err)
	}

	defer rows.Close()

	return hashString
}

func CheckMsg(user string) bool {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	hash := sha256.New()
	hash.Write([]byte(user))
	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	rows, err := db.Query("SHOW TABLES")
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			fmt.Println(table)
		}

		if table == hashString {
			return true
		}
	}

	return false
}

func GetMessage(user string) []Msg {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	hash := sha256.New()
	hash.Write([]byte(user))
	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	createSQL := fmt.Sprintf("SELECT `from`, `to`, `time`, `version`, `system`, `value`, `checksum` FROM %s", hashString)

	rows, err := db.Query(createSQL)
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	var messages []Msg

	for rows.Next() {
		var currentMsg Msg
		if err := rows.Scan(&currentMsg.From, &currentMsg.To, &currentMsg.Time, &currentMsg.Version, &currentMsg.System, &currentMsg.Value, &currentMsg.CheckSum); err != nil {
			log.Fatal("error while retreiving messages from db", err)
		}
		messages = append(messages, currentMsg)
	}

	return messages
}

func DeleteMsgs(user string) {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	hash := sha256.New()
	hash.Write([]byte(user))
	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	createSQL := fmt.Sprintf("DROP TABLE %s", hashString)

	rows, err := db.Query(createSQL)
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
}

func UploadPubKey(message Msg) {
	hashFrom := sha256.New()
	hashFrom.Write([]byte(message.From))
	hashFromInBytes := hashFrom.Sum(nil)
	hashFromString := hex.EncodeToString(hashFromInBytes)

	result := checkKey(hashFromString)

	if result {
		return
	} else {
		var err error
		db, err = sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			log.Fatal(err)
		}

		hashFrom := sha256.New()
		hashFrom.Write([]byte(message.From))
		hashFromInBytes := hashFrom.Sum(nil)
		hashFromString := hex.EncodeToString(hashFromInBytes)

		hashTo := sha256.New()
		hashTo.Write([]byte(message.To))
		hashToInBytes := hashTo.Sum(nil)
		hashToString := hex.EncodeToString(hashToInBytes)

		rows, err := db.Query("INSERT INTO publicKeys(`from`, `to`, `pubKey`) VALUES(?,?,?)", hashFromString, hashToString, message.Value)
		if err != nil {
			log.Fatal(err)
		}

		defer rows.Close()
	}

}

func checkKey(hashString string) bool {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT `from` FROM publicKeys WHERE `from` = ?;", hashString)
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	var results []string

	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			log.Fatal("error while retreiving messages from db", err)
		}
		results = append(results, result)
	}

	if len(results) > 0 {
		return true
	} else {
		return false
	}
}

func GetPubKey(hashString string) *rsa.PublicKey {
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT `pubKey` FROM publicKeys WHERE `from` = ?;", hashString)
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	var results []string

	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			log.Fatal("error while retreiving messages from db", err)
		}
		results = append(results, result)
	}

	key := results[0]

	block, _ := pem.Decode([]byte(key))
	if block == nil {
		log.Fatal("failed to decode PEM block from public key file")
	}

	// Parse the DER-encoded private key
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return publicKey
}

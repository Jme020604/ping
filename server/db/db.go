package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/go-sql-driver/mysql"
)

type Msg struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Time     string `json:"timeSent"`
	Version  string `json:"version"`
	System   int    `json:"system"`
	Value    string `json:"value"`
	CheckSum string `json:"checkSum"`
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

	username := message.From

	hash := makeMsgDb(username)

	insertSQL := fmt.Sprintf("INSERT INTO `%s` (`from`, `to`, `time`, `version`, `system`, `value`, `checkSum`) VALUES (?, ?, ?, ?, ?, ?, ?);", hash)

	rows, err := db.Query(insertSQL, message.From, message.To, message.Time, message.Version, message.System, message.Value, message.CheckSum)
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

	createSql := fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`(`from` VARCHAR(256) NOT NULL, `to` VARCHAR(256) NOT NULL, `time` VARCHAR(30) NOT NULL, `version` VARCHAR(5) NOT NULL, `system` int NOT NULL, `value` TEXT NOT NULL, `checkSum` VARCHAR(512) NOT NULL);", hashString)

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
		} else {
			return false
		}
	}

	return false
}

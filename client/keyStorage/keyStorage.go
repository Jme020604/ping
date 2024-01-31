// this part of the program is for storing the session keys
package keyStorage

import (
	"fmt"
	"log"

	"github.com/boltdb/bolt"
)

// Upload data to the BoltDB database
func UploadData(dbPath, bucketName, key, value string) error {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		// Create or open a bucket
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}

		// Store data in the bucket
		err = bucket.Put([]byte(key), []byte(key))
		return err
	})

	return err
}

// GetValueForKeyInBucket retrieves the value of a specific key in the BoltDB database bucket
func GetValueForKeyInBucket(dbPath, bucketName, key string) ([]byte, error) {
	var value []byte

	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket '%s' does not exist", bucketName)
		}

		// Retrieve the value for the specified key
		value = bucket.Get([]byte(key))
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	return value, nil
}

func KeyExists(dbPath, bucketName, key string) bool {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var keyExists bool

	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			// Bucket does not exist
			keyExists = false
			return nil
		}

		// Check if the key exists in the bucket
		if bucket.Get([]byte(key)) != nil {
			keyExists = true
		} else {
			// Key does not exist in the bucket
			keyExists = false
		}

		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	return keyExists
}

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"os"
	"sort"
	"strconv"
	"time"
)

func main() {

	firstKeyMiner := []byte("30770201010420b01b5f30ed449a36f701fdf95b290e5db7167a0b9b7f08ac17e6d93af1be6bb1a00a06082a8648ce3d030107a144034200040d113336e60c0c4c42bd20c6763ff0f50abda25725e5fc16d5ffc90ecc6d6437b454a6cac8c3d695e2955aecdab8fa758c9d3328870171d8fdd0d965a90bfb5e")

	nbMiners, _ := strconv.Atoi(os.Args[1])
	nbTx, _ := strconv.Atoi(os.Args[2])

	authKeys := make([][]byte, 0)
	for i := 0; i < nbMiners; i++ {
		authKeys = append(authKeys, generatePublicKey())
	}

	log.Printf("STARTING ENTROPY SORT FOR %d MINERS AND %d TRANSACTIONS...\n", nbMiners, nbTx)
	t := time.Now()
	for i := 0; i < nbTx; i++ {
		txHash := generateHash()
		entropySort(firstKeyMiner, txHash, authKeys)
	}
	log.Printf("ELAPSED TIME: %f s\n", time.Since(t).Seconds())
}

func generateHash() []byte {
	t := time.Now()
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(t.Unix()))
	return hash(b)
}

func hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func generatePublicKey() []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
}

func buildStartingPoint(firstKeyMiner []byte, txHash []byte) (string, error) {
	h := hmac.New(sha256.New, firstKeyMiner)
	h.Write([]byte(txHash))
	return hex.EncodeToString(h.Sum(nil)), nil
}

//entropySort sorts a list of nodes public keys using a "starting point" (HMAC of the transaction hash with the first node shared private key) and the hashes of the node public keys
func entropySort(firstKeyMiner []byte, txHash []byte, authKeys [][]byte) (sortedKeys [][]byte, err error) {
	startingPoint, err := buildStartingPoint(firstKeyMiner, txHash)
	if err != nil {
		return nil, err
	}

	//Building list of public keys and map of hashed key
	hashKeys := make([]string, len(authKeys))
	mHashKeys := make(map[string][]byte, 0)
	for i, k := range authKeys {
		h := hash(k)
		mHashKeys[hex.EncodeToString(h)] = k
		hashKeys[i] = hex.EncodeToString(h)
	}

	hashKeys = append(hashKeys, startingPoint)
	sort.Strings(hashKeys)
	var startPointIndex int
	for i, k := range hashKeys {
		if startingPoint == k {
			startPointIndex = i
			break
		}
	}

	end := sha256.Size

	//Sort keys by comparing the last character of the key with a starting point character
	for p := 0; len(sortedKeys) < len(hashKeys)-1 && p < end; p++ {

		//iterating from the starting point to the end of the list
		//add add the key if the latest character matchew the start point position
		for i := startPointIndex + 1; i < len(hashKeys); i++ {
			if []rune(hashKeys[i])[end-1] == []rune(startingPoint)[p] {
				var contains bool
				for _, k := range sortedKeys {
					if bytes.Equal(k, mHashKeys[hashKeys[i]]) {
						contains = true
						break
					}
				}
				if !contains {
					sortedKeys = append(sortedKeys, mHashKeys[hashKeys[i]])
				}
			}
		}

		//iterating from the 0 to the starting point
		//and add the key if the latest character matches the start point position
		for i := 0; i < startPointIndex; i++ {
			if []rune(hashKeys[i])[end-1] == []rune(startingPoint)[p] {
				var contains bool
				for _, k := range sortedKeys {
					if bytes.Equal(k, mHashKeys[hashKeys[i]]) {
						contains = true
						break
					}
				}
				if !contains {
					sortedKeys = append(sortedKeys, mHashKeys[hashKeys[i]])
				}
			}
		}
	}

	//We have tested all the characters of the staring point and not yet finished the sort operation, we will loop on all the hex characters to finish the sort
	if len(sortedKeys) < len(hashKeys)-1 {
		hexChar := []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
		for p := 0; len(sortedKeys) < len(hashKeys)-1 && p < len(hexChar); p++ {

			//iterating from the starting point to the end of the list
			//add add the key if the latest character matchew the start point position
			for i := startPointIndex + 1; i < len(hashKeys); i++ {
				if []rune(hashKeys[i])[end-1] == hexChar[p] {
					var contains bool
					for _, k := range sortedKeys {
						if bytes.Equal(k, mHashKeys[hashKeys[i]]) {
							contains = true
							break
						}
					}
					if !contains {
						sortedKeys = append(sortedKeys, mHashKeys[hashKeys[i]])
					}
				}
			}

			//iterating from the 0 to the starting point
			//and add the key if the latest character matches the start point position
			for i := 0; i < startPointIndex; i++ {
				if []rune(hashKeys[i])[end-1] == hexChar[p] {
					var contains bool
					for _, k := range sortedKeys {
						if bytes.Equal(k, mHashKeys[hashKeys[i]]) {
							contains = true
							break
						}
					}
					if !contains {
						sortedKeys = append(sortedKeys, mHashKeys[hashKeys[i]])
					}
				}
			}
		}
	}

	return
}

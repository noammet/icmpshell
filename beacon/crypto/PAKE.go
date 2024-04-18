package crypto

import (
	h "beacon/helper"
	s "beacon/sendICMP"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"

	"github.com/schollz/pake"
	"golang.org/x/crypto/chacha20poly1305"
)

// todo

type KeyWrapper struct {
	BeaconID string
	key      *pake.Pake
}

var WeakKey = []byte{1, 3, 3, 7}

func initKey(weakKey []byte) pake.Pake {
	A, err := pake.InitCurve(weakKey, 0, "siec")
	if err != nil {
		log.Fatal(err.Error())
	}
	return *A
}

func sendKey(A KeyWrapper) pake.Pake {
	buf, err := h.EncodeGob(A)
	if err != nil {
		log.Fatal(err.Error())
	}
	seqnum := h.GenerateRandomNumber()
	s.SendRaw(buf.Bytes(), seqnum)
	if err != nil {
		log.Fatal(err.Error())
	}
	recv := <-h.Crypt
	var wrappedB KeyWrapper
	gob.NewDecoder(bytes.NewBuffer(recv)).Decode(&wrappedB)
	return *wrappedB.key
}

func calcKey(A, B *pake.Pake) []byte {
	err := A.Update(B.Bytes())
	if err != nil {
		log.Fatal(err.Error())
	}
	kA, _ := A.SessionKey()
	return kA
}

func checkKey(A, B *pake.Pake) bool {
	err := A.Update(B.Bytes())
	if err != nil {
		log.Fatal(err.Error())
	}
	err = B.Update(A.Bytes())
	if err != nil {
		log.Fatal(err.Error())
	}
	kA, _ := A.SessionKey()
	kB, _ := B.SessionKey()
	return bytes.Equal(kA, kB)
}

func EncBlob(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	blob := aead.Seal(nonce, nonce, plaintext, nil)
	return blob, nil

}

func DecBlob(key, encryptedMsg []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(encryptedMsg) < aead.NonceSize() {
		err := fmt.Errorf("ciphertext too short")
		if err != nil {
			return nil, err
		}
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func Send(msg, key []byte) error {
	//sends an encryptes message
	encodedMsg, err := h.EncodeGob(msg)
	if err != nil {
		return err
	}
	cryptedBlob, err := EncBlob(key, encodedMsg.Bytes())
	if err != nil {
		return err
	}
	s.SendRaw(cryptedBlob, h.GenerateRandomNumber()) //needs a sequence number because it will be used to intialize first seqnum for the messages
	return nil
}
func KeyExhcange(weakKey []byte, beaconID string) ([]byte, error) {
	A := initKey(weakKey)
	h := sha256.New()
	_, err := h.Write([]byte(beaconID))
	if err != nil {
		return nil, err
	}
	wrappedA := KeyWrapper{
		BeaconID: beaconID, //encrypt with pub key and add a hash
		key:      &A,
	}
	B := sendKey(wrappedA)
	kA := calcKey(&A, &B)
	test := checkKey(&A, &B)
	if test {
		return kA, nil
	} else {
		err := fmt.Errorf("keys not equal something in key exchange goofed")
		return nil, err
	}
}

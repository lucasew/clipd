// Package main implements a tool that synchronizes the system clipboard across devices
// using NATS as the messaging fabric. Updates are symmetrically encrypted (AES-GCM)
// before broadcast, ensuring secure state synchronization between end devices.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	clipboard "github.com/atotto/clipboard"
	nats "github.com/nats-io/nats.go"
)

var group string
var natsHost string
var passHash = make([]byte, aes.BlockSize)

var ciph cipher.Block

var cur string
var err error

var srv *nats.Conn // Server instance
var sub *nats.Subscription

// setupServer initializes or re-establishes the connection to the configured NATS server.
// It modifies the global 'srv' and 'sub' variables as a side effect.
// When called, it loops until a successful connection to the NATS host is achieved,
// and subscribes to the device group topic. This ensures resilient connectivity.
func setupServer() {
	if srv != nil { // Reconnect
		srv.Close()
	}
	err = fmt.Errorf("") // just to fill
	for err != nil {
		log.Printf("Connecting to %s...", natsHost)
		srv, err = nats.Connect(
			natsHost,
			nats.Timeout(time.Second),
			nats.ReconnectWait(time.Second),
			nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
				log.Printf("ERR disconnect from %s: %s", nc.ConnectedAddr(), err.Error())
			}),
			nats.ReconnectHandler(func(nc *nats.Conn) {
				log.Printf("INFO: reconnecting to %s...", nc.ConnectedUrl())
			}),
		)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		log.Printf("Subscribing topic...")
		sub, err = srv.SubscribeSync(group)
	}
}

// setupKey derives a deterministic 256-bit symmetric key from the provided password
// to be used later in AES-GCM encryption/decryption cycles.
// Side effect: overrides the globally allocated 'passHash' byte slice.
func setupKey(passwd string) {
	sha := sha256.Sum256([]byte(passwd))
	for k := range passHash {
		passHash[k] = sha[k]
	}
}

// main is the CLI entrypoint. It parses configuration flags, initializes the network
// and cryptographic state, and starts the infinite event loop handling both incoming NATS
// state updates and outgoing local clipboard modifications.
func main() {
	var passwd string
	flag.StringVar(&group, "g", "", "What device group exchange clipboard state updates")
	flag.StringVar(&passwd, "p", "", "Password to encript the state updates")
	flag.StringVar(&natsHost, "s", "demo.nats.io", "Nats server to use")
	flag.Parse()
	if len(group) == 0 || len(passwd) == 0 {
		flag.Usage()
		return
	}
	group = fmt.Sprintf("__clipd__.%s", group)
	setupServer()
	setupKey(passwd)
	log.Printf("Starting the magic...")
	for {
		m, err := sub.NextMsg(time.Second)
		// if err != nil { // debugging purposes
		// 	println(err.Error())
		// }
		if err == nats.ErrInvalidConnection {
			log.Printf("WARN: No connection to the server")
			setupServer()
			time.Sleep(time.Second)
		}
		if err == nats.ErrTimeout {
			candidate, err := clipboard.ReadAll()
			if err != nil {
				log.Printf("ERR get clipboard: %s", err.Error())
				continue
			}
			if strings.EqualFold(cur, candidate) {
				continue
			} else {
				log.Printf("INFO: locally modified clipboard, sending update")
				d, err := encrypt([]byte(candidate))
				if err != nil {
					log.Printf("ERRO: %s", err.Error())
					continue
				}
				cur = candidate
				srv.Publish(group, d)
			}
			continue
		}
		if err != nil {
			log.Printf("ERR update listen: %s", err.Error())
			continue
		}
		d, err := decrypt(m.Data)
		if err != nil {
			log.Printf("ERR: %s", err.Error())
			continue
		}
		s := string(d)
		if !strings.EqualFold(s, cur) {
			//println(s)
			//println(cur)
			log.Printf("INFO: remotely modified clipboard, aplying changes")
			err = clipboard.WriteAll(s)
			if err != nil {
				log.Printf("ERR change clipboard: %s", err.Error())
			}
			cur = s
		}
	}
}

// encrypt converts plaintext clipboard data into an AES-GCM encrypted payload,
// prepending a randomly generated nonce to the ciphertext for proper decryption.
// This ensures that state updates sent over the wire cannot be easily read
// or tampered with by the NATS broker or intermediate network elements.
func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(passHash)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt extracts the prepended nonce and converts an AES-GCM ciphertext payload
// back into plaintext clipboard data, verifying message integrity and authenticity
// using the globally derived symmetric key.
func decrypt(data []byte) ([]byte, error) {
	key := []byte(passHash)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

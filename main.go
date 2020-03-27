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

const natsHost = "demo.nats.io"

var group string
var passHash = make([]byte, aes.BlockSize)

var ciph cipher.Block

var cur string

func main() {
	var passwd string
	flag.StringVar(&group, "g", "", "Para qual grupo de dispositivos enviar e receber atualizações de estado")
	flag.StringVar(&passwd, "p", "", "Senha para encriptar as atualizações de estado")
	flag.Parse()
	if len(group) == 0 || len(passwd) == 0 {
		flag.Usage()
		return
	}
	{
		sha := sha256.Sum256([]byte(passwd))
		for k := range passHash {
			passHash[k] = sha[k]
		}
	}
	group = fmt.Sprintf("__clipd__.%s", group)
	var err error
	log.Printf("Inicializando...")
	srv, err := nats.Connect(natsHost)
	if err != nil {
		panic(err)
	}
	log.Printf("Configurando servidor...")
	sub, err := srv.SubscribeSync(group)
	if err != nil {
		panic(err)
	}
	log.Printf("Iniciando a mágica...")
	for {
		m, err := sub.NextMsg(time.Second)
		if err == nats.ErrTimeout {
			candidate, err := clipboard.ReadAll()
			if err != nil {
				log.Printf("ERRO ao obter clipboard: %s", err.Error())
				continue
			}
			if strings.EqualFold(cur, candidate) {
				continue
			} else {
				log.Printf("INFO: clipboard modificado localmente, refletindo alterações")
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
			log.Printf("Erro ao escutar por mensagem: %s", err.Error())
			continue
		}
		d, err := decrypt(m.Data)
		if err != nil {
			log.Printf("ERRO: %s", err.Error())
			continue
		}
		s := string(d)
		if !strings.EqualFold(s, cur) {
			//println(s)
			//println(cur)
			log.Printf("INFO: clipboard modificado remotamente, refletindo alterações")
			err = clipboard.WriteAll(s)
			if err != nil {
				log.Printf("Erro ao alterar clipboard: %s", err.Error())
			}
		}
	}
}
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

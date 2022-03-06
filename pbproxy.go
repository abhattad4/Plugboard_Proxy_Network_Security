// References:
// https://github.com/dddpaul/gonc/blob/master/tcp/tcp.go
// https://golang.org/src/io/io.go
// https://github.com/smallnest/goframe
// https://medium.com/@yanzay/implementing-simple-netcat-using-go-bbab37507635
// https://www.melvinvivas.com/how-to-encrypt-and-decrypt-data-using-aes/
// https://pkg.go.dev/golang.org/x/crypto/pbkdf2#Key

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/smallnest/goframe"
	"golang.org/x/crypto/pbkdf2"
)

// ReadWriteBytes indicates transfer status
type ReadWriteBytes struct {
	bytes int64
}

var ErrShortWrite = errors.New("short write")

var ErrShortBuffer = errors.New("short buffer")

var saltBytes = 12
var encoderConfig = goframe.EncoderConfig{
	ByteOrder:                       binary.BigEndian,
	LengthFieldLength:               8,
	LengthAdjustment:                0,
	LengthIncludesLengthFieldLength: false,
}

var decoderConfig = goframe.DecoderConfig{
	ByteOrder:           binary.BigEndian,
	LengthFieldOffset:   0,
	LengthFieldLength:   8,
	LengthAdjustment:    0,
	InitialBytesToStrip: 8,
}

func main() {

	parameters := os.Args[1:]

	//Reading arguments
	var (
		myKey       string = "default"
		listenPort  string
		hostAndPort string
		finalPort   string
		finalHost   string
	)

	for i := 0; i < len(parameters); {
		if parameters[i] == "-p" {
			myKey = parameters[i+1]
			i = i + 2
		} else if parameters[i] == "-l" {
			listenPort = parameters[i+1]
			i = i + 2
		} else {
			if hostAndPort == "" {
				hostAndPort = parameters[i]
			} else {
				hostAndPort = hostAndPort + " " + parameters[i]
			}
			i++
		}
	}

	hostAndPortSplit := strings.Fields(hostAndPort)
	finalHost = hostAndPortSplit[0]
	finalPort = hostAndPortSplit[1]

	log.Println("Filename:", myKey)
	log.Println("PortToListen:", listenPort)
	log.Println("HostToConnect:", finalHost)
	log.Println("PortToConnect:", finalPort)

	data, err := ioutil.ReadFile(myKey)
	if err != nil {
		log.Println("Error while reading file:", err)
	}
	key := string(data)

	if listenPort == "" {
		StartClient("tcp", finalHost, finalPort, key)
	} else {
		StartServer("tcp", listenPort, key, finalHost, finalPort)
	}
}

// StartClient starts TCP connector
func StartClient(proto string, host string, port string, key string) {
	con, err := net.Dial(proto, host+":"+port)
	if err != nil {
		log.Println(err)
		return
	}
	conFrame := goframe.NewLengthFieldBasedFrameConn(encoderConfig, decoderConfig, con)
	c := make(chan ReadWriteBytes)
	redirectConnectionsClient(conFrame, c, key)
}

// StartServer starts TCP listener
func StartServer(proto string, port string, key string, finalH string, finalP string) {
	ln, err := net.Listen(proto, ":"+port)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Started listen on", proto+" :"+port)
	for {
		con, err := ln.Accept()
		if err != nil {
			log.Println(err)
			con.Close()
			break
		} else {
			conFrame := goframe.NewLengthFieldBasedFrameConn(encoderConfig, decoderConfig, con)
			log.Printf("[%s]: Connection created\n", con.RemoteAddr())
			rcon, err1 := net.Dial(proto, finalH+":"+finalP)
			if err1 != nil {
				log.Println(err1)
				con.Close()
				continue
			}
			rconFrame := goframe.NewLengthFieldBasedFrameConn(encoderConfig, decoderConfig, rcon)
			go redirectConnectionsServer(conFrame, rconFrame, key)
		}
	}
}

//Redirecting connections
func redirectConnectionsClient(con goframe.FrameConn, c chan ReadWriteBytes, key string) {
	redirect := func(conFrame goframe.FrameConn, key string, flag bool) {
		defer func() {
			conFrame.Close()
		}()
		//Input Reader is os.stdin
		if flag {
			var written int64 = 0
			buf := make([]byte, 64*1024)
			for {
				nr, er := os.Stdin.Read(buf)
				if er != nil {
					log.Println("Read Error", er)
					break
				}
				if nr > 0 {
					ciphertext := encrypt(buf[:nr], key)
					ew := conFrame.WriteFrame(ciphertext)
					if ew != nil {
						log.Println("Write Error", ew)
						break
					}
					written += int64(len(ciphertext))
				}
			}
			c <- ReadWriteBytes{bytes: written}
		} else {
			var written int64 = 0
			f := bufio.NewWriter(os.Stdout)
			var buf1 = make([]byte, 64*1024)
			for {
				nr, er := conFrame.Conn().Read(buf1)
				if er != nil {
					log.Println("Read Error", er)
					break
				}
				if nr > 0 {
					plaintext := decrypt(buf1[decoderConfig.LengthFieldLength:nr], key)
					nw, ew := f.Write(plaintext)
					f.Flush()
					if ew != nil {
						log.Println("Write Error", ew)
						break
					}
					written += int64(nw)
				}
			}
			c <- ReadWriteBytes{bytes: written}
		}
	}

	go redirect(con, key, false)
	go redirect(con, key, true)

	bytesWritten := <-c
	log.Printf("Remote connection has been closed, received %d bytes\n", bytesWritten.bytes)
	bytesWritten = <-c
	log.Printf("Local connection has been closed, sent %d bytes\n", bytesWritten.bytes)
}

//Redirecting connections
func redirectConnectionsServer(con goframe.FrameConn, rcon goframe.FrameConn, key string) {
	c := make(chan ReadWriteBytes)
	redirect := func(r goframe.FrameConn, w goframe.FrameConn, key string) {
		defer func() {
			r.Close()
			w.Close()
		}()
		if r.Conn() == rcon.Conn() {
			var written int64 = 0
			buf := make([]byte, 64*1024)
			for {
				nr, er := r.Conn().Read(buf)
				if er != nil {
					log.Println("Read Error", er)
					break
				}
				if nr > 0 {
					ciphertext := encrypt(buf[:nr], key)
					ew := w.WriteFrame(ciphertext)
					if ew != nil {
						log.Println("Write Error", ew)
						break
					}
					written += int64(len(ciphertext))
				}
			}
			c <- ReadWriteBytes{bytes: written}
		} else {
			var buf1 = make([]byte, 64*1024)
			var written int64 = 0
			for {
				nr, er := r.Conn().Read(buf1)
				if er != nil {
					log.Println("Read Error", er)
					break
				}
				if nr > 0 {
					plaintext := decrypt(buf1[decoderConfig.LengthFieldLength:nr], key)
					nw, ew := w.Conn().Write(plaintext)
					if ew != nil {
						log.Println("Write Error", ew)
						break
					}
					written += int64(nw)
				}
			}
			c <- ReadWriteBytes{bytes: written}
		}
	}

	go redirect(con, rcon, key)
	go redirect(rcon, con, key)

	bytesWritten := <-c
	log.Printf("Remote connection has been closed, received %d bytes\n", bytesWritten.bytes)
	bytesWritten = <-c
	log.Printf("Local connection has been closed, sent %d bytes\n", bytesWritten.bytes)
}

//Encryption function to encrypt the data
func encrypt(data []byte, mykey string) []byte {
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Printf("Error creating salt %s", err)
	}
	key := pbkdf2.Key([]byte(mykey), []byte(salt), 4096, sha256.Size, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error creating cipher %s", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error creating block %s", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("Error creating nonce %s", err)
	}
	dstFinal := append(salt, nonce...)
	ciphertext := gcm.Seal(dstFinal, nonce, data, nil)
	return ciphertext
}

//Decryption function to decrpyt the data
func decrypt(data []byte, mykey string) []byte {
	salt := data[:saltBytes]
	key := pbkdf2.Key([]byte(mykey), []byte(salt), 4096, sha256.Size, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error creating cipher %s", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error creating block %s", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[saltBytes:saltBytes+nonceSize], data[saltBytes+nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Error decrypting plaintext %s", err)
	}
	return plaintext
}

package app

import (
	"fmt"
	"log"
	"strings"
	"time"

	clipboard "github.com/atotto/clipboard"
	"github.com/lucasew/clipd/src/crypto"
	"github.com/lucasew/clipd/src/errorreporter"
	nats "github.com/nats-io/nats.go"
)

// App holds the application state.
type App struct {
	Group    string
	NatsHost string
	PassHash []byte

	Cur string

	Srv *nats.Conn
	Sub *nats.Subscription
}

// SetupServer establishes a connection to the NATS server and subscribes to the group.
func (a *App) SetupServer() {
	if a.Srv != nil { // Reconnect
		a.Srv.Close()
	}
	var err error = fmt.Errorf("") // just to fill
	for err != nil {
		log.Printf("Connecting to %s...", a.NatsHost)
		a.Srv, err = nats.Connect(
			a.NatsHost,
			nats.Timeout(time.Second),
			nats.ReconnectWait(time.Second),
			nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
				if err != nil {
					errorreporter.Report(err, fmt.Sprintf("disconnect from %s", nc.ConnectedAddr()))
				}
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
		a.Sub, err = a.Srv.SubscribeSync(a.Group)
		if err != nil {
			errorreporter.Report(err, "subscribe sync")
		}
	}
}

// HandleLocalUpdate checks the local clipboard for changes and sends them if necessary.
func (a *App) HandleLocalUpdate() {
	candidate, err := clipboard.ReadAll()
	if err != nil {
		errorreporter.Report(err, "get clipboard")
		return
	}
	if strings.EqualFold(a.Cur, candidate) {
		return
	}
	log.Printf("INFO: locally modified clipboard, sending update")
	d, err := crypto.Encrypt([]byte(candidate), a.PassHash)
	if err != nil {
		errorreporter.Report(err, "encrypt clipboard data")
		return
	}
	a.Cur = candidate
	err = a.Srv.Publish(a.Group, d)
	if err != nil {
		errorreporter.Report(err, "publish update")
	}
}

// HandleRemoteUpdate processes an incoming message and updates the local clipboard if it differs.
func (a *App) HandleRemoteUpdate(m *nats.Msg) {
	d, err := crypto.Decrypt(m.Data, a.PassHash)
	if err != nil {
		errorreporter.Report(err, "decrypt update")
		return
	}
	s := string(d)
	if !strings.EqualFold(s, a.Cur) {
		log.Printf("INFO: remotely modified clipboard, applying changes")
		err = clipboard.WriteAll(s)
		if err != nil {
			errorreporter.Report(err, "change clipboard")
		}
		a.Cur = s
	}
}

// Run starts the main event loop for the application.
func (a *App) Run() {
	log.Printf("Starting the magic...")
	for {
		m, err := a.Sub.NextMsg(time.Second)
		if err == nats.ErrInvalidConnection {
			log.Printf("WARN: No connection to the server")
			a.SetupServer()
			time.Sleep(time.Second)
			continue
		}
		if err == nats.ErrTimeout {
			a.HandleLocalUpdate()
			continue
		}
		if err != nil {
			errorreporter.Report(err, "update listen")
			continue
		}
		a.HandleRemoteUpdate(m)
	}
}

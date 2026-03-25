package main

import (
	"flag"
	"fmt"

	"github.com/lucasew/clipd/src/app"
	"github.com/lucasew/clipd/src/crypto"
)

func main() {
	var group string
	var natsHost string
	var passwd string

	flag.StringVar(&group, "g", "", "What device group exchange clipboard state updates")
	flag.StringVar(&passwd, "p", "", "Password to encript the state updates")
	flag.StringVar(&natsHost, "s", "demo.nats.io", "Nats server to use")
	flag.Parse()

	if len(group) == 0 || len(passwd) == 0 {
		flag.Usage()
		return
	}

	appInstance := &app.App{
		Group:    fmt.Sprintf("__clipd__.%s", group),
		NatsHost: natsHost,
		PassHash: crypto.SetupKey(passwd),
	}

	appInstance.SetupServer()
	appInstance.Run()
}

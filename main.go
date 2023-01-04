package main

import (
	"rto-softener/pkg/dialTimeout"
	"rto-softener/pkg/sockops"
	"time"
)

func main() {
	go loop()
	sockops.LockAndLoad()
}

func loop() {
	for {
		dialTimeout.DialTimeout(5 * time.Second)
		time.Sleep(1 * time.Second)
	}
}

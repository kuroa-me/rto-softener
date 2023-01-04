package dialTimeout

import (
	"fmt"
	"net"
	"time"
)

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	fmt.Printf("%s took %s\n", name, elapsed)
}

func DialTimeout(dur time.Duration) {
	fmt.Printf("Expect to timeout after %s\n", dur)
	defer timeTrack(time.Now(), "dialTimeout")
	conn, err := net.DialTimeout("tcp4", "9.9.9.9:9999", dur)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer conn.Close()
}

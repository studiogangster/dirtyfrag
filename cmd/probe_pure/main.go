package main

import (
	"fmt"
	"os"
	"runtime"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	fmt.Printf("sysname=%s\n", runtime.GOOS)
	fmt.Printf("release=%s\n", "unknown")
	fmt.Printf("machine=%s\n", runtime.GOARCH)

	if runtime.GOOS != "linux" {
		fmt.Println("result=NOT_APPLICABLE (not Linux)")
		os.Exit(3)
	}

	hasEsp4 := exists("/sys/module/esp4")
	hasEsp6 := exists("/sys/module/esp6")
	hasRxrpc := exists("/sys/module/rxrpc")

	btoi := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}

	fmt.Printf("modules_loaded: esp4=%d esp6=%d rxrpc=%d\n", btoi(hasEsp4), btoi(hasEsp6), btoi(hasRxrpc))

	if (hasEsp4 || hasEsp6) && hasRxrpc {
		fmt.Println("result=LIKELY_VULNERABLE (required modules loaded)")
		os.Exit(0)
	}

	if !hasRxrpc && !(hasEsp4 || hasEsp6) {
		fmt.Println("result=LIKELY_NOT_VULNERABLE (modules not loaded)")
		os.Exit(1)
	}

	fmt.Println("result=UNKNOWN (partial module exposure)")
	os.Exit(2)
}

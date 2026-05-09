package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func primaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}

	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}

	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To16() != nil {
				return ip.String()
			}
		}
	}

	return "unknown"
}

func main() {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	fmt.Printf("sysname=%s\n", runtime.GOOS)
	fmt.Printf("release=%s\n", "unknown")
	fmt.Printf("machine=%s\n", runtime.GOARCH)
	fmt.Printf("hostname=%s\n", hostname)
	fmt.Printf("host_ip=%s\n", primaryIP())

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

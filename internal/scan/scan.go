package scan

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
	"github.com/opennetworktools/netctl/internal/crafter"
)

func ARPScan() {
	iface, err := net.InterfaceByName("en0")
	if err != nil {
		panic(err)
	}

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Failed to open pcap handle: %v\n", err)
		log.Fatal(err)
	}
	defer handle.Close()

	srcIP, err := getIfaceIPv4(iface)
	if err != nil {
		log.Fatal(err)
	}

	targetSubnet := "192.168.1.0/24"
	_, ipv4Net, err := net.ParseCIDR(targetSubnet)
	if err != nil {
		log.Fatal(err)
	}

	// Set BPF filter
	err = handle.SetBPFFilter("arp")
	if err != nil {
		fmt.Printf("Failed to set BPF filter: %v\n", err)
		log.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		crafter.ReadARP(handle, iface, stop)
	}()

	// Loop through all IPs in subnet
	for ip := ipv4Net.IP.Mask(ipv4Net.Mask); ipv4Net.Contains(ip); incIP(ip) {
		if ip.Equal(srcIP) {
			continue // Skip our own IP
		}

		// Send ARP request
		if err := crafter.SendARPRequest(handle, iface.HardwareAddr.String(), srcIP.String(), ip.String()); err != nil {
			log.Println("Error sending ARP request:", err)
			continue
		}

		time.Sleep(5 * time.Millisecond) // avoid flooding
	}

	// wait a bit for reply, then stop listener
	time.Sleep(10 * time.Second)
	close(stop)

	// wait for goroutine to finish before exiting
	wg.Wait()
}

func getIfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found on %s", iface.Name)
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

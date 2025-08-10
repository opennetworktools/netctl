package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(pingCmd)

	pingCmd.Flags().StringP("type", "T", "", "Type of Ping")
}

var pingCmd = &cobra.Command{
	Use:                   "ping",
	Short:                 "ping command is used to check reachability of an IP address",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pingType, err := cmd.Flags().GetString("type")
		if err != nil {
			log.Fatalf("Error getting type: %v", err)
		}
		dstIP := args[0]
		if pingType == "http" || pingType == "https" {
			httpPing(dstIP, pingType)
		} else if pingType == "tcp" {
			tcp3WHSPing(dstIP, "80")
		} else if pingType == "tls" {
			tcp3WHSPing(dstIP, "443")
		} else if pingType == "quic" {
			quicPing(dstIP)
		} else if pingType == "http3" {
			http3Ping(dstIP, pingType)
		} else {
			// defaultPing(dstIP)
		}
	},
}

// The following implementation will send a HEAD request after 3-way handshake and certificate exchanges.
func httpPing(dstIP, version string) {
	url := normalizeURL(dstIP, version)
	req, _ := http.NewRequest("HEAD", url, nil)
	fmt.Printf("URL or IP Address: %v\n", url)

	start := time.Now()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("HTTP Ping failed: %v", err)
	}
	_ = res.Body.Close()
	rtt := time.Since(start)

	fmt.Printf("HTTP Status: %v\n", res.StatusCode)
	fmt.Printf("RTT: %v\n", rtt)
}

func tcp3WHSPing(addr, port string) {
	address := net.JoinHostPort(addr, port)
	fmt.Printf("Address: %s\n", address)

	// TCP handshake
	tcpStart := time.Now()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		fmt.Printf("TCP connection failed: %v\n", err)
		return
	}
	tcpRTT := time.Since(tcpStart)
	fmt.Printf("TCP 3-way handshake RTT: %v\n", tcpRTT)

	// TLS handshake (only for HTTPS)
	if port == "443" {
		tlsStart := time.Now()
		tlsConn := tls.Client(conn, &tls.Config{ServerName: addr, InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			fmt.Printf("TLS handshake failed: %v\n", err)
			_ = conn.Close()
			return
		}
		tlsRTT := time.Since(tlsStart)
		fmt.Printf("TLS handshake RTT: %v\n", tlsRTT)
		_ = tlsConn.Close()
	} else {
		_ = conn.Close()
	}
}

// QUIC Ping
func quicPing(addr string) {
	// TLS config for QUIC
	tlsConf := &tls.Config{
		ServerName: addr,
		NextProtos: []string{http3.NextProtoH3},
	}

	quicConf := &quic.Config{}

	address := net.JoinHostPort(addr, "443")
	fmt.Printf("QUIC address: %s\n", address)

	start := time.Now()

	// QUIC handshake
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
	defer cancel()
	session, err := quic.DialAddr(ctx, address, tlsConf, quicConf)
	if err != nil {
		fmt.Printf("QUIC connection failed: %v\n", err)
		return
	}
	rtt := time.Since(start)

	fmt.Printf("QUIC handshake RTT: %v\n", rtt)

	// Close QUIC connection
	_ = session.CloseWithError(0, "done")
}

// HTTP3 Ping
func http3Ping(host, pingType string) {
	url := normalizeURL(host, pingType)

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{},
	}
	defer tr.Close()

	client := &http.Client{
		Transport: tr,
	}

	fmt.Printf("HTTP/3 URL: %s\n", url)
	start := time.Now()
	resp, err := client.Head(url)
	if err != nil {
		fmt.Printf("HTTP/3 request failed: %v\n", err)
		return
	}
	rtt := time.Since(start)

	fmt.Printf("HTTP/3 status: %s\n", resp.Status)
	fmt.Printf("HTTP/3 RTT: %v\n", rtt)

	_ = resp.Body.Close()
}

func normalizeURL(input, version string) string {
	if version == "http" {
		if !strings.HasPrefix(input, "http://") {
			return "http://" + input
		}
	} else if version == "https" {
		if !strings.HasPrefix(input, "https://") {
			return "https://" + input
		}
	} else if version == "http3" {
		if !strings.HasPrefix(input, "https://") {
			return "https://" + input
		}
	}
	return input
}

// Broken
// Need to resolve DNS for the domain name
// func defaultPing(dstIP string) {
// 	iface, err := net.InterfaceByName("en0") // works on macOS
// 	if err != nil {
// 		panic(err)
// 	}
// 	srcMAC := iface.HardwareAddr.String()
// 	addrs, err := iface.Addrs()
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	var srcIP net.IP
// 	for _, addr := range addrs {
// 		switch v := addr.(type) {
// 		case *net.IPNet:
// 			srcIP = v.IP
// 		case *net.IPAddr:
// 			srcIP = v.IP
// 		}
// 	}

// 	// Two separate handles for ARP and ICMP
// 	arpHandle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
// 	if err != nil {
// 		log.Fatalf("Failed to open ARP pcap handle: %v", err)
// 	}
// 	defer arpHandle.Close()

// 	icmpHandle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
// 	if err != nil {
// 		log.Fatalf("Failed to open ICMP pcap handle: %v", err)
// 	}
// 	defer icmpHandle.Close()

// 	id := uint16(rand.Intn(0xffff))
// 	seq := uint16(1)

// 	gatewayIP, err := gateway.DiscoverGateway()
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	ipNet := &net.IPNet{
// 		IP:   net.ParseIP(srcIP.String()),
// 		Mask: net.CIDRMask(24, 32),
// 	}

// 	dst := net.ParseIP(dstIP)
// 	if dst == nil {
// 		log.Fatalf("Invalid destination IP")
// 	}

// 	// Resolve ARP
// 	// Determine whether to ARP for destination or gateway
// 	arpTargetIP := dst
// 	if !ipNet.Contains(dst) {
// 		arpTargetIP = gatewayIP
// 	}

// 	err = arpHandle.SetBPFFilter("arp")
// 	if err != nil {
// 		log.Fatalf("Failed to set ARP BPF filter: %v", err)
// 	}

// 	// Start up a goroutine to read in packet data.
// 	stop := make(chan struct{})
// 	go crafter.ReadARP(arpHandle, iface, stop)
// 	defer close(stop)

// 	err = crafter.SendARPRequest(arpHandle, srcMAC, srcIP.String(), arpTargetIP.String())
// 	if err != nil {
// 		fmt.Printf("Failed to send ARP packet: %v\n", err)
// 		return
// 	}

// 	// TODO: implement redaing ARP

// 	err = icmpHandle.SetBPFFilter("icmp")
// 	if err != nil {
// 		log.Fatalf("Failed to set ICMP BPF filter: %v", err)
// 	}

// 	start := time.Now()

// 	// Start listener before sending Echo
// 	done := make(chan error, 1)
// 	go func() {
// 		done <- crafter.ListenForICMPEchoReply(icmpHandle, dstIP, id, seq)
// 	}()

// 	// Let listener start before sending
// 	time.Sleep(50 * time.Millisecond)

// 	// Send ICMP Echo Request
// 	err = crafter.SendICMPEcho(icmpHandle, srcMAC, dstMAC.String(), srcIP.String(), dstIP, id, seq)
// 	if err != nil {
// 		log.Fatalf("sendICMPEcho: %v", err)
// 	}

// 	// Wait for listener result
// 	if err := <-done; err != nil {
// 		fmt.Println("No Pong")
// 		log.Fatalf("listenForICMPEchoReply: %v", err)
// 	}

// 	rtt := time.Since(start)
// 	fmt.Println("Pong")
// 	fmt.Printf("RTT: %v\n", rtt)
// }

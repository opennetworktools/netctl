package cmd

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/opennetworktools/netctl/internal/crafter"

	"github.com/gopacket/gopacket/pcap"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(craftCmd)
	craftCmd.AddCommand(arpCmd)
	craftCmd.AddCommand(tcpCmd)

	// arp command flags
	arpCmd.Flags().StringP("srcmac", "M", "", "Source MAC address of the Ethernet Frame")
	arpCmd.Flags().StringP("senderip", "S", "", "Sender IP address of the ARP Payload")
	arpCmd.Flags().StringP("targetip", "T", "", "Target IP address of the ARP Payload")

	arpCmd.MarkFlagRequired("srcmac")
	arpCmd.MarkFlagRequired("senderip")
	arpCmd.MarkFlagRequired("targetip")

	// tcp command flags
	// more flags like sequence number, window size, can be added as needed
	tcpCmd.Flags().StringP("srcmac", "M", "", "Source MAC address of the Ethernet Frame")
	tcpCmd.Flags().StringP("dstmac", "m", "", "Destination MAC address of the Ethernet Frame")
	tcpCmd.Flags().StringP("srcip", "S", "", "Source IP address of the IP Header")
	tcpCmd.Flags().StringP("dstip", "D", "", "Destination IP address of the IP Header")
	tcpCmd.Flags().IntP("srcport", "P", 54321, "Source Port Number of the TCP Header")
	tcpCmd.Flags().IntP("dstport", "p", 80, "Destination Port Number of the TCP Header")
	tcpCmd.Flags().IntP("ttl", "T", 64, "TTL (Time to Live) of the IP Header")

	tcpCmd.MarkFlagRequired("srcmac")
	tcpCmd.MarkFlagRequired("dstmac")
	tcpCmd.MarkFlagRequired("srcip")
	tcpCmd.MarkFlagRequired("dstip")
	tcpCmd.MarkFlagRequired("dstport")
}

var craftCmd = &cobra.Command{
	Use:                   "craft",
	Short:                 "craft command is used to create a frame/packet",
	Long:                  `craft command is used to create a frame/packet flags`,
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var arpCmd = &cobra.Command{
	Use:                   "arp",
	Short:                 "arp command is used to create a ARP Request/Reply packet",
	Long:                  `arp command is used to create a ARP Request/Reply packet by passing flags`,
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		srcMAC, err := cmd.Flags().GetString("srcmac")
		if err != nil {
			log.Fatalf("Error getting srcmac: %v", err)
		}

		senderIP, err := cmd.Flags().GetString("senderip")
		if err != nil {
			log.Fatalf("Error getting senderip: %v", err)
		}

		targetIP, err := cmd.Flags().GetString("targetip")
		if err != nil {
			log.Fatalf("Error getting targetip: %v", err)
		}

		// fmt.Printf("Source MAC: %v, Sender IP: %v, Target IP: %v\n", srcMAC, senderIP, targetIP)

		iface, err := net.InterfaceByName("en0")
		if err != nil {
			panic(err)
		}

		handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
		if err != nil {
			fmt.Printf("Failed to open pcap handle: %v\n", err)
			return
		}
		defer handle.Close()

		// Set BPF filter
		err = handle.SetBPFFilter("arp")
		if err != nil {
			fmt.Printf("Failed to set BPF filter: %v\n", err)
			return
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			crafter.ReadARP(handle, iface, stop)
		}()

		// Send ARP Request
		err = crafter.SendARPRequest(handle, srcMAC, senderIP, targetIP)
		if err != nil {
			fmt.Printf("Failed to send ARP packet: %v\n", err)
			close(stop) // stop listening
			wg.Wait()
			return
		}

		// wait a bit for reply, then stop listener
		time.Sleep(3 * time.Second)
		close(stop)

		// wait for goroutine to finish before exiting
		wg.Wait()
	},
}

var tcpCmd = &cobra.Command{
	Use:                   "tcp",
	Short:                 "tcp command is used to create TCP SYN packet",
	Long:                  `tcp command is used to create TCP SYN packet by passing flags`,
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		srcMAC, err := cmd.Flags().GetString("srcmac")
		if err != nil {
			log.Fatalf("Error getting srcmac: %v", err)
		}

		dstMAC, err := cmd.Flags().GetString("dstmac")
		if err != nil {
			log.Fatalf("Error getting dstmac: %v", err)
		}

		srcIP, err := cmd.Flags().GetString("srcip")
		if err != nil {
			log.Fatalf("Error getting srcip: %v", err)
		}

		dstIP, err := cmd.Flags().GetString("dstip")
		if err != nil {
			log.Fatalf("Error getting dstip: %v", err)
		}

		srcPort, err := cmd.Flags().GetInt("srcport")
		if err != nil {
			log.Fatalf("Error getting srcport: %v", err)
		}

		dstPort, err := cmd.Flags().GetInt("dstport")
		if err != nil {
			log.Fatalf("Error getting dstport: %v", err)
		}

		ttl, err := cmd.Flags().GetInt("ttl")
		if err != nil {
			log.Fatalf("Error getting ttl: %v", err)
		}

		iface, err := net.InterfaceByName("en0")
		if err != nil {
			panic(err)
		}

		handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
		if err != nil {
			fmt.Printf("Failed to open pcap handle: %v\n", err)
			return
		}
		defer handle.Close()

		err = handle.SetBPFFilter("tcp")
		if err != nil {
			fmt.Printf("Failed to set BPF filter: %v\n", err)
			return
		}

		// srcMAC := "3a:7e:48:98:7d:8c"
		// dstMAC := "c2:4a:89:08:39:ea"
		// srcIP := "192.168.1.100"
		// dstIP := "192.168.1.102"
		// srcPort := 54321
		// dstPort := 443

		// Send TCP SYN
		err = crafter.SendTCPSYN(handle, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, ttl)
		if err != nil {
			fmt.Printf("Failed to send TCP SYN packet: %v\n", err)
			return
		}

		// Listen for TCP SYN-ACK or RST-ACK
		err = crafter.ListenForTCPSYNACKOrRST(handle, srcIP, dstIP, srcPort, dstPort)
		if err != nil {
			fmt.Printf("Failed to receive TCP response: %v\n", err)
		}
	},
}

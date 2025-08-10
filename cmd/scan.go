package cmd

import (
	"log"

	"github.com/opennetworktools/netctl/internal/scan"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringP("type", "T", "", "Type of Scan")
}

var scanCmd = &cobra.Command{
	Use:                   "scan",
	Short:                 "Scan your LAN",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		scanType, err := cmd.Flags().GetString("type")
		if err != nil {
			log.Fatalf("Error getting type: %v", err)
		}
		if scanType == "arp" {
			scan.ARPScan()
		}
	},
}

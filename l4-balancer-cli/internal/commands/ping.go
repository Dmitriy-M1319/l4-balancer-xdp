package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/client"
	"github.com/spf13/cobra"
)

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Check balancer availability",
	Long:  `Sends a Ping RPC to the balancer and reports latency.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		c, err := client.New(flagAddress, flagTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer c.Close()

		elapsed := time.Since(start)
		fmt.Printf("PONG from %s  latency=%s\n", flagAddress, elapsed.Round(time.Millisecond))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pingCmd)
}

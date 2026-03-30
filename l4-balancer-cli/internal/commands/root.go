package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	flagAddress string
	flagTimeout time.Duration
)

var rootCmd = &cobra.Command{
	Use:   "l4-balancer-cli",
	Short: "CLI for managing the XDP L4 load balancer",
	Long: `l4-balancer-cli is a command-line tool for managing the XDP L4 load balancer
via its gRPC controlplane API`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(
		&flagAddress, "address", "a", "localhost:52001",
		"balancer gRPC address (host:port)",
	)
	rootCmd.PersistentFlags().DurationVarP(
		&flagTimeout, "timeout", "t", 10*time.Second,
		"request timeout",
	)
}

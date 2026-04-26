package commands

import (
	"fmt"
	"os"
	"time"

	pb "github.com/Dmitriy-M1319/l4-balancer-cli/api"
	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/client"
	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/output"
	"github.com/spf13/cobra"
)

var blacklistCmd = &cobra.Command{
	Use:   "blacklist",
	Short: "Manage current ip blacklist info",
}

var blacklistGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Print the current current ip blacklist info",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New(flagAddress, flagTimeout)
		if err != nil {
			return err
		}
		defer c.Close()

		resp, err := c.GetBlackList()
		if err != nil {
			return fmt.Errorf("GetBlackList: %w", err)
		}
		printBlackListTable(resp)
		return nil
	},
}

func printBlackListTable(cfg *pb.GetBlackListResponse) {
	blocked := cfg.GetList()
	if len(blocked) == 0 {
		output.PrintWarning("empty blacklist")
		return
	}

	svcTable := output.NewTable("IP", "TIMESTAMP")
	for _, b := range blocked {
		svcTable.AddRow(
			b.GetIpAddress(),
			time.Unix(int64(b.GetTimestamp()), 0).Format("2006-01-02 15:04:05"),
		)
	}
	fmt.Println("Blacklist:")
	svcTable.Render(os.Stdout)
}

func init() {
	blacklistCmd.AddCommand(blacklistGetCmd)
	rootCmd.AddCommand(blacklistCmd)
}

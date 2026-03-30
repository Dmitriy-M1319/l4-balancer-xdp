package commands

import (
	"fmt"
	"os"

	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/client"
	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	svcProtocol        string
	svcIPVersion       uint32
	svcEnabledOnly     bool
	svcIncludeBackends bool
	svcIncludeMetrics  bool
)

var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "List services",
	Long: `Lists all services registered in the balancer.

Optionally filter by protocol or IP version, and include backend/metrics details.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		defer c.Close()

		resp, err := c.ListServices(client.ListServicesOpts{
			Protocol:        svcProtocol,
			IpVersion:       svcIPVersion,
			EnabledOnly:     svcEnabledOnly,
			IncludeBackends: svcIncludeBackends,
			IncludeMetrics:  svcIncludeMetrics,
		})
		if err != nil {
			return fmt.Errorf("ListServices: %w", err)
		}

		services := resp.GetServices()
		if len(services) == 0 {
			output.PrintWarning("no services found")
			return nil
		}

		svcTable := output.NewTable("NAME", "VIP", "PORT", "PROTO", "BACKENDS")
		for _, s := range services {
			svcTable.AddRow(
				s.Name,
				s.Vip,
				fmt.Sprintf("%d", s.Port),
				s.Protocol,
				fmt.Sprintf("%d", len(s.GetBackends())),
			)
		}
		svcTable.Render(os.Stdout)

		if svcIncludeMetrics {
			for _, s := range services {
				m := s.GetMetrics()
				if m == nil {
					continue
				}
				fmt.Printf("\nMetrics for %q:\n", s.Name)
				mTable := output.NewTable("METRIC", "VALUE")
				mTable.AddRow("total_packets", fmt.Sprintf("%d", m.TotalPackets))
				mTable.AddRow("tcp_syn_packets", fmt.Sprintf("%d", m.TcpSynPackets))
				mTable.AddRow("prepared_packets", fmt.Sprintf("%d", m.PreparedPackets))
				mTable.AddRow("active_connections", fmt.Sprintf("%d", m.ActiveConnections))
				mTable.AddRow("total_bytes", output.FormatBytes(m.TotalBytes))
				mTable.Render(os.Stdout)
			}
		}

		if svcIncludeBackends {
			for _, s := range services {
				if len(s.GetBackends()) == 0 {
					continue
				}
				fmt.Printf("\nBackends for %q:\n", s.Name)
				var headers []string
				if svcIncludeMetrics {
					headers = []string{"IP", "PORT", "WEIGHT", "STATUS", "PACKETS", "BYTES", "CONNS"}
				} else {
					headers = []string{"IP", "PORT", "WEIGHT", "STATUS"}
				}
				bTable := output.NewTable(headers...)
				for _, b := range s.GetBackends() {
					row := []string{
						b.Ip,
						fmt.Sprintf("%d", b.Port),
						fmt.Sprintf("%d", b.Weight),
						output.EnabledLabel(b.Enabled),
					}
					if svcIncludeMetrics {
						m := b.GetMetrics()
						if m != nil {
							row = append(row,
								fmt.Sprintf("%d", m.TotalPackets),
								output.FormatBytes(m.TotalBytes),
								fmt.Sprintf("%d", m.ActiveConnections),
							)
						} else {
							row = append(row, "—", "—", "—")
						}
					}
					bTable.AddRow(row...)
				}
				bTable.Render(os.Stdout)
			}
		}

		return nil
	},
}

func init() {
	servicesCmd.Flags().StringVar(&svcProtocol, "protocol", "", "Filter by protocol: tcp|udp")
	servicesCmd.Flags().Uint32Var(&svcIPVersion, "ip-version", 0, "Filter by IP version: 4|6")
	servicesCmd.Flags().BoolVar(&svcEnabledOnly, "enabled-only", false, "Show only services with at least one enabled backend")
	servicesCmd.Flags().BoolVar(&svcIncludeBackends, "backends", false, "Include backend list")
	servicesCmd.Flags().BoolVar(&svcIncludeMetrics, "metrics", false, "Include metrics (implies --backends)")

	rootCmd.AddCommand(servicesCmd)
}

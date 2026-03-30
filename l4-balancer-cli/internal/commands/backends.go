package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/client"
	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/output"
	"github.com/spf13/cobra"
)

var backendsCmd = &cobra.Command{
	Use:   "backends",
	Short: "Manage backends",
}

var backendsListMetrics bool

var backendsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all backends across all services",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		defer c.Close()

		resp, err := c.ListBackends(backendsListMetrics)
		if err != nil {
			return fmt.Errorf("ListBackends: %w", err)
		}

		backends := resp.GetBackends()
		if len(backends) == 0 {
			output.PrintWarning("no backends found")
			return nil
		}

		var headers []string
		if backendsListMetrics {
			headers = []string{"IP", "PORT", "WEIGHT", "STATUS", "PACKETS", "SYN", "BYTES", "CONNS"}
		} else {
			headers = []string{"IP", "PORT", "WEIGHT", "STATUS"}
		}

		t := output.NewTable(headers...)
		for _, b := range backends {
			row := []string{
				b.Ip,
				fmt.Sprintf("%d", b.Port),
				fmt.Sprintf("%d", b.Weight),
				output.EnabledLabel(b.Enabled),
			}
			if backendsListMetrics {
				m := b.GetMetrics()
				if m != nil {
					row = append(row,
						fmt.Sprintf("%d", m.TotalPackets),
						fmt.Sprintf("%d", m.TcpSynPackets),
						output.FormatBytes(m.TotalBytes),
						fmt.Sprintf("%d", m.ActiveConnections),
					)
				} else {
					row = append(row, "—", "—", "—", "—")
				}
			}
			t.AddRow(row...)
		}
		t.Render(os.Stdout)
		return nil
	},
}

var (
	backendStatusService     string
	backendStatusVip         string
	backendStatusServicePort uint32
	backendStatusIp          string
	backendStatusPort        uint32
)

func makeBackendStatusCmd(enable bool) *cobra.Command {
	verb := "disable"
	if enable {
		verb = "enable"
	}

	return &cobra.Command{
		Use:   verb,
		Short: fmt.Sprintf("%s a backend", strings.Title(verb)),
		Long: fmt.Sprintf(`%s the specified backend.

The service can be identified either by --service (name) or by --vip + --service-port.`,
			strings.Title(verb)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if backendStatusIp == "" {
				return fmt.Errorf("--backend-ip is required")
			}
			if backendStatusService == "" && backendStatusVip == "" {
				return fmt.Errorf("either --service or --vip must be specified")
			}

			c, err := newClient()
			if err != nil {
				return err
			}
			defer c.Close()

			resp, err := c.SetBackendStatus(client.SetBackendStatusOpts{
				ServiceName: backendStatusService,
				Vip:         backendStatusVip,
				ServicePort: backendStatusServicePort,
				BackendIp:   backendStatusIp,
				BackendPort: backendStatusPort,
				Status:      enable,
			})
			if err != nil {
				return fmt.Errorf("SetBackendStatus: %w", err)
			}

			if resp.GetSuccess() {
				action := "disabled"
				if enable {
					action = "enabled"
				}
				output.PrintSuccess(fmt.Sprintf("backend %s:%d %s", backendStatusIp, backendStatusPort, action))
				return nil
			}

			output.PrintError(resp.GetError())
			os.Exit(1)
			return nil
		},
	}
}

func init() {
	backendsListCmd.Flags().BoolVar(&backendsListMetrics, "metrics", false, "Include metrics")

	enableCmd := makeBackendStatusCmd(true)
	disableCmd := makeBackendStatusCmd(false)

	for _, c := range []*cobra.Command{enableCmd, disableCmd} {
		c.Flags().StringVar(&backendStatusService, "service", "", "Service name")
		c.Flags().StringVar(&backendStatusVip, "vip", "", "Service VIP (alternative to --service)")
		c.Flags().Uint32Var(&backendStatusServicePort, "service-port", 0, "Service port (used with --vip)")
		c.Flags().StringVar(&backendStatusIp, "backend-ip", "", "Backend IP address (required)")
		c.Flags().Uint32Var(&backendStatusPort, "backend-port", 0, "Backend port")
	}

	backendsCmd.AddCommand(backendsListCmd, enableCmd, disableCmd)
	rootCmd.AddCommand(backendsCmd)
}

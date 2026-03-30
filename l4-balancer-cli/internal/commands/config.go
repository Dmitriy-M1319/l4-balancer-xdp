package commands

import (
	"encoding/json"
	"fmt"
	"os"

	pb "github.com/Dmitriy-M1319/l4-balancer-cli/api"
	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/client"
	"github.com/Dmitriy-M1319/l4-balancer-cli/internal/output"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage balancer configuration",
}

var configGetJsonFlag bool

var configGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Print the current balancer configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		defer c.Close()

		resp, err := c.GetConfig()
		if err != nil {
			return fmt.Errorf("GetConfig: %w", err)
		}

		if configGetJsonFlag {
			return printConfigJSON(resp.GetConfig())
		}
		printConfigTable(resp.GetConfig())
		return nil
	},
}

func printConfigJSON(cfg *pb.Configuration) error {
	type backendJSON struct {
		IP        string `json:"ip"`
		Port      uint32 `json:"port"`
		Weight    uint32 `json:"weight"`
		Enabled   bool   `json:"enabled"`
		IPVersion uint32 `json:"ip_version"`
	}
	type serviceJSON struct {
		Name      string        `json:"name"`
		VIP       string        `json:"vip"`
		Port      uint32        `json:"port"`
		Protocol  string        `json:"protocol"`
		IPVersion uint32        `json:"ip_version"`
		Algorithm string        `json:"algorithm"`
		Backends  []backendJSON `json:"backends"`
	}
	type configJSON struct {
		Services []serviceJSON `json:"services"`
	}

	out := configJSON{}
	for _, s := range cfg.GetServices() {
		sj := serviceJSON{
			Name:      s.GetName(),
			VIP:       s.GetVip(),
			Port:      s.GetPort(),
			Protocol:  s.GetProtocol(),
			IPVersion: s.GetIpVersion(),
			Algorithm: s.GetAlgorithm(),
		}
		for _, b := range s.GetBackends() {
			sj.Backends = append(sj.Backends, backendJSON{
				IP:        b.Ip,
				Port:      b.Port,
				Weight:    b.Weight,
				Enabled:   b.Enabled,
				IPVersion: b.IpVersion,
			})
		}
		out.Services = append(out.Services, sj)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printConfigTable(cfg *pb.Configuration) {
	services := cfg.GetServices()
	if len(services) == 0 {
		output.PrintWarning("configuration is empty")
		return
	}

	svcTable := output.NewTable("NAME", "VIP", "PORT", "PROTO", "IP_VER", "ALGORITHM", "BACKENDS")
	for _, s := range services {
		svcTable.AddRow(
			s.GetName(),
			s.GetVip(),
			fmt.Sprintf("%d", s.GetPort()),
			s.GetProtocol(),
			fmt.Sprintf("IPv%d", s.GetIpVersion()),
			s.GetAlgorithm(),
			fmt.Sprintf("%d", len(s.GetBackends())),
		)
	}
	fmt.Println("Services:")
	svcTable.Render(os.Stdout)

	for _, s := range services {
		if len(s.GetBackends()) == 0 {
			continue
		}
		fmt.Printf("\nBackends for %q:\n", s.GetName())
		bTable := output.NewTable("IP", "PORT", "WEIGHT", "ENABLED", "IP_VER")
		for _, b := range s.GetBackends() {
			bTable.AddRow(
				b.Ip,
				fmt.Sprintf("%d", b.Port),
				fmt.Sprintf("%d", b.Weight),
				output.BoolMark(b.Enabled),
				fmt.Sprintf("IPv%d", b.IpVersion),
			)
		}
		bTable.Render(os.Stdout)
	}
}

var configUpdateFile string

var configUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Apply a new configuration from a JSON file",
	Long: `Reads a JSON configuration file and sends it to the balancer.

File format:
  {
    "services": [
      {
        "name": "my-svc",
        "vip": "10.0.0.1",
        "port": 80,
        "protocol": "tcp",
        "ip_version": 4,
        "algorithm": "rr",
        "backends": [
          { "ip": "192.168.1.1", "port": 8080, "weight": 1, "enabled": true, "ip_version": 4 }
        ]
      }
    ]
  }`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if configUpdateFile == "" {
			return fmt.Errorf("--file is required")
		}

		data, err := os.ReadFile(configUpdateFile)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		cfg, err := parseConfigJSON(data)
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}

		c, err := newClient()
		if err != nil {
			return err
		}
		defer c.Close()

		resp, err := c.UpdateConfig(cfg)
		if err != nil {
			return fmt.Errorf("UpdateConfig: %w", err)
		}

		if resp.GetSuccess() {
			output.PrintSuccess("configuration applied successfully")
			return nil
		}

		output.PrintError("configuration rejected:")
		for _, e := range resp.GetErrors() {
			fmt.Printf("  • %s\n", e)
		}
		os.Exit(1)
		return nil
	},
}

func parseConfigJSON(data []byte) (*pb.Configuration, error) {
	type backendJSON struct {
		IP        string `json:"ip"`
		Port      uint32 `json:"port"`
		Weight    uint32 `json:"weight"`
		Enabled   bool   `json:"enabled"`
		IPVersion uint32 `json:"ip_version"`
	}
	type serviceJSON struct {
		Name      string        `json:"name"`
		VIP       string        `json:"vip"`
		Port      uint32        `json:"port"`
		Protocol  string        `json:"protocol"`
		IPVersion uint32        `json:"ip_version"`
		Algorithm string        `json:"algorithm"`
		Backends  []backendJSON `json:"backends"`
	}
	type configJSON struct {
		Services []serviceJSON `json:"services"`
	}

	var raw configJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	cfg := &pb.Configuration{}
	for _, s := range raw.Services {
		svc := &pb.Service{
			Name:      s.Name,
			Vip:       s.VIP,
			Port:      s.Port,
			Protocol:  s.Protocol,
			IpVersion: s.IPVersion,
			Algorithm: s.Algorithm,
		}
		for _, b := range s.Backends {
			svc.Backends = append(svc.Backends, &pb.Backend{
				Ip:        b.IP,
				Port:      b.Port,
				Weight:    b.Weight,
				Enabled:   b.Enabled,
				IpVersion: b.IPVersion,
			})
		}
		cfg.Services = append(cfg.Services, svc)
	}
	return cfg, nil
}

func init() {
	configGetCmd.Flags().BoolVar(&configGetJsonFlag, "json", false, "Output as JSON")

	configUpdateCmd.Flags().StringVarP(&configUpdateFile, "file", "f", "", "Path to JSON config file (required)")

	configCmd.AddCommand(configGetCmd, configUpdateCmd)
	rootCmd.AddCommand(configCmd)
}

func newClient() (*client.Client, error) {
	c, err := client.New(flagAddress, flagTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", flagAddress, err)
	}
	return c, nil
}

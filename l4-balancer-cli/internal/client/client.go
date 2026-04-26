package client

import (
	"context"
	"fmt"
	"time"

	pb "github.com/Dmitriy-M1319/l4-balancer-cli/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultTimeout = 10 * time.Second

type Client struct {
	conn    *grpc.ClientConn
	api     pb.L4BalancerApiClient
	timeout time.Duration
}

func New(address string, timeout time.Duration) (*Client, error) {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}

	c := &Client{
		conn:    conn,
		api:     pb.NewL4BalancerApiClient(conn),
		timeout: timeout,
	}

	if err := c.ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("balancer unreachable at %s: %w", address, err)
	}

	return c, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	_, err := c.api.Ping(ctx, &pb.EmptyMessage{})
	return err
}

func (c *Client) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.timeout)
}

func (c *Client) GetConfig() (*pb.GetConfigResponse, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	return c.api.GetConfig(ctx, &pb.GetConfigRequest{})
}

func (c *Client) GetBlackList() (*pb.GetBlackListResponse, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	return c.api.GetBlackList(ctx, &pb.EmptyMessage{})
}

func (c *Client) UpdateConfig(cfg *pb.Configuration) (*pb.UpdateConfigResponse, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	return c.api.UpdateConfig(ctx, &pb.UpdateConfigRequest{Config: cfg})
}

func (c *Client) ListServices(opts ListServicesOpts) (*pb.ListServicesResponse, error) {
	ctx, cancel := c.ctx()
	defer cancel()

	req := &pb.ListServicesRequest{
		IncludeBackends: opts.IncludeBackends,
		IncludeMetrics:  opts.IncludeMetrics,
	}

	filter := &pb.ServiceFilter{EnabledOnly: opts.EnabledOnly}
	hasFilter := opts.EnabledOnly
	if opts.Protocol != "" {
		filter.Protocol = &opts.Protocol
		hasFilter = true
	}
	if opts.IpVersion != 0 {
		filter.IpVersion = &opts.IpVersion
		hasFilter = true
	}
	if hasFilter {
		req.Filter = filter
	}

	return c.api.ListServices(ctx, req)
}

func (c *Client) ListBackends(includeMetrics bool) (*pb.ListBackendsResponse, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	return c.api.ListBackends(ctx, &pb.ListBackendsRequest{IncludeMetrics: includeMetrics})
}

func (c *Client) SetBackendStatus(req SetBackendStatusOpts) (*pb.SetBackendStatusResponse, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	return c.api.SetBackendStatus(ctx, &pb.SetBackendStatusRequest{
		ServiceName: req.ServiceName,
		Vip:         req.Vip,
		ServicePort: req.ServicePort,
		BackendIp:   req.BackendIp,
		BackendPort: req.BackendPort,
		Status:      req.Status,
	})
}

type ListServicesOpts struct {
	Protocol        string
	IpVersion       uint32
	EnabledOnly     bool
	IncludeBackends bool
	IncludeMetrics  bool
}

type SetBackendStatusOpts struct {
	ServiceName string
	Vip         string
	ServicePort uint32
	BackendIp   string
	BackendPort uint32
	Status      bool
}

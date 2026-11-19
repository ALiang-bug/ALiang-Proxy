package mobile

import (
	"context"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/group"

	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
)

func coreContext() context.Context {
	in := inbound.NewRegistry()
	tun.RegisterInbound(in)
	out := outbound.NewRegistry()
	trojan.RegisterOutbound(out)
	vless.RegisterOutbound(out)
	group.RegisterSelector(out)
	resolvers := dns.NewTransportRegistry()
	local.RegisterTransport(resolvers)
	transport.RegisterHTTPS(resolvers)
	return box.Context(context.Background(), in, out, endpoint.NewRegistry(), resolvers, service.NewRegistry(), certificate.NewRegistry())
}

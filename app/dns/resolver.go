package dns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	client *dns.Client
}

func NewResolver() *Resolver {
	return &Resolver{
		client: &dns.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	resp, _, err := r.client.ExchangeContext(ctx, m, net.JoinHostPort("8.8.8.8", "53"))
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}

	return ips, nil
}

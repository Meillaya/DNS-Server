package dns

import (
	"fmt"
	"net"
	"github.com/miekg/dns"
)

type Server struct {
	host string
	port int
}

func NewServer(host string, port int) *Server {
	return &Server{
		host: host,
		port: port,
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	server := &dns.Server{Addr: addr, Net: "udp"}

	dns.HandleFunc(".", s.handleDNSRequest)

	fmt.Printf("Starting DNS server on %s\n", addr)
	return server.ListenAndServe()
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			switch q.Qtype {
			case dns.TypeA:
				ip := net.ParseIP("127.0.0.1")
				if ip != nil {
					rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip.String()))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		}
	}

	w.WriteMsg(m)
}

func (s *Server) Stop() {
	// Implement graceful shutdown logic here
	fmt.Println("Stopping DNS server")
}

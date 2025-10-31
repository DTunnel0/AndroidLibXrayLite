package libv2ray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	v2internet "github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

type protectSet interface {
	Protect(int) bool
}

type resolved struct {
	domain       string
	ips          []net.IP
	port         int
	lastResolved time.Time
	ipIdx        int
	ipLock       sync.Mutex
	lastSwitched time.Time
}

func (r *resolved) NextIP() {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()

	if len(r.ips) <= 1 {
		return
	}

	now := time.Now()
	if now.Sub(r.lastSwitched) < time.Second*5 {
		return
	}

	r.ipIdx = (r.ipIdx + 1) % len(r.ips)
	r.lastSwitched = time.Now()
}

func (r *resolved) currentIP() net.IP {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()

	if len(r.ips) > 0 {
		return r.ips[r.ipIdx]
	}

	return nil
}

func NewProtectedDialer(p protectSet) *ProtectedDialer {
	return &ProtectedDialer{
		resolver:   &net.Resolver{PreferGo: false},
		protectSet: p,
	}
}

type ProtectedDialer struct {
	currentServer string
	resolveChan   chan struct{}

	vServer  *resolved
	resolver *net.Resolver

	protectSet
}

func (d *ProtectedDialer) IsVServerReady() bool {
	return (d.vServer != nil)
}

func (d *ProtectedDialer) PrepareResolveChan() {
	d.resolveChan = make(chan struct{})
}

func (d *ProtectedDialer) ResolveChan() chan struct{} {
	return d.resolveChan
}

func (d *ProtectedDialer) lookupAddr(addr string) (*resolved, error) {
	var (
		err        error
		host, port string
		portNum    int
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if host, port, err = net.SplitHostPort(addr); err != nil {
		return nil, err
	}

	if portNum, err = d.resolver.LookupPort(ctx, "tcp", port); err != nil {
		return nil, err
	}

	addrs, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("domain %s Failed to resolve", addr)
	}

	ips := make([]net.IP, 0)
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}

	rs := &resolved{
		domain:       host,
		ips:          ips,
		port:         portNum,
		lastResolved: time.Now(),
	}

	return rs, nil
}

func (d *ProtectedDialer) PrepareDomain(domainName string, closeCh <-chan struct{}) {
	d.currentServer = domainName

	maxRetry := 10
	for {
		if maxRetry == 0 {
			return
		}

		resolved, err := d.lookupAddr(domainName)
		if err != nil {
			maxRetry--
			select {
			case <-closeCh:

				return
			case <-time.After(time.Second * 2):
			}
			continue
		}

		d.vServer = resolved
		return
	}
}

func (d *ProtectedDialer) getFd(network v2net.Network) (fd int, err error) {
	switch network {
	case v2net.Network_TCP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	case v2net.Network_UDP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	default:
		err = fmt.Errorf("unknow network")
	}
	return
}

func (d *ProtectedDialer) Dial(
	ctx context.Context,
	src v2net.Address,
	dest v2net.Destination,
	sockopt *v2internet.SocketConfig,
) (net.Conn, error) {
	addr := dest.NetAddr()
	if addr == d.currentServer {
		if d.vServer == nil {
			log.Println("Dial pending prepare  ...", addr)
			<-d.resolveChan

			if d.vServer == nil {
				return nil, fmt.Errorf("fail to prepare domain %s", d.currentServer)
			}
		}

		fd, err := d.getFd(dest.Network)
		if err != nil {
			return nil, err
		}

		curIP := d.vServer.currentIP()
		conn, err := d.fdConn(ctx, curIP, d.vServer.port, dest.Network, fd)
		if err != nil {
			d.vServer.NextIP()
			return nil, err
		}

		return conn, nil
	}

	resolved, err := d.lookupAddr(addr)
	if err != nil {
		return nil, err
	}

	fd, err := d.getFd(dest.Network)
	if err != nil {
		return nil, err
	}

	return d.fdConn(ctx, resolved.ips[0], resolved.port, dest.Network, fd)
}

func (d *ProtectedDialer) DestIpAddress() net.IP {
	return d.vServer.currentIP()
}

func (d *ProtectedDialer) fdConn(ctx context.Context, ip net.IP, port int, network v2net.Network, fd int) (net.Conn, error) {
	defer unix.Close(fd)

	if !d.Protect(fd) {
		return nil, errors.New("fail to protect")
	}

	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], ip.To16())

	if network == v2net.Network_UDP {
		if err := unix.Bind(fd, &unix.SockaddrInet6{}); err != nil {
			return nil, err
		}
	} else {
		if err := unix.Connect(fd, sa); err != nil {
			return nil, err
		}
	}

	file := os.NewFile(uintptr(fd), "Socket")
	if file == nil {
		return nil, errors.New("fdConn fd invalid")
	}
	defer file.Close()

	if network == v2net.Network_UDP {
		packetConn, err := net.FilePacketConn(file)
		if err != nil {
			return nil, err
		}
		return &v2internet.PacketConnWrapper{
			Conn: packetConn,
			Dest: &net.UDPAddr{
				IP:   ip,
				Port: port,
			},
		}, nil
	} else {
		conn, err := net.FileConn(file)
		if err != nil {

			return nil, err
		}
		return conn, nil
	}
}

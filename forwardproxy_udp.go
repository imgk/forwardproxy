package forwardproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"go.uber.org/zap"
)

const (
	RequestProtocol = "connect-udp"

	ConnectUDPBindHeader     = "Connect-Udp-Bind"
	ProxyPublicAddressHeader = "Proxy-Public-Address"

	CompressionAssignValue = 0x1C0FE323
	CompressionCloseValue  = 0x1C0FE324
)

var (
	CapsuleProtocolHeaderValue string
	ConnectUDPBindHeaderValue  string
)

func init() {
	str, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	CapsuleProtocolHeaderValue = str
	ConnectUDPBindHeaderValue = str
}

type Payload interface {
	Send(io.Writer) error
}

type Datagram struct {
	Type    uint64
	Length  uint64
	Payload Payload
}

func (data *Datagram) Receive(r io.Reader) error {
	return data.ReceiveBuffer(r, make([]byte, 1024*32))
}

func (data *Datagram) ReceiveBuffer(r io.Reader, b []byte) error {
	err := error(nil)

	rr := quicvarint.NewReader(r)
	data.Type, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram type error: %w", err)
	}

	data.Length, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram length error: %w", err)
	}

	bb := b[:data.Length]
	_, err = io.ReadFull(r, bb)
	if err != nil {
		return fmt.Errorf("receive datagram payload error: %w", err)
	}

	data.Payload = &BytePayload{Payload: bb}

	return nil
}

func (data *Datagram) Send(w io.Writer) error {
	bb := quicvarint.Append(quicvarint.Append(make([]byte, 0, 16), data.Type), data.Length)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send type, length error: %w", err)
	}

	err = data.Payload.Send(w)
	if err != nil {
		return fmt.Errorf("send UDP payload error: %w", err)
	}

	return nil
}

type BytePayload struct {
	Payload []byte
}

func (data *BytePayload) Send(w io.Writer) error {
	_, err := w.Write(data.Payload)
	return err
}

type CompressedPayload struct {
	ContextID uint64
	Payload   []byte
}

func (data *CompressedPayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *CompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}
	data.ContextID = id
	data.Payload = b[nr:]
	return nil
}

func (data *CompressedPayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID)) + uint64(len(data.Payload))
}

type UncompressedPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
	Payload   []byte
}

func (data *UncompressedPayload) Send(w io.Writer) error {
	bb := append(append(append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion)),
		data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send uncompressed payload header error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *UncompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	switch b[nr] { // IPVersion
	case 4:
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
		data.Payload = b[nr+7:]
	case 6:
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
		data.Payload = b[nr+19:]
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *UncompressedPayload) Len() uint64 {
	switch data.IPVersion {
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2 + uint64(len(data.Payload))
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2 + uint64(len(data.Payload))
	}
	return 0
}

type CompressionAssignPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
}

func (data *CompressionAssignPayload) Send(w io.Writer) error {
	bb := append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion))
	if data.IPVersion != 0 {
		bb = append(append(bb, data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	}

	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send compression assign payload header error: %w", err)
	}

	return nil
}

func (data *CompressionAssignPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	switch b[nr] { // IPVersion
	case 0:
		if id != 2 {
			// use 2 for default uncompressed context id
			return fmt.Errorf("cannot use context id: %v as uncomressed id", id)
		}

		data.IPVersion = 0
	case 4:
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
	case 6:
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *CompressionAssignPayload) Len() uint64 {
	switch data.IPVersion {
	case 0:
		// context id is 2
		return 1 + 1
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2
	}
	return 0
}

type CompressionClosePayload struct {
	ContextID uint64
}

func (data *CompressionClosePayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}
	return nil
}

func (data *CompressionClosePayload) Parse(b []byte) error {
	var err error
	data.ContextID, _, err = quicvarint.Parse(b)
	if err != nil {
		return fmt.Errorf("parse context id error: %v", err)
	}
	return nil
}

func (data *CompressionClosePayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID))
}

type natmap struct {
	ContextMap struct {
		sync.RWMutex
		Map map[uint64]netip.AddrPort
	}
	AddrMap struct {
		sync.RWMutex
		Map map[netip.AddrPort]uint64
	}
}

func newNatMap() *natmap {
	nm := natmap{}
	nm.ContextMap.Map = map[uint64]netip.AddrPort{}
	nm.AddrMap.Map = map[netip.AddrPort]uint64{}
	return &nm
}

func (nm *natmap) GetAddr(id uint64) (netip.AddrPort, bool) {
	nm.ContextMap.RLock()
	addr, ok := nm.ContextMap.Map[id]
	nm.ContextMap.RUnlock()
	return addr, ok
}

func (nm *natmap) GetContextID(addr netip.AddrPort) (uint64, bool) {
	nm.AddrMap.RLock()
	id, ok := nm.AddrMap.Map[addr]
	nm.AddrMap.RUnlock()
	return id, ok
}

func (nm *natmap) Add(id uint64, addr netip.AddrPort) {
	nm.ContextMap.Lock()
	nm.AddrMap.Lock()
	nm.ContextMap.Map[id] = addr
	nm.AddrMap.Map[addr] = id
	nm.AddrMap.Unlock()
	nm.ContextMap.Unlock()
}

func (nm *natmap) Del(id uint64) {
	nm.ContextMap.Lock()
	addr, ok := nm.ContextMap.Map[id]
	delete(nm.ContextMap.Map, id)
	if ok {
		nm.AddrMap.Lock()
		delete(nm.AddrMap.Map, addr)
		nm.AddrMap.Unlock()
	}
	nm.ContextMap.Unlock()
}

type Request string

type RequestMatcher struct {
	source       string
	tokens       []string
	patternRegex *regexp.Regexp
}

func (rm *RequestMatcher) Create(source string) error {
	const tempToken = "__TMPTKN__"

	delimiters := []rune{'{', '}'}

	tokenRegex := regexp.MustCompile(string(delimiters[0]) + "([^" + string(delimiters) + "\\t\\r\\n]+)" + string(delimiters[1]))
	tokenMatches := tokenRegex.FindAllStringSubmatch(source, -1)
	tokens := make([]string, len(tokenMatches))
	for i, v := range tokenMatches {
		tokens[i] = v[1] //Index 1 is the first (and only) submatch
	}

	substitutedTemplate := tokenRegex.ReplaceAllString(source, tempToken) // Substitution is required before escaping so that the capture group doesn't get escaped
	escapedSubstitutedTemplate := regexp.QuoteMeta(substitutedTemplate)
	escapedTemplate := strings.ReplaceAll(escapedSubstitutedTemplate, tempToken, "(.+)")
	patternRegex, err := regexp.Compile(escapedTemplate)
	if err != nil {
		return fmt.Errorf("error when constructing regex: %v", err)
	}

	rm.source = source
	rm.tokens = tokens
	rm.patternRegex = patternRegex
	return nil
}

// Provided an input and a template, returns a map of tokens to values
func (rm RequestMatcher) Extract(input string) (map[string]string, error) {
	var ErrNoMatch = errors.New("unable to match")

	matches := rm.patternRegex.FindStringSubmatch(input)
	if len(matches) != len(rm.tokens)+1 {
		return nil, ErrNoMatch
	}

	result := make(map[string]string)
	for i, v := range rm.tokens {
		result[v] = matches[i+1]
	}

	return result, nil
}

type DatagramSender struct {
	sync.Mutex
	w io.Writer
}

func (ds *DatagramSender) SendDatagram(data Datagram) error {
	ds.Lock()
	err := data.Send(ds.w)
	ds.Unlock()
	return err
}

type udpProxyServer struct {
	*zap.Logger
	Matcher RequestMatcher
}

func newUDPProxyServer(uri string, lg *zap.Logger) (udpProxyServer, error) {
	srv := udpProxyServer{Logger: lg}
	if uri == "" {
		// CONNECT https://{host}/.well-known/masque/udp/{target_host}/{target_port}/
		// GET /.well-known/masque/udp/{target_host}/{target_port}/
		uri = "https://{host}/.well-known/masque/udp/{target_host}/{target_port}/"
	}
	err := srv.Matcher.Create(uri)
	if err != nil {
		return srv, fmt.Errorf("parse uri template error: %w", err)
	}
	return srv, err
}

func (srv *udpProxyServer) HandleStream(c io.ReadWriter, req Request, rc *net.UDPConn) error {
	if req == "*" {
		return srv.HandleStreamBind(c, req, rc)
	}

	done := make(chan struct{})

	go func() {
		data := Datagram{}
		b := make([]byte, 2048)
		for {
			err := data.ReceiveBuffer(c, b)
			if err != nil {
				break
			}

			if data.Type != 0 {
				continue
			}

			pl := &CompressedPayload{}
			err = pl.Parse((data.Payload.(*BytePayload)).Payload)
			if err != nil {
				break
			}

			if pl.ContextID != 0 {
				continue
			}

			_, err = rc.Write(pl.Payload)
			if err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	data := Datagram{
		Type: 0,
	}
	b := make([]byte, 2048)
	for {
		nr, err := rc.Read(b)
		if err != nil {
			break
		}

		pl := &CompressedPayload{
			ContextID: 0,
			Payload:   b[:nr],
		}

		// data.Length = quicvarint.Len(0) + uint64(nr)
		data.Length = 1 + uint64(nr)
		data.Payload = pl

		err = data.Send(c)
		if err != nil {
			break
		}
	}

	<-done
	return nil
}

func (src *udpProxyServer) HandleStreamBind(c io.ReadWriter, req Request, rc *net.UDPConn) error {
	nm := newNatMap()

	var firewall atomic.Bool
	var dgSender DatagramSender = DatagramSender{w: c}

	done := make(chan struct{})

	go func() {
		data := Datagram{}
		b := make([]byte, 2048)
	loop:
		for {
			err := data.ReceiveBuffer(c, b)
			if err != nil {
				break
			}
			// slog.Info("receive new datagram")

			bb := (data.Payload.(*BytePayload)).Payload
			switch data.Type {
			case 0:
				// slog.Info("receive new UDP datagram")
				id, nr, err := quicvarint.Parse(bb)
				if err != nil {
					continue
				}

				var pkt []byte
				var addr netip.AddrPort
				if id == 2 {
					if firewall.Load() {
						// ignore all packets with conext id set as 2 when assign close is set
						continue
					}
					switch bb[nr] {
					case 4:
						// nr = 1
						pkt = bb[8:]
						addr = netip.AddrPortFrom(netip.AddrFrom4(
							[4]byte{bb[2], bb[3], bb[4], bb[5]}), uint16(bb[6])<<8|uint16(bb[7]))
					case 6:
						// nr = 1
						pkt = bb[20:]
						addr = netip.AddrPortFrom(netip.AddrFrom16(
							[16]byte{bb[2], bb[3], bb[nr+4], bb[5],
								bb[6], bb[7], bb[8], bb[9],
								bb[10], bb[11], bb[12], bb[13],
								bb[14], bb[15], bb[16], bb[17]}), uint16(bb[18])<<8|uint16(bb[19]))
					default:
						break loop
					}
				} else {
					pkt = bb[nr:data.Length]

					var ok bool
					addr, ok = nm.GetAddr(id)
					if !ok {
						// no addr for this context id and ignore this packet
						continue
					}
				}

				_, err = rc.WriteToUDPAddrPort(pkt, addr)
				if err != nil {
					break loop
				}
			case CompressionAssignValue:
				// slog.Info("receive new compression assign datagram")
				data := Datagram{
					Type: CompressionAssignValue,
				}
				pl := CompressionAssignPayload{}
				if err := pl.Parse(bb); err != nil {
					break loop
				}
				switch pl.IPVersion {
				case 0:
					if pl.ContextID != 2 {
						// use 2 for default uncompressed context id
						continue
					}

					firewall.Store(false)
				case 4:
					nm.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))
				case 6:
					nm.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))
				default:
					break loop
				}
				// even for client side, odd for server side
				// ignore all odd id
				if pl.ContextID&1 == 0 {
					data.Length = pl.Len()
					data.Payload = &pl
					err := dgSender.SendDatagram(data)
					if err != nil {
						break loop
					}
				}
			case CompressionCloseValue:
				data := Datagram{
					Type: CompressionCloseValue,
				}
				pl := CompressionClosePayload{}
				err = pl.Parse(bb)
				if err != nil {
					break loop
				}
				if pl.ContextID == 2 {
					firewall.Store(true)
				} else {
					nm.Del(pl.ContextID)
				}
				data.Length = uint64(quicvarint.Len(pl.ContextID))
				data.Payload = &pl
				err = dgSender.SendDatagram(data)
				if err != nil {
					break loop
				}
			default:
				continue
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	data := Datagram{
		Type: 0,
	}
	b := make([]byte, 2048)
	i := 1 // odd for context id issued by server side
	for {
		nr, addr, err := rc.ReadFromUDPAddrPort(b)
		if err != nil {
			break
		}

		id, ok := nm.GetContextID(addr)
		if !ok {
			if firewall.Load() {
				continue
			}

			id = uint64(i)
			i += 2 // odd context id for server side compression assign

			func() {
				// send compression assign to utlize compressed payload
				data := Datagram{
					Type: CompressionAssignValue,
				}
				pl := CompressionAssignPayload{}
				pl.ContextID = id
				pl.Addr = addr.Addr()
				if pl.Addr.Is4() {
					pl.IPVersion = 4
					data.Length = uint64(quicvarint.Len(id)) + 1 + 4 + 2
				} else {
					pl.IPVersion = 6
					data.Length = uint64(quicvarint.Len(id)) + 1 + 16 + 2
				}
				pl.Port = addr.Port()
				data.Payload = &pl
				dgSender.SendDatagram(data)
			}()

			pl := UncompressedPayload{
				ContextID: 2, // always use 2 for uncompressed context id
			}
			pl.Addr = addr.Addr()
			if pl.Addr.Is4() {
				pl.IPVersion = 4
				data.Length = 1 + 1 + 4 + 2 + uint64(nr)
			} else {
				pl.IPVersion = 6
				data.Length = 1 + 1 + 16 + 2 + uint64(nr)
			}
			pl.Port = addr.Port()
			pl.Payload = b[:nr]
			data.Payload = &pl
		} else {
			data.Length = uint64(quicvarint.Len(id)) + uint64(nr)
			data.Payload = &CompressedPayload{
				ContextID: id,
				Payload:   b[:nr],
			}
		}

		err = dgSender.SendDatagram(data)
		if err != nil {
			break
		}
	}

	<-done
	return nil
}

func (srv *udpProxyServer) HandlePacket(str http3.Stream, req Request, rc *net.UDPConn) error {
	// https://github.com/quic-go/masque-go/issues/64
	if req == "*" {
		return srv.HandlePacketBind(str, req, rc)
	}

	// https://github.com/quic-go/masque-go/blob/master/proxy.go
	done := make(chan struct{})

	go func() {
		for {
			data, err := str.ReceiveDatagram(context.Background())
			if err != nil {
				break
			}
			id, nr, err := quicvarint.Parse(data)
			if err != nil {
				break
			}
			if id != 0 {
				// Drop this datagram. We currently only support proxying of UDP payloads.
				continue
			}
			if _, err := rc.Write(data[nr:]); err != nil {
				break
			}
		}

		rc.Close()
		done <- struct{}{}
	}()

	go func() {
		b := make([]byte, 2048)
		for {
			nr, err := rc.Read(b[1:])
			if err != nil {
				break
			}

			// context id is always 0
			if err := str.SendDatagram(b[:nr+1]); err != nil {
				break
			}
		}

		done <- struct{}{}
	}()

	// discard all capsules sent on the request stream
	if err := func(str quicvarint.Reader) error {
		for {
			_, r, err := http3.ParseCapsule(str)
			if err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
		}
	}(quicvarint.NewReader(str)); errors.Is(err, io.EOF) {
	}

	<-done
	<-done
	return nil
}

func (srv *udpProxyServer) HandlePacketBind(str http3.Stream, req Request, c *net.UDPConn) error {
	return fmt.Errorf("connect-udp-bind over http3 is not supported yet")
}

func (srv *udpProxyServer) ParseRequest(r *http.Request) (Request, error) {
	switch r.ProtoMajor {
	case 1:
		// parse HTTP/1.1 request
		if r.Method != http.MethodGet {
			return "", fmt.Errorf("expected GET request, got %s", r.Method)
		}
		if r.Header.Get("Connection") != "Upgrade" {
			return "", fmt.Errorf("unexpected Connection: %s", r.Proto)
		}
		if r.Header.Get("Upgrade") != RequestProtocol {
			return "", fmt.Errorf("unexpected Upgrade: %s", r.Proto)
		}
	case 2:
		// copy from https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/reverseproxy.go#L414-L428
		// check HTTP2 request
		if r.Method != http.MethodConnect {
			return "", fmt.Errorf("expected CONNECT request, got %s", r.Method)
		}
		if r.Header.Get(":protocol") != RequestProtocol {
			return "", fmt.Errorf("unexpected protocol: %s", r.Header.Get(":protocol"))
		}
	case 3:
		// copy from https://github.com/quic-go/masque-go/blob/master/request.go#L47-L119
		// and remove ckecking host
		if r.Method != http.MethodConnect {
			return "", fmt.Errorf("expected CONNECT request, got %s", r.Method)
		}
		if r.Proto != RequestProtocol {
			return "", fmt.Errorf("unexpected protocol: %s", r.Proto)
		}
	default:
		return "", fmt.Errorf("unexpected HTTP version: %v", r.ProtoMajor)
	}

	// The capsule protocol header is optional, but if it's present,
	// we need to validate its value.
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if ok {
		item, err := httpsfv.UnmarshalItem(capsuleHeaderValues)
		if err != nil {
			return "", fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues)
		}
		if v, ok := item.Value.(bool); !ok {
			return "", fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value))
		} else if !v {
			return "", fmt.Errorf("incorrect capsule header value: %t", item.Value)
		}
	}

	// check request as UDP bind
	var isUDPBind bool
	connectUDPBindHeaderValues, ok := r.Header[ConnectUDPBindHeader]
	if ok {
		item, err := httpsfv.UnmarshalItem(connectUDPBindHeaderValues)
		if err != nil {
			return "", fmt.Errorf("invalid bind header value: %s", connectUDPBindHeaderValues)
		}
		if v, ok := item.Value.(bool); !ok {
			return "", fmt.Errorf("incorrect bind header value type: %s", reflect.TypeOf(item.Value))
		} else if !v {
			return "", fmt.Errorf("incorrect bind header value: %t", item.Value)
		}
		isUDPBind = true
	}

	match, err := func() (map[string]string, error) {
		uri := *r.URL
		if uri.Scheme == "" {
			uri.Scheme = "https"
		}
		if uri.Host == "" {
			uri.Host = "in-place.com"
		}
		return srv.Matcher.Extract(uri.String())
	}()
	if err != nil {
		return "", fmt.Errorf("extract uri from %s error: %w", r.URL.String(), err)
	}

	targetHost := func(s string) string { return strings.ReplaceAll(s, "%3A", ":") }(match["target_host"])
	targetPortStr := match["target_port"]
	if targetHost == "" || targetPortStr == "" {
		return "", fmt.Errorf("expected target_host and target_port")
	}
	if targetHost == "*" && targetPortStr == "*" {
		if isUDPBind {
			return "*", nil
		}
		return "", fmt.Errorf("invalid Connect-UDP-Bind: %v", r.Header[ConnectUDPBindHeader])
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode target_port: %w", err)
	}
	return Request(net.JoinHostPort(targetHost, strconv.Itoa(targetPort))), nil
}

func (h *Handler) tryUDPoverHTTP(w http.ResponseWriter, r *http.Request) (bool, error) {
	// slog.Info("try UDP over HTTP")
	// do not handle UDP over HTTP if upstream is set
	if h.upstream != nil {
		// slog.Info(fmt.Sprintf("use upstream: %s", h.Upstream))
		return false, nil
	}

	// parse request
	req, err := h.udpProxyServer.ParseRequest(r)
	if err != nil {
		// slog.Error(fmt.Sprintf("parse request: %s", err.Error()))
		return false, err
	}

	// slog.Info(fmt.Sprintf("handle UDP over HTTP request: ---> %s", req))

	var rconn *net.UDPConn
	if req == "*" {
		err := error(nil)
		rconn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return false, fmt.Errorf("listen UDP connection error: %w", err)
		}
		defer rconn.Close()
	} else {
		ok, err := func(hostPort string) (bool, error) {
			host, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				// return nil, &proxyError{S: err.Error(), Code: http.StatusBadRequest}
				return false, caddyhttp.Error(http.StatusBadRequest, err)
			}

			if !h.portIsAllowed(port) {
				// return nil, &proxyError{S: "port " + port + " is not allowed", Code: http.StatusForbidden}
				return false, caddyhttp.Error(http.StatusForbidden,
					fmt.Errorf("port %s is not allowed", port))
			}

		match:
			for _, rule := range h.aclRules {
				if _, ok := rule.(*aclDomainRule); ok {
					switch rule.tryMatch(nil, host) {
					case aclDecisionDeny:
						return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("disallowed host %s", host))
					case aclDecisionAllow:
						break match
					}
				}
			}

			// in case IP was provided, net.LookupIP will simply return it
			IPs, err := net.LookupIP(host)
			if err != nil {
				// return nil, &proxyError{S: fmt.Sprintf("Lookup of %s failed: %v", host, err),
				// Code: http.StatusBadGateway}
				return false, caddyhttp.Error(http.StatusBadGateway,
					fmt.Errorf("lookup of %s failed: %v", host, err))
			}

			// This is net.Dial's default behavior: if the host resolves to multiple IP addresses,
			// Dial will try each IP address in order until one succeeds
			for _, ip := range IPs {
				if !h.hostIsAllowed(host, ip) {
					continue
				}
				return true, nil
			}

			return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
		}(string(req))
		if !ok {
			return false, err
		}

		raddr, err := net.ResolveUDPAddr("udp", string(req))
		if err != nil {
			return false, fmt.Errorf("resolve UDP address error: %w", err)
		}

		rconn, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			return false, fmt.Errorf("dial UDP connection error: %w", err)
		}
		defer rconn.Close()
	}

	switch r.ProtoMajor {
	case 1:
		// slog.Info(fmt.Sprintf("handle UDP over HTTP/1.1 request: ---> %s", req))

		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade:", RequestProtocol)
		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		if req == "*" {
			w.Header().Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
			w.Header().Set(ProxyPublicAddressHeader, rconn.LocalAddr().String())
		}
		w.WriteHeader(http.StatusSwitchingProtocols)

		rc := http.NewResponseController(w)
		err = rc.Flush()
		if err != nil {
			return true, caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("ResponseWriter flush error: %v", err))
		}

		conn, _, err := rc.Hijack()
		if err != nil {
			return true, err
		}
		defer conn.Close()

		return true, h.udpProxyServer.HandleStream(conn, req, rconn)
	case 2:
		// slog.Info(fmt.Sprintf("handle UDP over HTTP/2.0 request: ---> %s", req))

		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		if req == "*" {
			w.Header().Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
			w.Header().Set(ProxyPublicAddressHeader, rconn.LocalAddr().String())
		}
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		err = rc.Flush()
		if err != nil {
			return true, caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("ResponseWriter flush error: %v", err))
		}

		conn, _, err := rc.Hijack()
		if err != nil {
			return true, err
		}
		defer conn.Close()

		return true, h.udpProxyServer.HandleStream(conn, req, rconn)
	case 3:
		// slog.Info(fmt.Sprintf("handle UDP over HTTP/3.0 request: ---> %s", req))

		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		w.WriteHeader(http.StatusOK)

		return true, h.udpProxyServer.HandlePacket(w.(http3.HTTPStreamer).HTTPStream(), req, rconn)
	default:
		return false, nil
	}
}

package ctl

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Live: the core's open connections for the UI's live page, one call per
// refresh while the page is open. The core keeps no closed ones: what the
// page shows as closed is what left the list between two calls.

// LiveConn: one open connection as the core tracks it.
type LiveConn struct {
	ID          string
	Host        string // the name the core routed by, "" for a bare address
	Sniffed     bool   // the name was read from the traffic itself (ClientHello, Host:)
	DstIP       string // the address dialled; for a name, where it resolved
	Port        int
	Network     string // tcp, udp
	Process     string
	ProcessPath string
	Chains      []string // the outbound first, then the groups it was picked by
	Rule        string
	RulePayload string
	Probe       bool // the prober's own, over its listeners
	Start       time.Time
	Upload      int64
	Download    int64
}

// Live: the core's counters and its open connections.
type Live struct {
	UploadTotal   int64
	DownloadTotal int64
	Memory        uint64
	Conns         []LiveConn
}

// ErrCoreDown: nothing listens on the controller's port -- the core is not
// running; any other error is a core that runs and does not answer.
var ErrCoreDown = errors.New("the core is not running")

// LiveClient asks one core again and again, on connections kept open: the
// live page calls it every second. They are its own, and Release closes
// them: with the page closed nothing is left open to the core.
type LiveClient struct {
	a      *api
	tr     *http.Transport
	stream *http.Client // the core's log: open for as long as it is read
}

func NewLiveClient(apiAddr, secret string) *LiveClient {
	a := newAPI(apiAddr, secret)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// a second-long refresh: a call hung longer is no use to it
	a.c = &http.Client{Timeout: 3 * time.Second, Transport: tr}
	return &LiveClient{a, tr, &http.Client{Transport: tr}}
}

// Release closes the connections kept open for the next call.
func (l *LiveClient) Release() { l.tr.CloseIdleConnections() }

func (l *LiveClient) Connections() (Live, error) {
	b, err := l.a.do("GET", "/connections", nil)
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return Live{}, ErrCoreDown
	}
	if err != nil {
		return Live{}, err
	}
	var snap struct {
		DownloadTotal int64        `json:"downloadTotal"`
		UploadTotal   int64        `json:"uploadTotal"`
		Memory        uint64       `json:"memory"`
		Connections   []connection `json:"connections"`
	}
	if err := json.Unmarshal(b, &snap); err != nil {
		return Live{}, err
	}
	out := Live{UploadTotal: snap.UploadTotal, DownloadTotal: snap.DownloadTotal, Memory: snap.Memory,
		Conns: make([]LiveConn, 0, len(snap.Connections))}
	for _, c := range snap.Connections {
		m := c.Metadata
		lc := LiveConn{ID: c.ID, Host: c.domain(), Sniffed: m.SniffHost != "",
			DstIP: m.DestinationIP, Network: m.Network, Process: m.Process, ProcessPath: m.ProcessPath,
			Chains: c.Chains, Rule: c.Rule, RulePayload: c.RulePayload, Probe: c.fromProbe(),
			Upload: c.Upload, Download: c.Download}
		lc.Port, _ = strconv.Atoi(m.DestinationPort)
		// a name has no address of its own until it is dialled: the one a
		// TCP outbound connected to is where it went. A UDP one names the
		// tunnel's server there, not the destination.
		if !c.isUDP() && net.ParseIP(m.RemoteDst) != nil {
			lc.DstIP = m.RemoteDst
		}
		lc.Start, _ = time.Parse(time.RFC3339Nano, c.Start)
		out.Conns = append(out.Conns, lc)
	}
	return out, nil
}

// Close has the core drop one connection. One gone already is no error:
// the core answers the same either way.
func (l *LiveClient) Close(id string) error {
	err := l.a.closeConnection(id)
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return ErrCoreDown
	}
	return err
}

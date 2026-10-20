package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MAIN_SERVER = "://easy4ipcloud.com"
	MAIN_PORT   = 8800
	USERNAME    = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY     = "996103384cdf19179e19243e959bbf8b"
	SOCKET_BUF  = 65536

	PIPELINE_WINDOW = 32
	W_MIN           = 8
	W_MAX           = 256
	GOV_GROW        = 8
	GOV_SHRINK      = 16
	ACK_TIMEOUT     = 15 * time.Second

	TIMEOUT_MIN        = 2 * time.Second
	TIMEOUT_RTT_FACTOR = 10

	STORM_EXPIRED_EMA = 0.25
	GRAVE_CAP         = 1024
	SEND_STAGGER      = 100 * time.Microsecond
	ACK_GRACE         = 10 * time.Second
	CHANNEL_RETRIES   = 2
	PUMP_MAX_WAIT     = time.Second
	SEND_JITTER_BOUND = 500 * time.Millisecond
	MAX_RPS           = 3000
	BURST_LIMIT       = 64
	retriedFlushAt    = 500000
	TEARDOWN_ALIVE    = true
)

var (
	GovernorOn  = true
	GovernorCap = 0
)

type rateLimiter struct {
	interval time.Duration
	burst    time.Duration
	mu       sync.Mutex
	next     time.Time
}

func newRateLimiter(rps int, burst int) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 1
	}
	inv := time.Second / time.Duration(rps)
	return &rateLimiter{
		interval: inv,
		burst:    time.Duration(burst) * inv,
		next:     time.Now(),
	}
}

func (rl *rateLimiter) wait(ctx context.Context) error {
	if rl == nil {
		return nil
	}
	rl.mu.Lock()
	now := time.Now()
	earliest := now.Add(-rl.burst)
	if rl.next.Before(earliest) {
		rl.next = earliest
	}
	if rl.next.Before(now) {
		rl.next = now
	}
	reserve := rl.next
	rl.next = rl.next.Add(rl.interval)
	rl.mu.Unlock()

	delay := reserve.Sub(now)
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (rl *rateLimiter) tryReserve() bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	earliest := now.Add(-rl.burst)
	if rl.next.Before(earliest) {
		rl.next = earliest
	}
	if rl.next.After(now) {
		return false
	}
	rl.next = rl.next.Add(rl.interval)
	return true
}

func (rl *rateLimiter) nextDelay() time.Duration {
	if rl == nil {
		return 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	d := time.Until(rl.next)
	if d < 0 {
		d = 0
	}
	return d
}

var cseqCounter int64

type ScanStats struct {
	Checked  int64
	Alive    int64
	Dead     int64
	Errors   int64
	Total    int64
	Speed    float64
	Done     bool
	ErrorMsg string

	Reading        int64
	ReadLines      int64
	ReadBytes      int64
	ReadTotalBytes int64
	ReadValid      int64
	DedupResets    int64
	AliveRate      float64

	Fed         int64
	PrefixTotal int64
	PrefixDone  int64
	LastSerial  atomic.Value
}

func LastSerialOf(stats *ScanStats) string {
	s, ok := stats.LastSerial.Load().(string)
	if !ok {
		return ""
	}
	return s
}

var CrashHook func(recovered any)

func crashGuard(r any) {
	if CrashHook != nil {
		CrashHook(r)
	}
}

var FatalHook func(reason string, stack []byte)

func raiseOrReraise(r any) {
	crashGuard(r)
	if FatalHook != nil {
		FatalHook(panicReason(r), debug.Stack())
		return
	}
	panic(r)
}

func PanicReason(r any) string { return panicReason(r) }

func panicReason(r any) string {
	if r == nil {
		return "unknown panic"
	}
	s := fmt.Sprint(r)
	if i := strings.IndexByte(s, 10); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown panic"
	}
	return s
}

var TestCrashAfter time.Duration

const envTestCrash = "KRUSHITEL_TEST_CRASH_AFTER"

func init() {
	TestCrashAfter = parseCrashAfter(os.Getenv(envTestCrash))
	cachedTimeoutNs.Store(int64(ACK_TIMEOUT))
}

func parseCrashAfter(v string) time.Duration {
	norm := strings.ToLower(strings.TrimSpace(v))
	switch norm {
	case "", "off", "0", "no", "false", "disabled", "none", "выкл", "нет":
		return 0
	}
	d, err := time.ParseDuration(norm)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

func armInjector(ci *crashInjector, events chan<- string) {
	if ci == nil {
		return
	}
	ci.arm(TestCrashAfter)
	emitEvent(events, "[SYS] [gov] test-crash armed: упаду через "+TestCrashAfter.String())
}

const fatalDrainTimeout = 2 * time.Second

type crashInjector struct {
	deadline time.Time
	mu       sync.RWMutex
	once     sync.Once
}

func (ci *crashInjector) arm(d time.Duration) {
	if ci == nil || d <= 0 {
		return
	}
	ci.mu.Lock()
	ci.deadline = time.Now().Add(d)
	ci.mu.Unlock()
}

func (ci *crashInjector) armed() bool {
	if ci == nil {
		return false
	}
	ci.mu.Lock()
	dl := ci.deadline
	ci.mu.Unlock()
	return !dl.IsZero() && time.Now().After(dl)
}

func (ci *crashInjector) fire() {
	if !ci.armed() {
		return
	}
	ci.once.Do(func() {
		var m map[string]int
		m["pipeline"] = 1
	})
}

type dhResp struct {
	Code   int
	CSeq   int64
	Body   string
	usNode string
}

func parseDHResp(data []byte) dhResp {
	r := dhResp{}
	head := data
	rest := ""
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		head = data[:i]
		rest = string(data[i+4:])
	}
	lines := bytes.Split(head, []byte("\r\n"))
	for i, ln := range lines {
		if i == 0 {
			parts := bytes.SplitN(ln, []byte(" "), 3)
			if len(parts) >= 2 {
				r.Code, _ = strconv.Atoi(string(parts[1]))
			}
			continue
		}
		if j := bytes.IndexByte(ln, byte(':')); j > 0 {
			if bytes.EqualFold(ln[:j], []byte("CSeq")) {
				r.CSeq, _ = strconv.ParseInt(strings.TrimSpace(string(ln[j+1:])), 10, 64)
			}
		}
	}
	r.Body = rest
	r.usNode = strBetween(rest, "<US>", "</US>")
	return r
}

func strBetween(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func dhReq(method, path, body string, cseq int64, digest, nonce, curdate string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, cseq))
	sb.WriteString(fmt.Sprintf("Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n",
		USERNAME, digest, nonce, curdate))
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString("\r\n" + body)
	return sb.String()
}

func p2pChannelBody(lport int, aid []byte) string {
	aidHex := make([]string, 8)
	for i, b := range aid {
		aidHex[i] = fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:%d</LocalAddr><version>5.0.0</version></body>",
		strings.Join(aidHex, " "), lport)
}

func channelAckAlive(r dhResp) bool {
	return r.Code >= 200 && r.Code < 400 &&
		strBetween(r.Body, "<LocalAddr>", "</LocalAddr>") != ""
}

func randomAID() []byte {
	v := rand.Uint64()
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * uint(i)))
	}
	return out
}

type inflightChannel struct {
	serial   string
	aid      []byte
	deadline time.Time
	extended bool
	retries  int
	sentAt   time.Time
}

type graveEntry struct {
	serial   string
	aid      []byte
	retries  int
	deadline time.Time
	explicit bool
}

type channelPipeline struct {
	conn                      *net.UDPConn
	lport                     int
	digest, nonceStr, curdate string
	timeout                   time.Duration
	graceTTL                  time.Duration
	window                    int
	resolvedCycle             int64
	expiredCycle              int64
	expiredEMA                float64
	emaSet                    bool
	inflight                  map[int64]*inflightChannel
	graveyard                 map[int64]*graveEntry
	retried                   map[uint64]struct{}
	buf                       []byte
	limiter                   *rateLimiter
	ctx                       context.Context
	injector                  *crashInjector
	lastReconnect             time.Time
	lastRaw                   []byte
}

func (p *channelPipeline) tryRate() bool {
	if p.limiter == nil {
		return true
	}
	return p.limiter.tryReserve()
}

func (p *channelPipeline) blockRate() bool {
	if p.limiter == nil {
		return true
	}
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return p.limiter.wait(ctx) == nil
}

func (p *channelPipeline) nextRateDelay() time.Duration {
	if p.limiter == nil {
		return 0
	}
	return p.limiter.nextDelay()
}

func (p *channelPipeline) curTimeout() time.Duration {
	now := time.Now()
	if last := timeoutUpdatedAt.Load(); now.Sub(time.Unix(0, last)) > time.Second {
		if timeoutUpdatedAt.CompareAndSwap(last, now.UnixNano()) {
			to := int64(ACK_TIMEOUT)
			if med := govMedianRTT(); med > 0 {
				to = med * TIMEOUT_RTT_FACTOR
				if to < int64(TIMEOUT_MIN) {
					to = int64(TIMEOUT_MIN)
				}
				if to > int64(ACK_TIMEOUT) {
					to = int64(ACK_TIMEOUT)
				}
			}
			cachedTimeoutNs.Store(to)
		}
	}
	return time.Duration(cachedTimeoutNs.Load())
}

var (
	cachedTimeoutNs  atomic.Int64
	timeoutUpdatedAt atomic.Int64
)

func (p *channelPipeline) stormMode() bool {
	return p.emaSet && p.expiredEMA > STORM_EXPIRED_EMA
}

func (p *channelPipeline) gravePut(c int64, g *graveEntry, stats *ScanStats) {
	if len(p.graveyard) >= GRAVE_CAP {
		var oldC int64
		var oldD time.Time
		first := true
		for cc, gg := range p.graveyard {
			if first || gg.deadline.Before(oldD) {
				oldC, oldD, first = cc, gg.deadline, false
			}
		}
		if !first {
			og := p.graveyard[oldC]
			delete(p.graveyard, oldC)
			atomic.AddInt64(&stats.Dead, 1)
			protolog("× %s dead (graveyard overflow)", og.serial)
		}
	}
	p.graveyard[c] = g
}

func newChannelPipeline(conn *net.UDPConn, timeout time.Duration) *channelPipeline {
	p := &channelPipeline{
		conn:      conn,
		lport:     conn.LocalAddr().(*net.UDPAddr).Port,
		timeout:   timeout,
		graceTTL:  ACK_GRACE,
		window:    PIPELINE_WINDOW,
		inflight:  make(map[int64]*inflightChannel, PIPELINE_WINDOW),
graveyard: make(map[int64]*graveEntry, PIPELINE_WINDOW),
retried:   make(map[uint64]struct{}),
buf:       make([]byte, 65536),
}
nonce := time.Now().UnixNano()
p.nonceStr = fmt.Sprintf("%d", nonce)
p.curdate = time.Now().UTC().Format("2006-01-02T15:04:05Z")
pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, p.curdate, USERNAME, USERKEY)
hash := sha1.Sum([]byte(pwd))
p.digest = base64.StdEncoding.EncodeToString(hash[:])
cseq := atomic.AddInt64(&cseqCounter, 1)
p.write("DHGET", "/probe/p2psrv", "", cseq)
dl := time.Now().Add(timeout)
for {
p.conn.SetReadDeadline(dl)
n, err := p.conn.Read(p.buf)
if err != nil {
break
}
if r := parseDHResp(p.buf[:n]); r.CSeq == cseq {
break
}
}
return p
}
func (p *channelPipeline) write(method, path, body string, cseq int64) error {
p.refreshAuth()
p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
_, err := p.conn.Write([]byte(dhReq(method, path, body, cseq, p.digest, p.nonceStr, p.curdate)))
return err
}
func (p *channelPipeline) refreshAuth() {
nonce := rand.Int63n(1<<32) - (1 << 31)
p.nonceStr = strconv.FormatInt(nonce, 10)
p.curdate = time.Now().UTC().Format("2006-01-02T15:04:05Z")
hash := sha1.Sum([]byte(p.nonceStr + p.curdate + "DHP2P:" + USERNAME + ":" + USERKEY))
p.digest = base64.StdEncoding.EncodeToString(hash[:])
}
func isUDPHardError(err error) bool {
if err == nil {
return false
}
s := strings.ToLower(err.Error())
return strings.Contains(s, "connection reset") ||
strings.Contains(s, "connection refused") ||
strings.Contains(s, "forcibly closed") ||
strings.Contains(s, "broken pipe")
}
func (p *channelPipeline) reconnect() {
if time.Since(p.lastReconnect) < time.Second {
return
}
p.lastReconnect = time.Now()
raddr, _ := p.conn.RemoteAddr().(*net.UDPAddr)
if raddr == nil {
return
}
conn, err := net.DialUDP("udp", nil, raddr)
if err != nil {
return
}
conn.SetWriteBuffer(SOCKET_BUF)
conn.SetReadBuffer(256 * 1024)
old := p.conn
p.conn = conn
p.lport = conn.LocalAddr().(*net.UDPAddr).Port
old.Close()
}
func serialHash(s string) uint64 {
h := uint64(14695981039346656037)
for i := 0; i < len(s); i++ {
h ^= uint64(s[i])
h *= 1099511628211
}
return h
}
func (p *channelPipeline) markFirst(serial string, stats *ScanStats) {
atomic.AddInt64(&stats.Checked, 1)
}
func (p *channelPipeline) rememberRetried(serial string) {
p.retried[serialHash(serial)] = struct{}{}
if len(p.retried) >= retriedFlushAt {
p.retried = make(map[uint64]struct{})
}
}
func (p *channelPipeline) markRetried(serial string, stats *ScanStats) {
h := serialHash(serial)
if _, ok := p.retried[h]; !ok {
p.retried[h] = struct{}{}
atomic.AddInt64(&stats.Checked, 1)
if len(p.retried) >= retriedFlushAt {
p.retried = make(map[uint64]struct{})
}
}
}
func (p *channelPipeline) sendFail(serial string, stats *ScanStats) {
p.markFirst(serial, stats)
atomic.AddInt64(&stats.Dead, 1)
}
func sendJitter() time.Duration {
return time.Duration(rand.Int63n(int64(SEND_JITTER_BOUND)))
}
func (p *channelPipeline) send(serial string) bool {
cseq := atomic.AddInt64(&cseqCounter, 1)
aid := randomAID()
if err := p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", serial), p2pChannelBody(p.lport, aid), cseq); err != nil {
if isUDPHardError(err) {
p.reconnect()
}
protolog("× %s send fail (socket write)", serial)
return false
}
p.inflight[cseq] = &inflightChannel{serial: serial, aid: aid, deadline: time.Now().Add(p.curTimeout() + sendJitter()), sentAt: time.Now()}
time.Sleep(SEND_STAGGER)
return true
}
func (p *channelPipeline) readResp(dl time.Time) (dhResp, bool) {
p.conn.SetReadDeadline(dl)
n, err := p.conn.Read(p.buf)
if err != nil {
return dhResp{}, false
}
p.lastRaw = append(p.lastRaw[:0], p.buf[:n]...)
return parseDHResp(p.buf[:n]), true
}
var On401 func(serial, raw string)
func record401(serial string, raw []byte) {
if On401 == nil {
return
}
On401(serial, string(raw))
}
func Wire401Dump(path string, max int64) func() {
if max <= 0 {
max = 1000
}
f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
if err != nil {
return func() {}
}
var mu sync.Mutex
var n int64
On401 = func(serial, raw string) {
mu.Lock()
defer mu.Unlock()
if n >= max {
return
}
n++
fmt.Fprintf(f, "=== %s %s ===\n%s\n", time.Now().Format("15:04:05"), serial, raw)
}
return func() {
On401 = nil
mu.Lock()
defer mu.Unlock()
_ = f.Sync()
_ = f.Close()
}
}
func (p *channelPipeline) minDeadline() time.Time {
var m time.Time
for _, ir := range p.inflight {
if m.IsZero() || ir.deadline.Before(m) {
m = ir.deadline
}
}
for _, g := range p.graveyard {
if m.IsZero() || g.deadline.Before(m) {
m = g.deadline
}
}
return m
}
func (p *channelPipeline) expire(stats *ScanStats) {
now := time.Now()
storm := p.stormMode()
for c, ir := range p.inflight {
if now.After(ir.deadline) {
delete(p.inflight, c)
p.expiredCycle++
govRecordTO()
if ir.retries == 0 {
p.markFirst(ir.serial, stats)
} else {
p.markRetried(ir.serial, stats)
}
if storm {
atomic.AddInt64(&stats.Dead, 1)
continue
}
p.rememberRetried(ir.serial)
p.gravePut(c, &graveEntry{serial: ir.serial, aid: ir.aid, retries: ir.retries, deadline: now.Add(p.graceTTL)}, stats)
}
}
for c, g := range p.graveyard {
if now.After(g.deadline) {
if g.retries >= CHANNEL_RETRIES {
delete(p.graveyard, c)
atomic.AddInt64(&stats.Dead, 1)
continue
}
if storm && !g.explicit {
delete(p.graveyard, c)
atomic.AddInt64(&stats.Dead, 1)
continue
}
if !p.tryRate() {
g.deadline = now.Add(p.nextRateDelay() + time.Millisecond)
continue
}
delete(p.graveyard, c)
p.sendRetry(g, stats)
}
}
}
func (p *channelPipeline) sendRetry(g *graveEntry, stats *ScanStats) {
cseq := atomic.AddInt64(&cseqCounter, 1)
aid := randomAID()
if err := p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", g.serial), p2pChannelBody(p.lport, aid), cseq); err != nil {
if isUDPHardError(err) {
p.reconnect()
}
govRecordErr()
atomic.AddInt64(&stats.Dead, 1)
return
}
p.inflight[cseq] = &inflightChannel{serial: g.serial, aid: aid, retries: g.retries + 1, deadline: time.Now().Add(p.curTimeout() + sendJitter()), sentAt: time.Now()}
time.Sleep(SEND_STAGGER)
}
func (p *channelPipeline) resolve(r dhResp, aliveCh chan<- string, stats *ScanStats) {
if r.Code < 200 {
if ir, ok := p.inflight[r.CSeq]; ok && !ir.extended {
ir.extended = true
ir.deadline = time.Now().Add(p.curTimeout())
}
return
}
if ir, ok := p.inflight[r.CSeq]; ok {
delete(p.inflight, r.CSeq)
p.resolvedCycle++
if ir.retries == 0 {
p.markFirst(ir.serial, stats)
} else {
p.markRetried(ir.serial, stats)
}
if !ir.sentAt.IsZero() {
govRecordOK(time.Since(ir.sentAt))
}
if channelAckAlive(r) {
atomic.AddInt64(&stats.Alive, 1)
aliveCh <- ir.serial
p.teardown(ir.aid, r)
} else if r.Code == 401 {
delete(p.inflight, r.CSeq)
p.expiredCycle++
govRecordTO()
p.rememberRetried(ir.serial)
p.gravePut(r.CSeq, &graveEntry{serial: ir.serial, aid: ir.aid, retries: ir.retries, deadline: time.Now().Add(p.graceTTL), explicit: true}, stats)
record401(ir.serial, p.lastRaw)
} else {
atomic.AddInt64(&stats.Dead, 1)
}
return
}
if g, ok := p.graveyard[r.CSeq]; ok {
delete(p.graveyard, r.CSeq)
p.resolvedCycle++
if channelAckAlive(r) {
atomic.AddInt64(&stats.Alive, 1)
aliveCh <- g.serial
p.teardown(g.aid, r)
} else if r.Code == 401 && g.retries < CHANNEL_RETRIES {
govRecordTO()
p.gravePut(r.CSeq, &graveEntry{serial: g.serial, aid: g.aid, retries: g.retries, deadline: time.Now().Add(p.graceTTL), explicit: true}, stats)
record401(g.serial, p.lastRaw)
} else {
atomic.AddInt64(&stats.Dead, 1)
if r.Code == 401 {
record401(g.serial, p.lastRaw)
govRecordTO()
}
}
return
}
}
func (p *channelPipeline) teardown(aid []byte, ack dhResp) {
if !TEARDOWN_ALIVE {
return
}
invAid := make([]byte, 8)
for i, b := range aid {
invAid[i] = ^b
}
build := func(eaddr []byte) []byte {
out := make([]byte, 0, 40)
out = append(out, 0xFF, 0xFE, 0xFF, 0xE7)
c1, c2 := randomAID(), randomAID()
out = append(out, c1[:4]...)
out = append(out, c2[:]...)
out = append(out, c1[4:]...)
out = append(out, 0x7F, 0xD5, 0xFF, 0xF7)
out = append(out, invAid...)
out = append(out, 0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE)
out = append(out, eaddr...)
return out
}
for _, addrStr := range []string{
strBetween(ack.Body, "", ""),
strBetween(ack.Body, "", ""),
} {
host, portStr, err := net.SplitHostPort(addrStr)
if err != nil {
continue
}
port, err := strconv.Atoi(portStr)
if err != nil {
continue
}
ip := net.ParseIP(host).To4()
if ip == nil {
continue
}
eaddr := make([]byte, 6)
binary.BigEndian.PutUint16(eaddr[0:2], uint16(port))
copy(eaddr[2:], ip)
for i := range eaddr {
eaddr[i] = ^eaddr[i]
}
init := build(eaddr)
p.conn.WriteTo(init, &net.UDPAddr{IP: ip, Port: port})
p.conn.Write(init)
}
}
func (p *channelPipeline) govern() {
	total := p.resolvedCycle + p.expiredCycle
	if total > 0 {
		share := float64(p.expiredCycle) / float64(total)
		if p.emaSet {
			p.expiredEMA = (p.expiredEMA * 7 / 8) + (share / 8)
		} else {
			p.expiredEMA, p.emaSet = share, true
		}
	}
	switch {
	case p.emaSet && p.expiredEMA < 0.02:
		p.window += GOV_GROW
		if p.window > W_MAX {
			p.window = W_MAX
		}
	case p.emaSet && p.expiredEMA > 0.10:
		p.window -= GOV_SHRINK
		if p.window < W_MIN {
			p.window = W_MIN
		}
	}
	p.resolvedCycle, p.expiredCycle = 0, 0
}
func (p *channelPipeline) run(ctx context.Context, jobs <-chan string, aliveCh chan<- string, stats *ScanStats) {
p.ctx = ctx
var pumpCap time.Duration
for {
if ctx.Err() != nil {
return
}
if p.injector != nil && p.injector.armed() {
p.injector.fire()
}
pumpCap = 0
for len(p.inflight) < p.window {
if !p.tryRate() {
pumpCap = p.nextRateDelay() + time.Millisecond
goto readPhase
}
select {
case <-ctx.Done():
return
case s, ok := <-jobs:
if !ok {
goto drain
}
if !p.send(s) {
if ctx.Err() != nil {
return
}
p.sendFail(s, stats)
}
default:
goto readPhase
}
}
readPhase:
if len(p.inflight) == 0 && len(p.graveyard) == 0 {
select {
case <-ctx.Done():
return
case s, ok := <-jobs:
if !ok {
return
}
if !p.blockRate() {
return
}
if !p.send(s) {
if ctx.Err() != nil {
return
}
p.sendFail(s, stats)
}
}
continue
}
p.pump(ctx, aliveCh, stats, pumpCap)
if (p.resolvedCycle + p.expiredCycle) >= int64(p.window) {
p.govern()
}
}
drain:
for (len(p.inflight) > 0 || len(p.graveyard) > 0) && ctx.Err() == nil {
p.pump(ctx, aliveCh, stats, 0)
if (p.resolvedCycle + p.expiredCycle) >= int64(p.window) {
p.govern()
}
}
}
func (p *channelPipeline) pump(ctx context.Context, aliveCh chan<- string, stats *ScanStats, maxWait time.Duration) {
dl := p.minDeadline()
now := time.Now()
wait := dl.Sub(now)
if maxWait > 0 && maxWait < wait {
wait = maxWait
}
if wait > PUMP_MAX_WAIT {
wait = PUMP_MAX_WAIT
}
if wait < time.Millisecond {
wait = time.Millisecond
}
r, got := p.readResp(now.Add(wait))
if !got {
p.expire(stats)
return
}
p.resolve(r, aliveCh, stats)
p.expire(stats)
}
func scanWorker(ctx context.Context, conn *net.UDPConn, jobs <-chan string, aliveCh chan<- string, stats *ScanStats, timeout time.Duration, limiter *rateLimiter, injector *crashInjector) {
p := newChannelPipeline(conn, timeout)
p.limiter = limiter
p.injector = injector
p.run(ctx, jobs, aliveCh, stats)
}
type countReader struct {
r io.Reader
n *int64
}
func (c *countReader) Read(p []byte) (int, error) {
n, err := c.r.Read(p)
if n > 0 {
atomic.AddInt64(c.n, int64(n))
}
return n, err
}
func emitEvent(events chan<- string, s string) {
if events == nil {
return
}
select {
case events <- s:
default:
}
}
var Debug bool
func protolog(format string, args ...any) {}
func lookupCloudIPs() []net.IP {
ips, err := net.LookupIP(MAIN_SERVER)
if err != nil || len(ips) == 0 {
return []net.IP{net.ParseIP("47.89.22.115")}
}
return ips
}
func newEgress(ip net.IP) (*net.UDPConn, error) {
conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: MAIN_PORT})
if err != nil {
return nil, err
}
_ = conn.SetWriteBuffer(SOCKET_BUF)
_ = conn.SetReadBuffer(256 * 1024)
return conn, nil
}
func streamSerials(ctx context.Context, f *os.File, stats *ScanStats, events chan<- string, out chan<- string, dedupWindow int) (int64, string) {
atomic.StoreInt64(&stats.Reading, 1)
defer atomic.StoreInt64(&stats.Reading, 0)
defer close(out)
var readBytes int64
sc := bufio.NewScanner(&countReader{r: f, n: &readBytes})
var emitted, lines, valid int64
for sc.Scan() {
lines++
s := strings.TrimSpace(sc.Text())
if s == "" || strings.HasPrefix(s, "#") {
continue
}
select {
case <-ctx.Done():
return emitted, ""
case out <- s:
}
emitted++
valid++
}
atomic.StoreInt64(&stats.ReadLines, lines)
atomic.StoreInt64(&stats.ReadValid, valid)
atomic.StoreInt64(&stats.Total, emitted)
atomic.StoreInt64(&stats.ReadBytes, readBytes)
return emitted, ""
}
func govRecordErr()           {}
func govRecordTO()            {}
func govRecordOK(d time.Duration) {}
func govMedianRTT() int64     { return 0 }
func resetGov()               {}
func governorLoop(ctx context.Context, lim *rateLimiter) {}
const govStartPPS = 1000

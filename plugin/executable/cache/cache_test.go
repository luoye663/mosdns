/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func Test_cachePlugin_Dump(t *testing.T) {
	c := NewCache(&Args{Size: 16 * dumpBlockSize}, Opts{}) // Big enough to create dump fragments.
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("test.", dns.TypeA)

	now := time.Now()
	hourLater := now.Add(time.Hour)
	v := &item{
		resp:           resp,
		storedTime:     now,
		expirationTime: hourLater,
	}

	// Fill the cache
	for i := 0; i < 32*dumpBlockSize; i++ {
		c.backend.Store(key(strconv.Itoa(i)), v, hourLater)
	}

	buf := new(bytes.Buffer)
	enw, err := c.writeDump(buf)
	if err != nil {
		t.Fatal(err)
	}

	reloaded := NewCache(&Args{Size: 16 * dumpBlockSize}, Opts{})
	defer reloaded.Close()
	enr, err := reloaded.readDump(buf)
	if err != nil {
		t.Fatal(err)
	}

	if enw != enr {
		t.Fatalf("read err, wrote %d entries, read %d", enw, enr)
	}

	ttlCache := NewCache(&Args{Size: 16}, Opts{})
	defer ttlCache.Close()
	ttlResp := resp.Copy()
	ttlResp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}}}
	storedTime := time.Now().Add(-2 * time.Second)
	ttlCache.backend.Store("ttl-entry", &item{resp: ttlResp, storedTime: storedTime, expirationTime: storedTime.Add(10 * time.Second)}, storedTime.Add(10*time.Second))
	ttlDump := new(bytes.Buffer)
	if _, err := ttlCache.writeDump(ttlDump); err != nil {
		t.Fatal(err)
	}
	ttlReloaded := NewCache(&Args{Size: 16}, Opts{})
	defer ttlReloaded.Close()
	if _, err := ttlReloaded.readDump(ttlDump); err != nil {
		t.Fatal(err)
	}
	first, _ := getRespFromCache("ttl-entry", ttlReloaded.backend, false, 0)
	if first == nil {
		t.Fatal("reloaded entry was not found")
	}
	time.Sleep(1100 * time.Millisecond)
	second, _ := getRespFromCache("ttl-entry", ttlReloaded.backend, false, 0)
	if second == nil || second.Answer[0].Header().Ttl >= first.Answer[0].Header().Ttl {
		t.Fatalf("TTL did not decrease after reload: first=%d second=%v", first.Answer[0].Header().Ttl, second)
	}

	lazyCache := NewCache(&Args{Size: 16, LazyCacheTTL: 60}, Opts{})
	defer lazyCache.Close()
	lazyStored := time.Now().Add(-11 * time.Second)
	lazyCache.backend.Store("lazy-entry", &item{resp: ttlResp, storedTime: lazyStored, expirationTime: lazyStored.Add(10 * time.Second)}, lazyStored.Add(70*time.Second))
	lazyDump := new(bytes.Buffer)
	if _, err := lazyCache.writeDump(lazyDump); err != nil {
		t.Fatal(err)
	}
	lazyReloaded := NewCache(&Args{Size: 16, LazyCacheTTL: 60}, Opts{})
	defer lazyReloaded.Close()
	if _, err := lazyReloaded.readDump(lazyDump); err != nil {
		t.Fatal(err)
	}
	if response, lazy := getRespFromCache("lazy-entry", lazyReloaded.backend, true, expiredMsgTtl); response == nil || !lazy {
		t.Fatalf("lazy entry was not restored: response=%v lazy=%t", response, lazy)
	}
}

func TestCacheAPIRequiresControlToken(t *testing.T) {
	c := NewCache(&Args{Size: 16}, Opts{})
	c.controlToken = []byte("cache-test-token")

	for _, testCase := range []struct {
		name  string
		token string
		want  int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "wrong", token: "wrong", want: http.StatusUnauthorized},
		{name: "valid", token: "cache-test-token", want: http.StatusOK},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/flush", nil)
			if testCase.token != "" {
				req.Header.Set("Authorization", "Bearer "+testCase.token)
			}
			response := httptest.NewRecorder()
			c.Api().ServeHTTP(response, req)
			if response.Code != testCase.want {
				t.Fatalf("status = %d, want %d", response.Code, testCase.want)
			}
		})
	}
}

func TestCacheEnabledAPIBypassesAndFlushesCache(t *testing.T) {
	c := NewCache(&Args{Size: 16}, Opts{})
	c.controlToken = []byte("cache-test-token")
	resp := new(dns.Msg)
	resp.SetQuestion("test.", dns.TypeA)
	c.backend.Store("entry", &item{resp: resp, storedTime: time.Now(), expirationTime: time.Now().Add(time.Hour)}, time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodPut, "/enabled", bytes.NewBufferString(`{"enabled":false}`))
	req.Header.Set("Authorization", "Bearer cache-test-token")
	response := httptest.NewRecorder()
	c.Api().ServeHTTP(response, req)
	if response.Code != http.StatusOK || c.enabled.Load() || c.backend.Len() != 0 {
		t.Fatalf("status=%d enabled=%t entries=%d", response.Code, c.enabled.Load(), c.backend.Len())
	}
}

func TestCacheKeySeparatesECSSubnets(t *testing.T) {
	first := new(dns.Msg)
	first.SetQuestion("example.com.", dns.TypeA)
	first.SetEdns0(1200, false)
	first.IsEdns0().Option = append(first.IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: []byte{192, 0, 2, 0}})
	second := first.Copy()
	second.IsEdns0().Option[0] = &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: []byte{198, 51, 100, 0}}
	if getMsgKey(first) == getMsgKey(second) {
		t.Fatal("distinct ECS subnets share a cache key")
	}
}

func TestCacheKeySeparatesQuestionClasses(t *testing.T) {
	inet := new(dns.Msg)
	inet.SetQuestion("example.com.", dns.TypeA)
	chaos := inet.Copy()
	chaos.Question[0].Qclass = dns.ClassCHAOS
	if getMsgKey(inet) == getMsgKey(chaos) {
		t.Fatal("distinct question classes share a cache key")
	}
}

func TestRuntimeLazyRefreshDeduplicatesWithoutBlockingHits(t *testing.T) {
	runtime := newTestRuntime(t, 60)
	query := runtimeQuery("lazy.example.")
	msgKey := getMsgKey(query)
	now := time.Now()
	runtime.backend.Store(key(msgKey), &item{resp: runtimeResponse(query), storedTime: now.Add(-time.Minute), expirationTime: now.Add(-time.Second)}, now.Add(time.Minute))

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	forward := func(_ context.Context, qCtx *query_context.Context) error {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		qCtx.SetResponse(runtimeResponse(qCtx.Q()))
		return nil
	}

	const callers = 64
	start := make(chan struct{})
	var callersWG sync.WaitGroup
	callersWG.Add(callers)
	for range callers {
		go func() {
			defer callersWG.Done()
			<-start
			qCtx := query_context.NewContext(query.Copy())
			if hit, _, err := runtime.Exec(context.Background(), qCtx, forward); err != nil || !hit {
				t.Errorf("lazy lookup hit=%t err=%v", hit, err)
			}
		}()
	}
	close(start)
	callersDone := make(chan struct{})
	go func() { callersWG.Wait(); close(callersDone) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lazy refresh did not start")
	}
	select {
	case <-callersDone:
	case <-time.After(time.Second):
		t.Fatal("lazy cache hits waited for refresh")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("lazy refresh calls = %d, want 1", got)
	}
	close(release)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeFlushBlocksInFlightMissWriteback(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	query := runtimeQuery("miss-flush.example.")
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		qCtx := query_context.NewContext(query)
		_, _, err := runtime.Exec(context.Background(), qCtx, func(_ context.Context, qCtx *query_context.Context) error {
			close(started)
			<-release
			qCtx.SetResponse(runtimeResponse(qCtx.Q()))
			return nil
		})
		done <- err
	}()
	<-started
	runtime.Flush()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := runtime.Len(); got != 0 {
		t.Fatalf("in-flight miss restored %d entries after flush", got)
	}
}

func TestRuntimeFlushBlocksInFlightLazyWriteback(t *testing.T) {
	runtime := newTestRuntime(t, 60)
	query := runtimeQuery("lazy-flush.example.")
	msgKey := getMsgKey(query)
	now := time.Now()
	runtime.backend.Store(key(msgKey), &item{resp: runtimeResponse(query), storedTime: now.Add(-time.Minute), expirationTime: now.Add(-time.Second)}, now.Add(time.Minute))
	started, release := make(chan struct{}), make(chan struct{})
	qCtx := query_context.NewContext(query.Copy())
	hit, _, err := runtime.Exec(context.Background(), qCtx, func(_ context.Context, qCtx *query_context.Context) error {
		close(started)
		<-release
		qCtx.SetResponse(runtimeResponse(qCtx.Q()))
		return nil
	})
	if err != nil || !hit {
		t.Fatalf("lazy lookup hit=%t err=%v", hit, err)
	}
	<-started
	runtime.Flush()
	close(release)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if got := runtime.Len(); got != 0 {
		t.Fatalf("lazy refresh restored %d entries after flush", got)
	}
}

func TestRuntimeCoalescesConcurrentColdMisses(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	const queries = 32
	start := make(chan struct{})
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var calls atomic.Int32
	results := make(chan error, queries)
	forward := func(_ context.Context, qCtx *query_context.Context) error {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
		}
		<-release
		qCtx.SetResponse(runtimeResponse(qCtx.Q()))
		return nil
	}
	for range queries {
		go func() {
			<-start
			qCtx := query_context.NewContext(runtimeQuery("coalesced.example."))
			_, _, err := runtime.Exec(context.Background(), qCtx, forward)
			if err == nil && (qCtx.R() == nil || len(qCtx.R().Answer) != 1) {
				err = errors.New("coalesced query did not receive the leader response")
			}
			results <- err
		}()
	}
	close(start)
	<-entered
	time.Sleep(20 * time.Millisecond)
	close(release)
	for range queries {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("forward calls = %d, want 1", got)
	}
}

func TestRuntimePropagatesOverloadInfoToColdMissWaiter(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	started, release := make(chan struct{}), make(chan struct{})
	wantErr := errors.New("DNS concurrency limit reached")
	leaderCtx := query_context.NewContext(runtimeQuery("overloaded.example."))
	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := runtime.Exec(context.Background(), leaderCtx, func(_ context.Context, qCtx *query_context.Context) error {
			close(started)
			<-release
			query_context.SetOverloadAction(qCtx, query_context.OverloadREFUSED)
			query_context.SetOverloadInfo(qCtx, query_context.OverloadInfo{Scope: query_context.OverloadScopeGroup, GroupID: "default", Limit: 16})
			return wantErr
		})
		leaderDone <- err
	}()
	<-started

	waiterCtx := query_context.NewContext(runtimeQuery("overloaded.example."))
	waiterDone := make(chan error, 1)
	go func() {
		_, _, err := runtime.Exec(context.Background(), waiterCtx, func(context.Context, *query_context.Context) error {
			return errors.New("waiter unexpectedly forwarded")
		})
		waiterDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	close(release)
	if err := <-leaderDone; !errors.Is(err, wantErr) {
		t.Fatalf("leader error = %v", err)
	}
	if err := <-waiterDone; !errors.Is(err, wantErr) {
		t.Fatalf("waiter error = %v", err)
	}
	if action, ok := query_context.OverloadActionFromContext(waiterCtx); !ok || action != query_context.OverloadREFUSED {
		t.Fatalf("waiter overload action = %q ok=%t", action, ok)
	}
	if info, ok := query_context.OverloadInfoFromContext(waiterCtx); !ok || info.Scope != query_context.OverloadScopeGroup || info.GroupID != "default" || info.Limit != 16 {
		t.Fatalf("waiter overload info = %+v ok=%t", info, ok)
	}
}

func TestCacheTTLAPIFlushesExistingEntries(t *testing.T) {
	c := NewCache(&Args{Size: 16}, Opts{})
	c.controlToken = []byte("cache-test-token")
	c.backend.Store("entry", &item{}, time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodPut, "/ttl", bytes.NewBufferString(`{"ttl":60}`))
	req.Header.Set("Authorization", "Bearer cache-test-token")
	response := httptest.NewRecorder()
	c.Api().ServeHTTP(response, req)
	if response.Code != http.StatusOK || c.lazyCacheTTL.Load() != 60 || c.backend.Len() != 0 {
		t.Fatalf("status=%d ttl=%d entries=%d", response.Code, c.lazyCacheTTL.Load(), c.backend.Len())
	}
}

func TestNegativeCacheResponses(t *testing.T) {
	for _, test := range []struct {
		name       string
		response   *dns.Msg
		config     negativeCacheConfig
		wantStored bool
		wantTTL    uint32
	}{
		{name: "NXDOMAIN defaults without SOA", response: negativeResponse(dns.RcodeNameError, false), config: negativeCacheConfig{Enabled: true, TTLSeconds: 30}, wantStored: true, wantTTL: 30},
		{name: "NODATA without SOA", response: negativeResponse(dns.RcodeSuccess, false), config: negativeCacheConfig{Enabled: true, TTLSeconds: 45}, wantStored: true, wantTTL: 45},
		{name: "CNAME-only NODATA", response: cnameOnlyResponse(), config: negativeCacheConfig{Enabled: true, TTLSeconds: 30}, wantStored: true, wantTTL: 30},
		{name: "referral is not NODATA", response: referralResponse(), config: negativeCacheConfig{Enabled: false, TTLSeconds: 30}, wantStored: true, wantTTL: 300},
		{name: "SOA TTL capped by config", response: negativeResponse(dns.RcodeNameError, true), config: negativeCacheConfig{Enabled: true, TTLSeconds: 20}, wantStored: true, wantTTL: 20},
		{name: "SOA minimum caps config", response: negativeResponse(dns.RcodeNameError, true), config: negativeCacheConfig{Enabled: true, TTLSeconds: 300}, wantStored: true, wantTTL: 60},
		{name: "NXDOMAIN disabled", response: negativeResponse(dns.RcodeNameError, false), config: negativeCacheConfig{Enabled: false, TTLSeconds: 30}},
		{name: "NODATA disabled", response: negativeResponse(dns.RcodeSuccess, false), config: negativeCacheConfig{Enabled: false, TTLSeconds: 30}},
		{name: "SERVFAIL", response: negativeResponse(dns.RcodeServerFailure, false), config: negativeCacheConfig{Enabled: true, TTLSeconds: 30}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := NewCache(&Args{Size: 16}, Opts{})
			defer c.Close()
			stored := saveRespToCache("key", test.response, c.backend, 0, test.config)
			if stored != test.wantStored || c.backend.Len() != boolToInt(test.wantStored) {
				t.Fatalf("stored=%t entries=%d", stored, c.backend.Len())
			}
			if test.wantStored {
				entry, expiration, ok := c.backend.Get("key")
				if !ok {
					t.Fatal("stored entry not found")
				}
				remaining := uint32(time.Until(expiration).Round(time.Second) / time.Second)
				if remaining != test.wantTTL {
					t.Fatalf("cache TTL=%d want=%d", remaining, test.wantTTL)
				}
				if len(entry.resp.Ns) > 0 && entry.resp.Ns[0].Header().Ttl > test.wantTTL {
					t.Fatalf("SOA TTL=%d exceeds cache TTL=%d", entry.resp.Ns[0].Header().Ttl, test.wantTTL)
				}
			}
		})
	}
}

func TestCacheDoesNotStoreResponseWhenExecutionFails(t *testing.T) {
	c := NewCache(&Args{Size: 16}, Opts{})
	defer c.Close()
	query := new(dns.Msg)
	query.SetQuestion("error.example.", dns.TypeA)
	qCtx := query_context.NewContext(query)
	wantErr := errors.New("upstream failed")
	next := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		qCtx.SetResponse(negativeResponse(dns.RcodeNameError, false))
		return wantErr
	})}}, nil)
	if err := c.Exec(context.Background(), qCtx, next); !errors.Is(err, wantErr) {
		t.Fatalf("error=%v want=%v", err, wantErr)
	}
	if c.backend.Len() != 0 {
		t.Fatalf("execution error cached %d entries", c.backend.Len())
	}
}

func TestNegativeCacheAPI(t *testing.T) {
	c := NewCache(&Args{Size: 16}, Opts{})
	defer c.Close()
	c.controlToken = []byte("cache-test-token")

	response := cacheAPIRequest(c, http.MethodGet, "/negative-cache", "")
	var initial negativeCacheConfig
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&initial) != nil || !initial.Enabled || initial.TTLSeconds != defaultNegativeCacheTTL {
		t.Fatalf("default response status=%d config=%+v", response.Code, initial)
	}

	for _, test := range []struct {
		name string
		body string
		want int
	}{
		{name: "minimum", body: `{"enabled":true,"ttl_seconds":1}`, want: http.StatusOK},
		{name: "maximum and disabled", body: `{"enabled":false,"ttl_seconds":86400}`, want: http.StatusOK},
		{name: "zero", body: `{"enabled":false,"ttl_seconds":0}`, want: http.StatusBadRequest},
		{name: "too large", body: `{"enabled":true,"ttl_seconds":86401}`, want: http.StatusBadRequest},
		{name: "negative", body: `{"enabled":true,"ttl_seconds":-1}`, want: http.StatusBadRequest},
		{name: "missing TTL", body: `{"enabled":true}`, want: http.StatusBadRequest},
		{name: "missing enabled", body: `{"ttl_seconds":30}`, want: http.StatusBadRequest},
		{name: "unknown field", body: `{"enabled":true,"ttl_seconds":30,"extra":1}`, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			c.backend.Store("entry", &item{}, time.Now().Add(time.Hour))
			response := cacheAPIRequest(c, http.MethodPut, "/negative-cache", test.body)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.want == http.StatusOK && c.backend.Len() != 0 {
				t.Fatalf("configuration change left %d entries", c.backend.Len())
			}
			c.backend.Flush()
		})
	}

	response = cacheAPIRequest(c, http.MethodGet, "/negative-cache", "")
	var current negativeCacheConfig
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&current) != nil || current.Enabled || current.TTLSeconds != maxNegativeCacheTTL {
		t.Fatalf("current response status=%d config=%+v", response.Code, current)
	}
}

func TestNegativeCacheAPIKeepsEntriesWhenConfigurationIsUnchanged(t *testing.T) {
	c := NewCache(&Args{Size: 16}, Opts{})
	defer c.Close()
	c.controlToken = []byte("cache-test-token")
	c.backend.Store("entry", &item{}, time.Now().Add(time.Hour))

	response := cacheAPIRequest(c, http.MethodPut, "/negative-cache", `{"enabled":true,"ttl_seconds":30}`)
	if response.Code != http.StatusOK || c.backend.Len() != 1 {
		t.Fatalf("status=%d entries=%d", response.Code, c.backend.Len())
	}
}

func TestReadDumpSkipsEntriesWithoutStoredTime(t *testing.T) {
	resp := new(dns.Msg)
	resp.SetQuestion("legacy.example.", dns.TypeA)
	resp.Response = true
	resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "legacy.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	block, err := proto.Marshal(&CacheDumpBlock{Entries: []*CachedEntry{{
		Key:                 []byte("legacy"),
		CacheExpirationTime: time.Now().Add(time.Minute).Unix(),
		MsgExpirationTime:   time.Now().Add(time.Minute).Unix(),
		Msg:                 packed,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var dump bytes.Buffer
	writer, err := gzip.NewWriterLevel(&dump, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	writer.Name = dumpHeader
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(len(block)))
	if _, err := writer.Write(length); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(block); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	c := NewCache(&Args{Size: 16}, Opts{})
	defer c.Close()
	loaded, err := c.readDump(&dump)
	if err != nil || loaded != 0 || c.backend.Len() != 0 {
		t.Fatalf("loaded=%d entries=%d err=%v", loaded, c.backend.Len(), err)
	}
}

func negativeResponse(rcode int, withSOA bool) *dns.Msg {
	response := new(dns.Msg)
	response.SetQuestion("negative.example.", dns.TypeA)
	response.Response = true
	response.Rcode = rcode
	if withSOA {
		response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120}, Minttl: 60}}
	}
	return response
}

func cnameOnlyResponse() *dns.Msg {
	response := negativeResponse(dns.RcodeSuccess, false)
	response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "negative.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "missing.example."}}
	return response
}

func referralResponse() *dns.Msg {
	response := negativeResponse(dns.RcodeSuccess, false)
	response.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example."}}
	return response
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func cacheAPIRequest(c *Cache, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer cache-test-token")
	response := httptest.NewRecorder()
	c.Api().ServeHTTP(response, request)
	return response
}

func newTestRuntime(t *testing.T, lazyTTL int) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(RuntimeConfig{Enabled: true, Size: 128, LazyCacheTTL: lazyTTL, NegativeTTLSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func runtimeQuery(name string) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeA)
	return query
}

func runtimeResponse(query *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: query.Question[0].Qclass, Ttl: 60}, A: []byte{192, 0, 2, 1}}}
	return response
}

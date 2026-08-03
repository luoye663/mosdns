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
	"hash/maphash"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"golang.org/x/exp/constraints"
)

type key string

var seed = maphash.MakeSeed()

func (k key) Sum() uint64 {
	return maphash.String(seed, string(k))
}

// getMsgKey returns a string key for the query msg, or an empty
// string if query should not be cached.
func getMsgKey(q *dns.Msg) string {
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return ""
	}

	const (
		adBit = 1 << iota
		cdBit
		doBit
	)

	question := q.Question[0]
	buf := make([]byte, 1+2+1+len(question.Name)) // bits + qtype + qname length + qname
	b := byte(0)
	// RFC 6840 5.7: The AD bit in a query as a signal
	// indicating that the requester understands and is interested in the
	// value of the AD bit in the response.
	if q.AuthenticatedData {
		b = b | adBit
	}
	if q.CheckingDisabled {
		b = b | cdBit
	}
	if opt := q.IsEdns0(); opt != nil && opt.Do() {
		b = b | doBit
	}
	buf[0] = b
	buf[1] = byte(question.Qtype << 8)
	buf[2] = byte(question.Qtype)
	buf[3] = byte(len(question.Name))
	copy(buf[4:], question.Name)
	// ECS changes an upstream's geographic answer. Include it in the key so
	// clients from distinct anonymous subnets can never share an answer.
	if opt := q.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
				buf = append(buf, byte(ecs.Family>>8), byte(ecs.Family), ecs.SourceNetmask, ecs.SourceScope)
				buf = append(buf, ecs.Address...)
				break
			}
		}
	}
	return utils.BytesToStringUnsafe(buf)
}

type item struct {
	resp           *dns.Msg
	storedTime     time.Time
	expirationTime time.Time
}

func copyNoOpt(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}

	m2 := new(dns.Msg)
	m2.MsgHdr = m.MsgHdr
	m2.Compress = m.Compress

	if len(m.Question) > 0 {
		m2.Question = make([]dns.Question, len(m.Question))
		copy(m2.Question, m.Question)
	}

	lenExtra := len(m.Extra)
	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			lenExtra--
		}
	}

	s := make([]dns.RR, len(m.Answer)+len(m.Ns)+lenExtra)
	m2.Answer, s = s[:0:len(m.Answer)], s[len(m.Answer):]
	m2.Ns, s = s[:0:len(m.Ns)], s[len(m.Ns):]
	m2.Extra = s[:0:lenExtra]

	for _, r := range m.Answer {
		m2.Answer = append(m2.Answer, dns.Copy(r))
	}
	for _, r := range m.Ns {
		m2.Ns = append(m2.Ns, dns.Copy(r))
	}

	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}
		m2.Extra = append(m2.Extra, dns.Copy(r))
	}
	return m2
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

// getRespFromCache returns the cached response from cache.
// The ttl of returned msg will be changed properly.
// Returned bool indicates whether this response is hit by lazy cache.
// Note: Caller SHOULD change the msg id because it's not same as query's.
func getRespFromCache(msgKey string, backend *cache.Cache[key, *item], lazyCacheEnabled bool, lazyTtl int) (*dns.Msg, bool) {
	// Lookup cache
	v, _, _ := backend.Get(key(msgKey))

	// Cache hit
	if v != nil {
		now := time.Now()

		// Not expired.
		if now.Before(v.expirationTime) {
			r := v.resp.Copy()
			dnsutils.SubtractTTL(r, uint32(now.Sub(v.storedTime).Seconds()))
			return r, false
		}

		// Msg expired but cache isn't. This is a lazy cache enabled entry.
		// If lazy cache is enabled, return the response.
		if lazyCacheEnabled {
			r := v.resp.Copy()
			dnsutils.SetTTL(r, uint32(lazyTtl))
			return r, true
		}
	}

	// cache miss
	return nil, false
}

// saveRespToCache saves r to cache backend. It returns false if r
// should not be cached and was skipped.
func saveRespToCache(msgKey string, r *dns.Msg, backend *cache.Cache[key, *item], lazyCacheTtl int, negativeConfig negativeCacheConfig) bool {
	if r.Truncated != false {
		return false
	}

	var msgTtl time.Duration
	var cacheTtl time.Duration
	negativeTTL, negative := getNegativeTTL(r, negativeConfig)
	if negative {
		if negativeTTL == 0 {
			return false
		}
		msgTtl = time.Duration(negativeTTL) * time.Second
		cacheTtl = msgTtl
	} else if r.Rcode == dns.RcodeSuccess {
		minTTL := dnsutils.GetMinimalTTL(r)
		msgTtl = time.Duration(minTTL) * time.Second
		if lazyCacheTtl > 0 {
			cacheTtl = time.Duration(lazyCacheTtl) * time.Second
		} else {
			cacheTtl = msgTtl
		}
	}
	if msgTtl <= 0 || cacheTtl <= 0 {
		return false
	}

	now := time.Now()
	resp := copyNoOpt(r)
	if negative {
		capNegativeSOATTL(resp, negativeTTL)
	}
	v := &item{
		resp:           resp,
		storedTime:     now,
		expirationTime: now.Add(msgTtl),
	}
	backend.Store(key(msgKey), v, now.Add(cacheTtl))
	return true
}

func getNegativeTTL(r *dns.Msg, config negativeCacheConfig) (uint32, bool) {
	isNegative := r.Rcode == dns.RcodeNameError || isNODATA(r)
	if !isNegative {
		return 0, false
	}
	if !config.Enabled {
		return 0, true
	}

	ttl := config.TTLSeconds
	for _, rr := range r.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl = min(ttl, min(soa.Hdr.Ttl, soa.Minttl))
	}
	return ttl, true
}

func capNegativeSOATTL(r *dns.Msg, ttl uint32) {
	for _, rr := range r.Ns {
		if _, ok := rr.(*dns.SOA); ok && rr.Header().Ttl > ttl {
			rr.Header().Ttl = ttl
		}
	}
}

func isNODATA(r *dns.Msg) bool {
	if r.Rcode != dns.RcodeSuccess {
		return false
	}
	if len(r.Answer) > 0 {
		if len(r.Question) != 1 || r.Question[0].Qtype == dns.TypeANY {
			return false
		}
		qtype := r.Question[0].Qtype
		for _, rr := range r.Answer {
			if rr.Header().Rrtype == qtype {
				return false
			}
		}
	}

	hasSOA := false
	hasNS := false
	for _, rr := range r.Ns {
		hasSOA = hasSOA || rr.Header().Rrtype == dns.TypeSOA
		hasNS = hasNS || rr.Header().Rrtype == dns.TypeNS
	}
	if hasNS && !hasSOA {
		return false
	}
	return true
}

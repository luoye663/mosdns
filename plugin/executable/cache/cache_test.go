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
	"github.com/miekg/dns"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func Test_cachePlugin_Dump(t *testing.T) {
	c := NewCache(&Args{Size: 16 * dumpBlockSize}, Opts{}) // Big enough to create dump fragments.

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
	enr, err := c.readDump(buf)
	if err != nil {
		t.Fatal(err)
	}

	if enw != enr {
		t.Fatalf("read err, wrote %d entries, read %d", enw, enr)
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

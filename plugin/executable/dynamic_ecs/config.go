// Package dynamic_ecs applies per-group EDNS Client Subnet configuration.
package dynamic_ecs

import (
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

type Config struct {
	Mode    string `json:"mode" yaml:"mode"`
	Mask4   int    `json:"mask4" yaml:"mask4"`
	Mask6   int    `json:"mask6" yaml:"mask6"`
	Preset4 string `json:"preset4,omitempty" yaml:"preset4"`
	Preset6 string `json:"preset6,omitempty" yaml:"preset6"`
}

func CanonicalConfig(config Config) (Config, error) {
	if config.Mode == "" {
		config.Mode = "off"
	}
	if config.Mode != "off" && config.Mode != "client_subnet" && config.Mode != "fixed_subnet" {
		return Config{}, errors.New("mode must be off, client_subnet or fixed_subnet")
	}
	if config.Mask4 == 0 {
		config.Mask4 = 24
	}
	if config.Mask6 == 0 {
		config.Mask6 = 48
	}
	if config.Mask4 < 0 || config.Mask4 > 32 || config.Mask6 < 0 || config.Mask6 > 128 {
		return Config{}, errors.New("invalid ECS mask")
	}
	config.Preset4, config.Preset6 = strings.TrimSpace(config.Preset4), strings.TrimSpace(config.Preset6)
	if config.Mode == "fixed_subnet" {
		if config.Preset4 == "" && config.Preset6 == "" {
			return Config{}, errors.New("at least one fixed subnet is required")
		}
		for _, item := range []struct {
			value *string
			want4 bool
		}{{&config.Preset4, true}, {&config.Preset6, false}} {
			if *item.value == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(*item.value)
			if err != nil || prefix.Addr().Is4() != item.want4 {
				return Config{}, errors.New("fixed subnets must be valid IPv4 or IPv6 CIDRs")
			}
			*item.value = prefix.Masked().String()
		}
	} else if config.Preset4 != "" || config.Preset6 != "" {
		return Config{}, errors.New("fixed subnets are only allowed for fixed_subnet")
	}
	return config, nil
}

func ApplyConfig(qCtx *query_context.Context, config Config) error {
	if config.Mode == "off" {
		return nil
	}
	opt := qCtx.QOpt()
	for _, item := range opt.Option {
		if item.Option() == dns.EDNS0SUBNET {
			return nil
		}
	}
	if qCtx.QQuestion().Qclass != dns.ClassINET {
		return nil
	}
	var addr netip.Addr
	bits := config.Mask6
	if config.Mode == "fixed_subnet" {
		preset := config.Preset6
		if qCtx.ServerMeta.ClientAddr.Unmap().Is4() {
			preset = config.Preset4
		}
		if preset == "" {
			return nil
		}
		prefix, _ := netip.ParsePrefix(preset)
		addr, bits = prefix.Addr(), prefix.Bits()
	} else {
		addr = qCtx.ServerMeta.ClientAddr.Unmap()
	}
	if !addr.IsValid() {
		return nil
	}
	family := uint16(2)
	if addr.Is4() {
		bits, family = config.Mask4, 1
		if config.Mode == "fixed_subnet" {
			prefix, _ := netip.ParsePrefix(config.Preset4)
			bits = prefix.Bits()
		}
	}
	masked := netip.PrefixFrom(addr, bits).Masked().Addr()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: uint8(bits), Address: net.IP(masked.AsSlice())})
	return nil
}

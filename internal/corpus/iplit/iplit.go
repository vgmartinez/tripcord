// Package iplit parses IPv4 literals the way inet_aton does, so a host
// check sees decimal, hex, octal, and short dotted forms as addresses.
package iplit

import (
	"net"
	"strconv"
	"strings"
)

// ParseIPv4 reads an inet_aton address: one 32-bit value, a.b with
// b 24 bits, a.b.c with c 16 bits, or a.b.c.d. Each component is
// decimal, hex (0x), or octal (leading 0).
func ParseIPv4(s string) (net.IP, bool) {
	if s == "" || strings.ContainsAny(s, "/?#@") {
		return nil, false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return nil, false
	}
	nums := make([]uint64, len(parts))
	for i, part := range parts {
		n, ok := parseComp(part)
		if !ok {
			return nil, false
		}
		nums[i] = n
	}
	var ip uint64
	switch len(nums) {
	case 1:
		if nums[0] > 0xffffffff {
			return nil, false
		}
		ip = nums[0]
	case 2:
		if nums[0] > 0xff || nums[1] > 0xffffff {
			return nil, false
		}
		ip = nums[0]<<24 | nums[1]
	case 3:
		if nums[0] > 0xff || nums[1] > 0xff || nums[2] > 0xffff {
			return nil, false
		}
		ip = nums[0]<<24 | nums[1]<<16 | nums[2]
	case 4:
		if nums[0] > 0xff || nums[1] > 0xff || nums[2] > 0xff || nums[3] > 0xff {
			return nil, false
		}
		ip = nums[0]<<24 | nums[1]<<16 | nums[2]<<8 | nums[3]
	default:
		return nil, false
	}
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).To4(), true
}

func parseComp(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) > 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')):
		base = 16
		s = s[2:]
	case len(s) > 1 && s[0] == '0':
		base = 8
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

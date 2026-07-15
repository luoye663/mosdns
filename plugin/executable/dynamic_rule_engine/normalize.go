package dynamic_rule_engine

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// NormalizeDomain 执行项目规则要求的统一域名规范化；regexp 不应调用此函数。
func NormalizeDomain(input string) (string, error) {
	s := strings.TrimSpace(input)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("domain is empty")
	}
	if strings.ContainsRune(s, '*') {
		return "", fmt.Errorf("domain contains wildcard")
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("domain contains control character")
	}

	// Lookup profile 同时执行 IDNA 查找域名所需的 ASCII 转换与字符约束。
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(s))
	if err != nil {
		return "", fmt.Errorf("convert IDN to ASCII: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > DefaultLimits().MaxDomainChars {
		return "", fmt.Errorf("domain length %d exceeds %d", len(ascii), DefaultLimits().MaxDomainChars)
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", fmt.Errorf("domain contains empty label")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("domain label length %d exceeds 63", len(label))
		}
		if !utf8.ValidString(label) {
			return "", fmt.Errorf("domain label is not valid UTF-8")
		}
	}
	return ascii, nil
}

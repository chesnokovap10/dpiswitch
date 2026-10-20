package nrpt

import (
	"strings"
	"testing"
)

// The lines Get-DnsClientNrptPolicy prints: the rule is found among others,
// and another server set for "." is not it.
func TestEffectiveIn(t *testing.T) {
	if !effectiveIn("10.0.0.1\r\n" + strings.Join(Servers, ";") + "\r\n") {
		t.Error("the rule not found")
	}
	if effectiveIn("198.18.0.2\r\n") || effectiveIn("") {
		t.Error("another table taken for the rule")
	}
}

package probe

import (
	"errors"
	"testing"
)

// A lookup no resolver answered is asked once more; one answered with no
// record is an answer, and is not.
func TestAskTwice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		errs  []error
		asked int
		ok    bool
	}{
		{"answered", []error{nil}, 1, true},
		{"no records", []error{lookupError{"no records; timeout", true}}, 1, false},
		{"failed, then answered", []error{lookupError{"timeout; SERVFAIL", false}, nil}, 2, true},
		{"failed twice", []error{errors.New("timeout"), errors.New("timeout")}, 2, false},
	} {
		n := 0
		ips, err := askTwice(func() ([]string, error) {
			err := tc.errs[n]
			n++
			if err != nil {
				return nil, err
			}
			return []string{"2001:db8::1"}, nil
		})
		if n != tc.asked || (err == nil && len(ips) == 1) != tc.ok {
			t.Errorf("%s: asked %d times, %v, %v", tc.name, n, ips, err)
		}
	}
	// what lookupAny says of resolvers that all answered "none"
	_, err := lookupAny(Dialer{}, []Resolver{{}, {}}, "a.example",
		func(Resolver, Dialer, string) ([]string, error) { return nil, nil })
	if !errors.Is(err, errNoRecords) || err.Error() != "no records; no records" {
		t.Errorf("no records anywhere: %v", err)
	}
	_, err = lookupAny(Dialer{}, []Resolver{{}}, "a.example",
		func(Resolver, Dialer, string) ([]string, error) { return nil, errors.New("timeout") })
	if errors.Is(err, errNoRecords) {
		t.Errorf("a failure taken for an answer: %v", err)
	}
}

package webui

import (
	"errors"
	"fmt"
	"net"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/paths"
)

// Second tunnel (awg2): presets and the custom list only.
// Other traffic is unaffected -- it still goes through awg + the detector.

// saveConf2 checks and stores the second tunnel's .conf. Loading and
// removing it changes config.yaml, so the service restarts afterwards.
func saveConf2(text string) error {
	c, err := awgconf.Parse(text)
	if err != nil {
		return err
	}
	if _, _, err := net.SplitHostPort(c.Peer["Endpoint"]); err != nil {
		return fmt.Errorf("cannot parse Endpoint: %w", err)
	}
	if c1, err := awgconf.ParseFile(paths.SourceConf()); err == nil && awgconf.SameKey(c1, c) {
		return errors.New("this is the same config as the first tunnel")
	}
	if err := paths.UserReady(); err != nil {
		return err
	}
	// the second tunnel's private key: written locked down, or not at all
	return paths.WriteSecret(paths.SourceConf2(), []byte(text))
}

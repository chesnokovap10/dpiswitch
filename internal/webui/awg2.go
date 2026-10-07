package webui

import (
	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/paths"
)

// Second tunnel (awg2): presets and the custom list only.
// Other traffic is unaffected -- it still goes through awg1 + the detector.

// saveConf2 checks and stores the second tunnel's .conf. Loading and
// removing it changes config.yaml, so the service restarts afterwards. A
// .conf the core could not use is refused here: it used to be taken, and
// the service left it out of the config with a line in its log alone.
func saveConf2(text string) error {
	c, err := awgconf.Parse(text)
	if err != nil {
		return err
	}
	if err := c.Usable(); err != nil {
		return err
	}
	if err := c.CheckKeys(); err != nil {
		return err
	}
	if c1, err := awgconf.ParseFile(paths.SourceConf()); err == nil && awgconf.SameKey(c1, c) {
		return awgconf.ErrSameKey
	}
	if err := paths.UserReady(); err != nil {
		return err
	}
	// the second tunnel's private key: written locked down, or not at all
	return paths.WriteSecret(paths.SourceConf2(), []byte(text))
}

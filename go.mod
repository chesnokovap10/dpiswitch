module dpiswitch

go 1.26.0

require (
	github.com/quic-go/quic-go v0.62.0
	github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	go4.org/netipx v0.0.0-20220725152314-7e7bdc8411bf // indirect
	golang.org/x/text v0.42.0 // indirect
)

// patched: the arena hands out aligned memory, see third_party/wf/README.md
replace github.com/tailscale/wf => ./third_party/wf

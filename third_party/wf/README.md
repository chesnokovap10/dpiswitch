# tailscale/wf, patched

A copy of github.com/tailscale/wf at 6fbb0a674ee6 (2024-02-14, the latest
there is), used through the `replace` in dpiswitch's go.mod. One change, in
malloc.go: the arena hands out pointer-aligned memory. Upstream bumps its
pointer by each allocation's length, so a struct with pointers could land
at an odd address after a string; writing it while the garbage collector is
marking runs the write barrier, which throws on an unaligned destination --
the service died at start with "bulkBarrierPreWrite: unaligned arguments"
whenever the UDP guard put its filters in during a GC (07.10.2026).

The generators, the tool dependencies and the tests that need an
administrator are left out. Licensed under the BSD license in LICENSE.

// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

import (
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

// Every allocation is pointer-aligned, whatever came before it: a string
// of an odd count of UTF-16 units used to leave the next struct at an
// address the write barrier throws on.
func TestArenaAligned(t *testing.T) {
	var a arena
	defer a.Dispose()
	for _, n := range []uintptr{1, 2, 3, 6, 10, 16, 17, 24, 4000, 5, 90} {
		p := uintptr(a.Alloc(n))
		if p%unsafe.Sizeof(uintptr(0)) != 0 {
			t.Fatalf("allocation of %d bytes at %#x, not pointer-aligned", n, p)
		}
	}
}

// What the service died of: rules turned into filters after allocations of
// every length, while the collector runs. With the arena unaligned this
// throws "bulkBarrierPreWrite: unaligned arguments".
func TestFilterWhileCollecting(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	lt := layerTypes{LayerALEAuthConnectV4: {}}
	for i := 0; i < 2000; i++ {
		var a arena
		// what comes before the filter in the service: its conditions,
		// a program's path among them, of any length
		a.Alloc(uintptr(1 + i%7))
		r := &Rule{
			Name:   strings.Repeat("x", i%7),
			Layer:  LayerALEAuthConnectV4,
			Weight: 1,
			Action: ActionBlock,
		}
		if _, err := toFilter0(&a, r, lt); err != nil {
			t.Fatal(err)
		}
		a.Dispose()
	}
}

// genicon draws the application and tray icons.
//
// The glyph is a branching arrow -- one stem splitting into two paths --
// which is what the program does: traffic forks into the direct path and
// the tunnel. Everything is rendered from geometry with supersampling, so
// every size is crisp instead of being scaled down from one bitmap.
//
//	go run ./tools/genicon
//
// writes assets/app.ico (16..256, PNG entries, for the exe) and
// internal/tray/icons/{on,off,error}.ico (16..32, BMP entries, for the tray).
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

type rgb struct{ r, g, b float64 }

// point in unit coordinates, (0,0) top-left
type pt struct{ x, y float64 }

// glyph geometry in unit coordinates
var (
	stemBottom = pt{0.5, 0.82}
	fork       = pt{0.5, 0.60}
	leftTip    = pt{0.25, 0.25}
	rightTip   = pt{0.75, 0.25}
	stroke     = 0.072 // half-width of the lines
	headLen    = 0.16
	headHalf   = 0.125
)

func segDist(p, a, b pt) float64 {
	dx, dy := b.x-a.x, b.y-a.y
	t := ((p.x-a.x)*dx + (p.y-a.y)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	cx, cy := a.x+t*dx-p.x, a.y+t*dy-p.y
	return math.Hypot(cx, cy)
}

func inTriangle(p, a, b, c pt) bool {
	s := func(p1, p2, p3 pt) float64 { return (p1.x-p3.x)*(p2.y-p3.y) - (p2.x-p3.x)*(p1.y-p3.y) }
	d1, d2, d3 := s(p, a, b), s(p, b, c), s(p, c, a)
	neg := d1 < 0 || d2 < 0 || d3 < 0
	pos := d1 > 0 || d2 > 0 || d3 > 0
	return !(neg && pos)
}

// arrowhead at tip, pointing away from `from`
func head(tip, from pt) (a, b, c pt) {
	dx, dy := tip.x-from.x, tip.y-from.y
	l := math.Hypot(dx, dy)
	ux, uy := dx/l, dy/l
	// push the tip a little forward so the head covers the line end
	t := pt{tip.x + ux*headLen*0.35, tip.y + uy*headLen*0.35}
	base := pt{t.x - ux*headLen, t.y - uy*headLen}
	return t, pt{base.x - uy*headHalf, base.y + ux*headHalf}, pt{base.x + uy*headHalf, base.y - ux*headHalf}
}

// shaft ends where the arrowhead begins, so line caps don't stick out
func shaftEnd(tip, from pt) pt {
	dx, dy := tip.x-from.x, tip.y-from.y
	l := math.Hypot(dx, dy)
	return pt{tip.x - dx/l*headLen*0.4, tip.y - dy/l*headLen*0.4}
}

func inGlyph(p pt) bool {
	if segDist(p, stemBottom, fork) <= stroke {
		return true
	}
	for _, tip := range []pt{leftTip, rightTip} {
		if segDist(p, fork, shaftEnd(tip, fork)) <= stroke {
			return true
		}
		a, b, c := head(tip, fork)
		if inTriangle(p, a, b, c) {
			return true
		}
	}
	return false
}

// background shapes
func inRoundRect(p pt, r float64) bool {
	m := 0.02 // margin
	x := math.Max(math.Abs(p.x-0.5)-(0.5-m-r), 0)
	y := math.Max(math.Abs(p.y-0.5)-(0.5-m-r), 0)
	return math.Hypot(x, y) <= r
}

func inCircle(p pt) bool { return math.Hypot(p.x-0.5, p.y-0.5) <= 0.48 }

type style struct {
	circle   bool // tray: circle, app: rounded square
	top, bot rgb  // vertical gradient
}

func render(size int, st style) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 8 // supersampling per axis
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var bg, gl float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					p := pt{(float64(x) + (float64(sx)+0.5)/ss) / float64(size),
						(float64(y) + (float64(sy)+0.5)/ss) / float64(size)}
					in := false
					if st.circle {
						in = inCircle(p)
					} else {
						in = inRoundRect(p, 0.22)
					}
					if in {
						bg++
						if inGlyph(p) {
							gl++
						}
					}
				}
			}
			n := float64(ss * ss)
			a := bg / n
			if a == 0 {
				continue
			}
			t := (float64(y) + 0.5) / float64(size)
			c := rgb{st.top.r + (st.bot.r-st.top.r)*t, st.top.g + (st.bot.g-st.top.g)*t, st.top.b + (st.bot.b-st.top.b)*t}
			w := gl / bg // share of white glyph inside the covered area
			r := c.r*(1-w) + 255*w
			g := c.g*(1-w) + 255*w
			b := c.b*(1-w) + 255*w
			img.SetNRGBA(x, y, color.NRGBA{uint8(r + 0.5), uint8(g + 0.5), uint8(b + 0.5), uint8(a*255 + 0.5)})
		}
	}
	return img
}

// bmpEntry encodes an image as an ICO BMP entry (BITMAPINFOHEADER + BGRA + AND mask)
func bmpEntry(img *image.NRGBA) []byte {
	s := img.Bounds().Dx()
	var b bytes.Buffer
	le(&b, uint32(40), int32(s), int32(s*2), uint16(1), uint16(32),
		uint32(0), uint32(0), int32(0), int32(0), uint32(0), uint32(0))
	for y := s - 1; y >= 0; y-- {
		for x := 0; x < s; x++ {
			c := img.NRGBAAt(x, y)
			b.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	rowBytes := ((s + 31) / 32) * 4
	b.Write(make([]byte, rowBytes*s)) // AND mask: all zero, alpha does the work
	return b.Bytes()
}

// le writes fixed-size values in little-endian order
func le(b *bytes.Buffer, vals ...any) {
	for _, v := range vals {
		binary.Write(b, binary.LittleEndian, v)
	}
}

func pngEntry(img *image.NRGBA) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		log.Fatal(err)
	}
	return b.Bytes()
}

func writeICO(path string, sizes []int, st style, usePNG func(int) bool) {
	type ent struct {
		size int
		data []byte
	}
	var ents []ent
	for _, s := range sizes {
		img := render(s, st)
		if usePNG(s) {
			ents = append(ents, ent{s, pngEntry(img)})
		} else {
			ents = append(ents, ent{s, bmpEntry(img)})
		}
	}
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, []uint16{0, 1, uint16(len(ents))})
	off := 6 + 16*len(ents)
	for _, e := range ents {
		d := byte(e.size)
		if e.size >= 256 {
			d = 0
		}
		b.Write([]byte{d, d, 0, 0})
		le(&b, uint16(1), uint16(32), uint32(len(e.data)), uint32(off))
		off += len(e.data)
	}
	for _, e := range ents {
		b.Write(e.data)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("%s: %d sizes, %d bytes", path, len(ents), b.Len())
}

func main() {
	// application icon: teal-to-blue rounded square; large sizes as PNG
	writeICO("assets/app.ico", []int{16, 20, 24, 32, 40, 48, 64, 96, 128, 256},
		style{top: rgb{38, 196, 133}, bot: rgb{30, 110, 220}},
		func(s int) bool { return s >= 64 })

	// tray icons: state-coloured circles, BMP entries (read by the tray loader)
	tray := []int{16, 20, 24, 32}
	bmp := func(int) bool { return false }
	writeICO("internal/tray/icons/on.ico", tray, style{circle: true, top: rgb{52, 190, 110}, bot: rgb{30, 150, 85}}, bmp)
	writeICO("internal/tray/icons/off.ico", tray, style{circle: true, top: rgb{150, 156, 166}, bot: rgb{110, 116, 126}}, bmp)
	writeICO("internal/tray/icons/error.ico", tray, style{circle: true, top: rgb{235, 90, 75}, bot: rgb{195, 50, 45}}, bmp)
}

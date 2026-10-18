// macapp собирает NetSwitch для macOS на любой системе: бинарники для Intel и Apple Silicon,
// универсальный (fat) Mach-O из них, NetSwitch.app с иконкой и архив NetSwitch-mac.zip.
//
//	go run ./tools/macapp -version 1.4.0 -out dist
//
// Запускать из корня репозитория. Время файлов в архиве — время последнего коммита.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func main() {
	version := flag.String("version", "", "версия программы, например 1.4.0")
	out := flag.String("out", "dist", "папка для результата")
	readme := flag.String("readme", "", "README.txt, который положить в архив рядом с NetSwitch.app")
	flag.Parse()
	if *version == "" {
		fail("нужен -version")
	}
	if err := os.MkdirAll(*out, 0755); err != nil {
		fail(err.Error())
	}
	mtime := commitTime()

	var slices [][]byte
	for _, arch := range []string{"amd64", "arm64"} {
		bin := filepath.Join(*out, "NetSwitch-darwin-"+arch)
		build(arch, bin)
		b, err := os.ReadFile(bin)
		if err != nil {
			fail(err.Error())
		}
		slices = append(slices, b)
	}
	exe := fat(slices)
	icns := icon()
	plist := infoPlist(*version)

	zpath := filepath.Join(*out, "NetSwitch-mac.zip")
	f, err := os.Create(zpath)
	if err != nil {
		fail(err.Error())
	}
	zw := zip.NewWriter(f)
	add := func(name string, mode os.FileMode, data []byte) {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mtime}
		if strings.HasSuffix(name, "/") {
			h.Method = zip.Store
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			fail(err.Error())
		}
		if _, err := w.Write(data); err != nil {
			fail(err.Error())
		}
	}
	const app = "NetSwitch/NetSwitch.app/"
	add("NetSwitch/", os.ModeDir|0755, nil)
	add(app, os.ModeDir|0755, nil)
	add(app+"Contents/", os.ModeDir|0755, nil)
	add(app+"Contents/Info.plist", 0644, []byte(plist))
	add(app+"Contents/PkgInfo", 0644, []byte("APPL????"))
	add(app+"Contents/MacOS/", os.ModeDir|0755, nil)
	add(app+"Contents/MacOS/NetSwitch", 0755, exe)
	add(app+"Contents/Resources/", os.ModeDir|0755, nil)
	add(app+"Contents/Resources/NetSwitch.icns", 0644, icns)
	if *readme != "" {
		b, err := os.ReadFile(*readme)
		if err != nil {
			fail(err.Error())
		}
		add("NetSwitch/README.txt", 0644, b)
	}
	if err := zw.Close(); err != nil {
		fail(err.Error())
	}
	f.Close()
	_ = os.WriteFile(filepath.Join(*out, "NetSwitch-universal"), exe, 0755)
	fmt.Println("готово:", zpath)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "macapp:", msg)
	os.Exit(1)
}

func commitTime() time.Time {
	out, err := exec.Command("git", "log", "-1", "--format=%ct").Output()
	if err != nil {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	sec, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return time.Unix(sec, 0).UTC()
}

func build(arch, out string) {
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	c := exec.Command(gobin, "build", "-trimpath", "-ldflags", "-s -w", "-o", out, ".")
	c.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		fail("go build " + arch + ": " + err.Error())
	}
}

// fat склеивает тонкие Mach-O в универсальный: заголовок 0xCAFEBABE и срезы по границе 16 КБ.
func fat(slices [][]byte) []byte {
	const align = 14
	var hdr bytes.Buffer
	be := binary.BigEndian
	_ = binary.Write(&hdr, be, uint32(0xCAFEBABE))
	_ = binary.Write(&hdr, be, uint32(len(slices)))
	off := uint32(1 << align)
	var offs []uint32
	for _, s := range slices {
		if len(s) < 12 || binary.LittleEndian.Uint32(s) != 0xFEEDFACF {
			fail("не 64-битный Mach-O")
		}
		cpu, sub := binary.LittleEndian.Uint32(s[4:]), binary.LittleEndian.Uint32(s[8:])
		for _, v := range []uint32{cpu, sub, off, uint32(len(s)), align} {
			_ = binary.Write(&hdr, be, v)
		}
		offs = append(offs, off)
		off += uint32(len(s))
		off = (off + (1<<align - 1)) &^ (1<<align - 1)
	}
	res := make([]byte, off)
	copy(res, hdr.Bytes())
	for i, s := range slices {
		copy(res[offs[i]:], s)
	}
	return res[:int(offs[len(offs)-1])+len(slices[len(slices)-1])]
}

func infoPlist(version string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>ru</string>
	<key>CFBundleExecutable</key>
	<string>NetSwitch</string>
	<key>CFBundleIconFile</key>
	<string>NetSwitch</string>
	<key>CFBundleIdentifier</key>
	<string>com.netswitch.app</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>NetSwitch</string>
	<key>CFBundleDisplayName</key>
	<string>NetSwitch</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>` + version + `</string>
	<key>CFBundleVersion</key>
	<string>` + version + `</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
`
}

// icon — значок как в окне программы: синий скруглённый квадрат с двумя стрелками.
func icon() []byte {
	var body bytes.Buffer
	for _, e := range []struct {
		typ  string
		size int
	}{{"ic07", 128}, {"ic08", 256}, {"ic09", 512}, {"ic10", 1024}} {
		var p bytes.Buffer
		_ = png.Encode(&p, drawIcon(e.size))
		body.WriteString(e.typ)
		_ = binary.Write(&body, binary.BigEndian, uint32(8+p.Len()))
		body.Write(p.Bytes())
	}
	var res bytes.Buffer
	res.WriteString("icns")
	_ = binary.Write(&res, binary.BigEndian, uint32(8+body.Len()))
	res.Write(body.Bytes())
	return res.Bytes()
}

func drawIcon(n int) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	s := float64(n) / 1024
	// квадрат 824×824 с отступом 100 и радиусом 185, как у значков macOS
	x0, y0, w, r := 100*s, 100*s, 824*s, 185*s
	// стрелки в координатах значка 24×24 из интерфейса: M7 7h11l-3-3 M17 17H6l3 3
	segs := [][4]float64{{7, 7, 18, 7}, {18, 7, 15, 4}, {17, 17, 6, 17}, {6, 17, 9, 20}}
	scale := w / 24
	lw := 2.2 * scale / 2
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			px, py := float64(x)+.5, float64(y)+.5
			a := roundRectCover(px, py, x0, y0, w, w, r)
			if a <= 0 {
				continue
			}
			t := (py - y0) / w
			col := mix(color.NRGBA{0x3d, 0x9b, 0xff, 255}, color.NRGBA{0x00, 0x62, 0xe6, 255}, t)
			d := math.Inf(1)
			for _, sg := range segs {
				d = math.Min(d, segDist(px, py, x0+sg[0]*scale, y0+sg[1]*scale, x0+sg[2]*scale, y0+sg[3]*scale))
			}
			if wa := clamp(lw-d+.5, 0, 1); wa > 0 {
				col = mix(col, color.NRGBA{255, 255, 255, 255}, wa)
			}
			col.A = uint8(255 * a)
			img.SetNRGBA(x, y, col)
		}
	}
	return img
}

func roundRectCover(px, py, x, y, w, h, r float64) float64 {
	cx := math.Max(x+r, math.Min(px, x+w-r))
	cy := math.Max(y+r, math.Min(py, y+h-r))
	d := math.Hypot(px-cx, py-cy) - r
	return clamp(.5-d, 0, 1)
}

func segDist(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := clamp(((px-ax)*dx+(py-ay)*dy)/(dx*dx+dy*dy), 0, 1)
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

func mix(a, b color.NRGBA, t float64) color.NRGBA {
	t = clamp(t, 0, 1)
	f := func(x, y uint8) uint8 { return uint8(float64(x)*(1-t) + float64(y)*t + .5) }
	return color.NRGBA{f(a.R, b.R), f(a.G, b.G), f(a.B, b.B), 255}
}

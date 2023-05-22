package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"

	"github.com/google/hilbert"
	"github.com/mazznoer/colorgrad"
)

var MAX int
var PNG *[]byte
var PNGS [256]*[]byte

const DIM = 1024
const SLASH8 = 64
const PREFIXES = 1048576

func main() {
	addr := os.Args[1]
	lb := os.Args[2]

	grad1 := colorgrad.Reds()
	grad2 := colorgrad.Plasma()

	var old [PREFIXES]uint64

	go func() {
		for {
			var new [PREFIXES]uint64
			var cur [PREFIXES]uint64

			resp, err := http.Get(lb)

			if err == nil {
				defer resp.Body.Close()

				b, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Fatal(err)
				}

				err = json.Unmarshal(b, &new)
				if err != nil {
					log.Fatal(err)
				}

				var max uint64 = 1

				for i, _ := range cur {
					v := new[i] - old[i]

					if v > max {
						max = v
						MAX = i >> 12
					}

					cur[i] = v
				}

				fmt.Println(max)
				PNG = render(cur, max, grad1)

				now := time.Now()
				for n := 0; n < 256; n++ {
					PNGS[n] = render2(uint8(n), cur, max, grad2)
				}
				log.Println(time.Now().Sub(now))

				copy(old[:], new[:])

			}

			time.Sleep(55 * time.Second)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="60">
    <title>Hello, World!</title>
  </head>
  <body style="background-color:black;color:white;">
    <table>
    <tr>
      <td style="vertical-align: top;"><img src="data:image/png;base64,%s"></td>
      <td style="vertical-align: top;"><img src="data:image/png;base64,%s">
      <div>⚠️Enlarged tile may be rotated compared to map⚠️</div>
      </td>
  </body>
</html>
`
		n := MAX

		fmt.Println(r.URL.Path)

		if len(r.URL.Path) > 1 {
			n, _ = strconv.Atoi(r.URL.Path[1:])
		}

		png := PNGS[n]

		if PNG != nil && png != nil {
			b641 := base64.StdEncoding.EncodeToString(*PNG)
			b642 := base64.StdEncoding.EncodeToString(*png)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(html, b641, b642)))
		}
	})

	http.ListenAndServe(addr, nil)
}

func render(cur [PREFIXES]uint64, max uint64, grad colorgrad.Gradient) *[]byte {

	upLeft := image.Point{0, 0}
	lowRight := image.Point{DIM, DIM}

	img := image.NewRGBA(image.Rectangle{upLeft, lowRight})

	s, _ := hilbert.NewHilbert(DIM)

	for k, _ := range cur {
		x, y, _ := s.Map(k)
		c := ALLOC[uint8(k>>12)]

		r := uint8((c >> 16) & 0xff)
		g := uint8((c >> 8) & 0xff)
		b := uint8(c & 0xff)

		img.SetRGBA(x, y, color.RGBA{r, g, b, 64})
	}

	s, _ = hilbert.NewHilbert(16)

	for n := 0; n < 256; n++ {
		x, y, _ := s.Map(n)

		col := color.RGBA{200, 100, 0, 200}
		point := fixed.Point26_6{fixed.I((x * SLASH8) + 4), fixed.I((y * SLASH8) + 12)}

		d := &font.Drawer{
			Dst:  img,
			Src:  image.NewUniform(col),
			Face: basicfont.Face7x13,
			Dot:  point,
		}

		label := fmt.Sprint(n)

		switch ALLOC[uint8(n)] {
		case IANA:
			label += " IANA"
		case MULTICAST:
			label += " MCST"
		case RESERVED:
			label += " RSVD"
		case LOOPBACK:
			label += " LPBK"

		case RIPE:
			label += " RIPE"
		case ARIN:
			label += " ARIN"
		case APNIC:
			label += " APNI"
		case LACNIC:
			label += " LACN"
		case AFRINIC:
			label += " AFRI"

		case DAIMLER:
			label += " DAIM"
		case FORD:
			label += " FORD"
		case APPLE:
			label += " APPL"
		case PRUDENTIAL:
			label += " PRUD"
		case PSINET:
			label += " PSIN"
		case ATT:
			label += " AT&T"

		case DDNRVN:
			fallthrough
		case DISA:
			fallthrough
		case AISC:
			fallthrough
		case DOD:
			fallthrough
		case DSINORTH:
			fallthrough
		case DLASAC:
			fallthrough
		case DODNIC:
			fallthrough
		case USDOD:
			label += " ARMY"
		}

		d.DrawString(label)
	}

	s, _ = hilbert.NewHilbert(DIM)

	for k, v := range cur {
		x, y, _ := s.Map(k)

		var f float64

		if max != 0 {
			f = float64(v) / float64(max)
		} else {
			f = 0
		}

		if v != 0 {
			col := grad.At(f)
			img.Set(x, y, col)
		}

	}

	var buff bytes.Buffer

	png.Encode(&buff, img)
	b, _ := ioutil.ReadAll(&buff)

	return &b
}

func render2(slash8 uint8, cur [PREFIXES]uint64, max uint64, grad colorgrad.Gradient) *[]byte {

	upLeft := image.Point{0, 0}
	lowRight := image.Point{8 * 64, 8*64 + 50}

	img := image.NewRGBA(image.Rectangle{upLeft, lowRight})

	s, _ := hilbert.NewHilbert(64)
	var slice [4096]uint64

	copy(slice[:], cur[(int(slash8)<<12):])

	for k, v := range slice {
		x, y, _ := s.Map(k)

		var f float64

		if max != 0 {
			f = float64(v) / float64(max)
		} else {
			f = 0
		}

		if v != 0 {
			col := grad.At(f)

			for i := 0; i < 8; i++ {
				for j := 0; j < 8; j++ {
					img.Set((x*8)+i, (y*8)+j, col)
				}
			}
		}
	}

	for x := 0; x < 8*64; x++ {
		f := float64(x) / 512.0
		col := grad.At(f)
		for y := 0; y < 50; y++ {
			img.Set(x, 512+y, col)
		}
	}

	for n := 0; n < 8*64; n++ {
		img.SetRGBA(0, n, color.RGBA{100, 100, 100, 128})
		img.SetRGBA(511, n, color.RGBA{100, 100, 100, 128})
	}

	for n := 0; n < 8*64; n++ {
		img.SetRGBA(n, 0, color.RGBA{100, 100, 100, 128})
		img.SetRGBA(n, 511, color.RGBA{100, 100, 100, 128})
	}

	col := color.RGBA{0, 0, 0, 255}
	point := fixed.Point26_6{fixed.I(300), fixed.I(540)}

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(col),
		Face: basicfont.Face7x13,
		Dot:  point,
	}

	d.DrawString(fmt.Sprintf("%d.0.0.0/8, Max: %d pps", slash8, max/50))

	var buff bytes.Buffer

	png.Encode(&buff, img)
	b, _ := ioutil.ReadAll(&buff)

	return &b
}

const IANA = 0x000000
const ARIN = 0x00ffff
const RIPE = 0xffffff
const APNIC = 0xff0000
const AFRINIC = 0x00ff00
const LACNIC = 0x0000ff
const LOOPBACK = 0xffff00
const APPLE = 0xff00ff
const DISA = 0xc0c0c0
const AISC = 0x808080
const DOD = 0x800000
const ATT = 0x808000
const FORD = 0x008000
const DDNRVN = 0x800080
const DSINORTH = 0x008080
const DLASAC = 0x000080
const PSINET = 0xb8860b
const PRUDENTIAL = 0x3cb371
const DAIMLER = 0x5f9ea0
const DODNIC = 0x9370DB
const USDOD = 0xcd853f
const MULTICAST = 0xff6347
const RESERVED = 0xa52a2a

// https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
var ALLOC = map[uint8]uint32{
	0:   IANA,
	1:   APNIC,
	2:   RIPE,
	3:   ARIN,
	4:   ARIN,
	5:   RIPE,
	6:   AISC,
	7:   ARIN,
	8:   ARIN,
	9:   ARIN,
	10:  IANA,
	11:  DOD,
	12:  ATT,
	13:  ARIN,
	14:  APNIC,
	15:  ARIN,
	16:  ARIN,
	17:  APPLE,
	18:  ARIN,
	19:  FORD,
	20:  ARIN,
	21:  DDNRVN,
	22:  DISA,
	23:  ARIN,
	24:  ARIN,
	25:  RIPE,
	26:  DISA,
	27:  APNIC,
	28:  DSINORTH,
	29:  DISA,
	30:  DISA,
	31:  RIPE,
	32:  ARIN,
	33:  DLASAC,
	34:  ARIN,
	35:  ARIN,
	36:  APNIC,
	37:  RIPE,
	38:  PSINET,
	39:  APNIC,
	40:  ARIN,
	41:  AFRINIC,
	42:  APNIC,
	43:  APNIC,
	44:  ARIN,
	45:  ARIN,
	46:  RIPE,
	47:  ARIN,
	48:  PRUDENTIAL,
	49:  APNIC,
	50:  ARIN,
	51:  RIPE,
	52:  ARIN,
	53:  DAIMLER,
	54:  ARIN,
	55:  DODNIC,
	56:  ARIN,
	57:  RIPE,
	58:  APNIC,
	59:  APNIC,
	60:  APNIC,
	61:  APNIC,
	62:  RIPE,
	63:  ARIN,
	64:  ARIN,
	65:  ARIN,
	66:  ARIN,
	67:  ARIN,
	68:  ARIN,
	69:  ARIN,
	70:  ARIN,
	71:  ARIN,
	72:  ARIN,
	73:  ARIN,
	74:  ARIN,
	75:  ARIN,
	76:  ARIN,
	77:  RIPE,
	78:  RIPE,
	79:  RIPE,
	80:  RIPE,
	81:  RIPE,
	82:  RIPE,
	83:  RIPE,
	84:  RIPE,
	85:  RIPE,
	86:  RIPE,
	87:  RIPE,
	88:  RIPE,
	89:  RIPE,
	90:  RIPE,
	91:  RIPE,
	92:  RIPE,
	93:  RIPE,
	94:  RIPE,
	95:  RIPE,
	96:  ARIN,
	97:  ARIN,
	98:  ARIN,
	99:  ARIN,
	100: ARIN,
	101: APNIC,
	102: AFRINIC,
	103: APNIC,
	104: ARIN,
	105: AFRINIC,
	106: APNIC,
	107: ARIN,
	108: ARIN,
	109: RIPE,
	110: APNIC,
	111: APNIC,
	112: APNIC,
	113: APNIC,
	114: APNIC,
	115: APNIC,
	116: APNIC,
	117: APNIC,
	118: APNIC,
	119: APNIC,
	120: APNIC,
	121: APNIC,
	122: APNIC,
	123: APNIC,
	124: APNIC,
	125: APNIC,
	126: APNIC,
	127: LOOPBACK,
	128: ARIN,
	129: ARIN,
	130: ARIN,
	131: ARIN,
	132: ARIN,
	133: APNIC,
	134: ARIN,
	135: ARIN,
	136: ARIN,
	137: ARIN,
	138: ARIN,
	139: ARIN,
	140: ARIN,
	141: RIPE,
	142: ARIN,
	143: ARIN,
	144: ARIN,
	145: RIPE,
	146: ARIN,
	147: ARIN,
	148: ARIN,
	149: ARIN,
	150: APNIC,
	151: RIPE,
	152: ARIN,
	153: APNIC,
	154: AFRINIC,
	155: ARIN,
	156: ARIN,
	157: ARIN,
	158: ARIN,
	159: ARIN,
	160: ARIN,
	161: ARIN,
	162: ARIN,
	163: APNIC,
	164: ARIN,
	165: ARIN,
	166: ARIN,
	167: ARIN,
	168: ARIN,
	169: ARIN,
	170: ARIN,
	171: APNIC,
	172: ARIN,
	173: ARIN,
	174: ARIN,
	175: APNIC,
	176: RIPE,
	177: LACNIC,
	178: RIPE,
	179: LACNIC,
	180: APNIC,
	181: LACNIC,
	182: APNIC,
	183: APNIC,
	184: ARIN,
	185: RIPE,
	186: LACNIC,
	187: LACNIC,
	188: RIPE,
	189: LACNIC,
	190: LACNIC,
	191: LACNIC,
	192: ARIN,
	193: RIPE,
	194: RIPE,
	195: RIPE,
	196: AFRINIC,
	197: AFRINIC,
	198: ARIN,
	199: ARIN,
	200: LACNIC,
	201: LACNIC,
	202: APNIC,
	203: APNIC,
	204: ARIN,
	205: ARIN,
	206: ARIN,
	207: ARIN,
	208: ARIN,
	209: ARIN,
	210: APNIC,
	211: APNIC,
	212: RIPE,
	213: RIPE,
	214: USDOD,
	215: USDOD,
	216: ARIN,
	217: RIPE,
	218: APNIC,
	219: APNIC,
	220: APNIC,
	221: APNIC,
	222: APNIC,
	223: APNIC,
	224: MULTICAST,
	225: MULTICAST,
	226: MULTICAST,
	227: MULTICAST,
	228: MULTICAST,
	229: MULTICAST,
	230: MULTICAST,
	231: MULTICAST,
	232: MULTICAST,
	233: MULTICAST,
	234: MULTICAST,
	235: MULTICAST,
	236: MULTICAST,
	237: MULTICAST,
	238: MULTICAST,
	239: MULTICAST,
	240: RESERVED,
	241: RESERVED,
	242: RESERVED,
	243: RESERVED,
	244: RESERVED,
	245: RESERVED,
	246: RESERVED,
	247: RESERVED,
	248: RESERVED,
	249: RESERVED,
	250: RESERVED,
	251: RESERVED,
	252: RESERVED,
	253: RESERVED,
	254: RESERVED,
	255: RESERVED,
}

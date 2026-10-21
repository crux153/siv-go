package difffuzz

import (
	"bytes"
	"crypto/aes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	siv "github.com/crux153/siv-go"
	"github.com/ericlagergren/polyval"
)

// TestWrapHunt searches for inputs whose 32-bit CTR counter wraps
// inside the message and runs every fork path on them. Random inputs
// wrap with probability nblocks/2^32 (2^-16 for 1 MiB), so plain
// fuzzing almost never reaches the wrap. The hunter predicts the tag
// cheaply: POLYVAL is linear, so changing the last plaintext block by
// D changes the POLYVAL sum by D·H^2 (the length block follows it).
// Each candidate costs two field multiplications and one AES block.
//
// Enabled by WRAPHUNT=<duration>; WRAPHUNT_WORKERS sets the goroutine
// count (default GOMAXPROCS); progress goes to WRAPHUNT_LOG every
// minute.
func TestWrapHunt(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("WRAPHUNT"))
	if err != nil {
		t.Skip("set WRAPHUNT=<duration> to run")
	}
	workers := runtime.GOMAXPROCS(0)
	if w, err := strconv.Atoi(os.Getenv("WRAPHUNT_WORKERS")); err == nil && w > 0 {
		workers = w
	}
	logPath := os.Getenv("WRAPHUNT_LOG")
	if logPath == "" {
		logPath = "wraphunt.progress"
	}

	var st huntStats
	deadline := time.Now().Add(d)
	start := time.Now()
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var seed [32]byte
			cryptorand.Read(seed[:])
			seed[0] ^= byte(w)
			r := rand.New(rand.NewChaCha8(seed))
			for time.Now().Before(deadline) {
				if err := huntOnce(r, &st); err != nil {
					st.failures.Add(1)
					fmt.Fprintf(os.Stderr, "WRAPHUNT FAILURE: %v\n", err)
					t.Error(err)
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				st.write(logPath, time.Since(start))
			case <-done:
				return
			}
		}
	}()
	wg.Wait()
	close(done)
	st.write(logPath, time.Since(start))
}

type huntStats struct {
	bases, candidates, wraps, segWraps, failures, predictMiss atomic.Int64
	lane                                                      [8]atomic.Int64 // wrap block index mod 8
}

func (s *huntStats) write(path string, el time.Duration) {
	var lanes [8]int64
	for i := range lanes {
		lanes[i] = s.lane[i].Load()
	}
	line := fmt.Sprintf("%s elapsed=%s bases=%d candidates=%d wraps=%d segment_wraps=%d failures=%d predict_miss=%d wrap_lane_mod8=%v\n",
		time.Now().Format(time.RFC3339), el.Truncate(time.Second), s.bases.Load(), s.candidates.Load(),
		s.wraps.Load(), s.segWraps.Load(), s.failures.Load(), s.predictMiss.Load(), lanes)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		f.WriteString(line)
		f.Close()
	}
}

func huntOnce(r *rand.Rand, st *huntStats) error {
	keyLen := 32
	if r.IntN(10) == 0 {
		keyLen = 16
	}
	key := make([]byte, keyLen)
	nonce := make([]byte, siv.NonceSize)
	fillRand(r, key)
	fillRand(r, nonce)

	// Length: mostly whole 1 MiB segments, else 256-byte multiples
	// from 64 KiB, occasionally 16-byte multiples (NewGCM only).
	var n int
	switch x := r.IntN(10); {
	case x < 7:
		n = siv.MaxSegmentSize
	case x < 9:
		n = (siv.MinSegmentSize/siv.SegmentQuantum + r.IntN((siv.MaxSegmentSize-siv.MinSegmentSize)/siv.SegmentQuantum+1)) * siv.SegmentQuantum
	default:
		n = (siv.MinSegmentSize + r.IntN(siv.MaxSegmentSize-siv.MinSegmentSize)) &^ 15
	}
	aadLen := aadSegment
	if r.IntN(8) == 0 {
		aadLen = r.IntN(97)
	}
	pt := make([]byte, n)
	aad := make([]byte, aadLen)
	fillRand(r, pt)
	fillRand(r, aad)

	// RFC 8452 §4 key derivation.
	kgk, _ := aes.NewCipher(key)
	derive := func(j uint32) []byte {
		var in, out [16]byte
		binary.LittleEndian.PutUint32(in[:4], j)
		copy(in[4:], nonce)
		kgk.Encrypt(out[:], in[:])
		return out[:8]
	}
	authKey := append(derive(0), derive(1)...)
	encKey := append(derive(2), derive(3)...)
	if keyLen == 32 {
		encKey = append(append(encKey, derive(4)...), derive(5)...)
	}
	enc, _ := aes.NewCipher(encKey)

	// POLYVAL sum over pad(aad) || pt || lengths.
	pv, err := polyval.New(authKey)
	if err != nil {
		return nil // all-zero H (2^-128); skip
	}
	padded := make([]byte, (aadLen+15)&^15)
	copy(padded, aad)
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[:8], uint64(aadLen)*8)
	binary.LittleEndian.PutUint64(lens[8:], uint64(n)*8)
	pv.Update(padded)
	pv.Update(pt)
	pv.Update(lens[:])
	base := pv.Sum(nil)
	st.bases.Add(1)

	nb := uint64(n / 16)
	limit := uint64(1<<32) - nb // wrap iff ctr > limit
	var delta, dh2, s, tag [16]byte
	var probe [32]byte
	for tries := uint64(0); tries < 64*(1<<32)/nb; tries++ {
		fillRand(r, delta[:])
		copy(probe[:16], delta[:]) // probe = delta || 0, so POLYVAL = delta·H^2
		pv.Reset()
		pv.Update(probe[:])
		pv.Sum(dh2[:0])
		for i := range s {
			s[i] = base[i] ^ dh2[i]
		}
		for i := range nonce {
			s[i] ^= nonce[i]
		}
		s[15] &= 0x7f
		enc.Encrypt(tag[:], s[:])
		ctr := uint64(binary.LittleEndian.Uint32(tag[:4]))
		if ctr <= limit {
			continue
		}
		st.candidates.Add(int64(tries + 1))
		st.wraps.Add(1)
		wrapAt := int((uint64(1<<32) - ctr) * 16) // byte offset of the first wrapped block
		st.lane[(wrapAt/16)%8].Add(1)

		last := pt[n-16:]
		for i := range last {
			last[i] ^= delta[i]
		}
		want := refSeal(key, nonce, pt, aad)
		if !bytes.Equal(want[n:], tag[:]) {
			st.predictMiss.Add(1)
			return nil // hunter bug, not a fork bug; counted
		}
		if err := checkAEAD(key, nonce, pt, aad, wrapAt+r.IntN(n-wrapAt), uint(r.IntN(8))); err != nil {
			record("wrap-aead", map[string][]byte{"key": key, "nonce": nonce, "aad": aad, "pt": pt}, err.Error())
			return fmt.Errorf("wrap at byte %d: %w", wrapAt, err)
		}
		if n%siv.SegmentQuantum == 0 && aadLen == aadSegment {
			st.segWraps.Add(1)
			// One tiling with a tile boundary right at the wrap, one random.
			cut := wrapAt &^ (siv.SegmentQuantum - 1)
			var tilesA []int
			if cut > 0 && cut < n {
				tilesA = []int{cut, n - cut}
			} else {
				tilesA = []int{n}
			}
			tb := make([]byte, 8)
			fillRand(r, tb)
			tilesK := tiling(n, tb)
			if err := checkSegment(key, nonce, pt, aad, segSizeFor(n), tilesA, tilesK, wrapAt+r.IntN(n-wrapAt), r.IntN(n+16)); err != nil {
				record("wrap-segment", map[string][]byte{"key": key, "nonce": nonce, "aad": aad, "pt": pt}, err.Error())
				return fmt.Errorf("wrap at byte %d: %w", wrapAt, err)
			}
			if err := checkSegment(key, nonce, pt, aad, segSizeFor(n), tilesK, tilesA, -1, wrapAt); err != nil {
				record("wrap-segment", map[string][]byte{"key": key, "nonce": nonce, "aad": aad, "pt": pt}, err.Error())
				return fmt.Errorf("wrap at byte %d (swapped tilings): %w", wrapAt, err)
			}
		}
		return nil
	}
	st.candidates.Add(int64(64 * (1 << 32) / nb))
	return nil
}

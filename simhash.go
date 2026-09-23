package main

import (
	"hash/fnv"
	"math"
	"math/bits"
	"regexp"
	"strings"
)

// Tokens: words + whole HTML tags, so both text and page structure feed the hash.
// Unicode letters and digits (\p{L}, \p{N}) are included so non-Latin bodies — Turkish,
// Chinese, Arabic, Cyrillic, etc. — actually produce textual tokens instead of collapsing
// to only ASCII scaffolding, which would make localized real pages indistinguishable from
// their same-envelope soft-404s.
var tokenRe = regexp.MustCompile(`[\p{L}\p{N}_]+|<[^>]+>`)

func tokenize(body string) []string {
	return tokenRe.FindAllString(strings.ToLower(body), -1)
}

// SimHash is a 64-bit locality-sensitive hash over token frequencies. Two documents that
// share most tokens land at a small Hamming distance even when a few tokens differ — which
// is exactly a soft-404 template whose only variation is a reflected path or a random filler.
func SimHash(body string) uint64 {
	toks := tokenize(body)
	if len(toks) == 0 {
		return 0
	}
	freq := map[string]int{}
	for _, t := range toks {
		freq[t]++
	}
	var v [64]float64
	for t, f := range freq {
		// Log-dampened weight: template tokens decide the hash; a bulky repeated block
		// (ads, a long list, reflected filler) can't dominate it. freq 1→1, 8→3.1, 40→4.7.
		w := 1 + math.Log(float64(f))
		h := fnv.New64a()
		h.Write([]byte(t))
		hv := h.Sum64()
		for i := 0; i < 64; i++ {
			if hv&(1<<uint(i)) != 0 {
				v[i] += w
			} else {
				v[i] -= w
			}
		}
	}
	var sh uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			sh |= 1 << uint(i)
		}
	}
	return sh
}

// Hamming is the number of differing bits — the similarity distance between two SimHashes.
func Hamming(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle returns the page <title>, whitespace-collapsed and lowercased — a cheap,
// stable discriminator: a real page usually titles itself differently from the 404 page.
func extractTitle(body string) string {
	m := reTitle.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.ToLower(strings.Join(strings.Fields(m[1]), " "))
}

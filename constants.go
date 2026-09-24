package main

// Central tuning knobs for lucid. Every magic number that a maintainer might want to change
// lives here so a code reader doesn't have to hunt across files. Constants stay next to
// their unit (bytes / seconds / probability / count) so a wrong-order edit fails to compile.
//
// Values that a USER should be able to change are exposed as -flags in main.go and shadowed
// on Config; the constants below are the SITE-invariant defaults lucid ships with — changing
// them changes the tool's behavior, not one operator's run.
//
// If a constant is genuinely local to one function (e.g. a 200-byte body preview inside a
// single formatter), it stays where it's used. Only cross-file tuning lands here.

const (
	// --- Fetch / SimHash / cleanup ---

	// fetchErrThreshold flips cfg.Truncated=true when this fraction of verify-fetches
	// returned r.Err. Picks up systemic breakage (WAF flipped on, upstream down) while
	// tolerating incidental timeouts on a long tail. Any single directory that errors on
	// ALL of its candidates ALSO flips Truncated regardless of the global rate.
	fetchErrThreshold = 0.20

	// harBodyCap is the per-response body cap in HAR entries — 64 KiB is Burp's practical
	// import ceiling. Bodies past this are truncated by the scanner and flagged via
	// harRespExtra.Truncated so a report reader knows they only got a preview.
	harBodyCap = 64 * 1024

	// simhashDynamicSpread is the intra-baseline Hamming spread above which calibrate()
	// flips Profile.Dynamic=true — a value >6 across the calibration probes means the
	// not-found page is variable (nonces, timestamps, random ads), and judge() needs a
	// wider threshold to avoid false hits.
	simhashDynamicSpread = 6

	// simhashThresholdMargin is added to the observed intra-baseline spread when the user
	// hasn't set -threshold. It's the "give the not-found envelope some room" fudge that
	// prevents legitimate variance from bleeding into VHit.
	simhashThresholdMargin = 4
)

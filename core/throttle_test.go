package core

// KSM-881 — unit tests for the throttle backoff helpers. These live in package core (white-box)
// so they can pin the throttleJitter seam and call the unexported helpers directly.

import (
	"testing"
	"time"
)

func TestThrottleDelayExponentialSequence(t *testing.T) {
	orig := throttleJitter
	throttleJitter = func() float64 { return 0 }
	defer func() { throttleJitter = orig }()

	want := []time.Duration{
		11 * time.Second, 22 * time.Second, 44 * time.Second, 88 * time.Second, 176 * time.Second,
	}
	for attempt, w := range want {
		if got := throttleDelay(attempt, 0); got != w {
			t.Errorf("throttleDelay(%d, 0) = %v, want %v", attempt, got, w)
		}
	}
}

func TestThrottleDelayRetryAfterPrecedence(t *testing.T) {
	orig := throttleJitter
	throttleJitter = func() float64 { return 0 }
	defer func() { throttleJitter = orig }()

	// A positive retry_after (7s) wins over the exponential value for attempt 3 (88s).
	if got := throttleDelay(3, 7); got != 7*time.Second {
		t.Errorf("throttleDelay(3, 7) = %v, want 7s", got)
	}
}

func TestThrottleDelayJitterBounds(t *testing.T) {
	orig := throttleJitter
	defer func() { throttleJitter = orig }()

	throttleJitter = func() float64 { return 0.25 }
	if got, want := throttleDelay(0, 0), time.Duration(13.75*float64(time.Second)); got != want {
		t.Errorf("upper-bound delay = %v, want %v", got, want)
	}
	throttleJitter = func() float64 { return -0.25 }
	if got, want := throttleDelay(0, 0), time.Duration(8.25*float64(time.Second)); got != want {
		t.Errorf("lower-bound delay = %v, want %v", got, want)
	}
}

func TestThrottleDelayJitterWithinRangeRealRandom(t *testing.T) {
	base := float64(44 * time.Second) // attempt 2 -> 44s
	for i := 0; i < 1000; i++ {
		d := float64(throttleDelay(2, 0))
		if d < base*0.75 || d > base*1.25 {
			t.Fatalf("delay %v outside [%v, %v]", time.Duration(d), time.Duration(base*0.75), time.Duration(base*1.25))
		}
	}
}

func TestParseThrottle(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantThrottled bool
		wantRetry     float64
	}{
		{"throttled no retry_after", `{"error":"throttled"}`, true, 0},
		{"throttled with retry_after", `{"error":"throttled","retry_after":5}`, true, 5},
		{"result_code key", `{"result_code":"throttled"}`, true, 0},
		{"other error", `{"error":"access_denied"}`, false, 0},
		{"non-json body", `Bad Gateway`, false, 0},
		{"empty body", ``, false, 0},
		{"non-numeric retry_after", `{"error":"throttled","retry_after":"soon"}`, true, 0},
		{"negative retry_after", `{"error":"throttled","retry_after":-3}`, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotRetry, gotThrottled := parseThrottle([]byte(tc.body))
			if gotThrottled != tc.wantThrottled || gotRetry != tc.wantRetry {
				t.Errorf("parseThrottle(%q) = (%v, %v), want (%v, %v)",
					tc.body, gotRetry, gotThrottled, tc.wantRetry, tc.wantThrottled)
			}
		})
	}
}

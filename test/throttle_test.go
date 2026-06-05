package test

// KSM-881 — end-to-end tests for throttle retry, driving the real PostQuery loop through the
// public GetSecrets API. Backoff never actually waits: the shared test Context's Sleep seam is
// installed as a recorder via captureThrottleSleeps (reset by the deferred ResetMockResponseQueue).

import (
	"errors"
	"testing"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func newThrottleSM() *ksm.SecretsManager {
	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	return ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)
}

func throttledResponse(retryAfter string) *MockResponse {
	body := `{"error":"throttled","message":"throttled"`
	if retryAfter != "" {
		body += `,"retry_after":` + retryAfter
	}
	body += `}`
	return NewMockResponse([]byte(body), 403, nil)
}

func recordResponse() *MockResponse {
	res := NewMockResponse([]byte{}, 200, nil)
	r := res.AddRecord("My Record", "login", "", nil, nil)
	r.Field("login", "", "", "", "My Login")
	r.Field("password", "", "", "", "My Password")
	return res
}

// captureThrottleSleeps installs a recorder on the shared test Context's Sleep seam so the backoff
// never actually sleeps; the returned pointer collects the requested delays in order.
func captureThrottleSleeps() *[]time.Duration {
	delays := &[]time.Duration{}
	(*Ctx).Sleep = func(d time.Duration) { *delays = append(*delays, d) }
	return delays
}

func TestThrottleRetryThenSuccess(t *testing.T) {
	defer ResetMockResponseQueue()
	sm := newThrottleSM()
	delays := captureThrottleSleeps()

	MockResponseQueue.AddMockResponse(throttledResponse(""))
	MockResponseQueue.AddMockResponse(recordResponse())

	records, err := sm.GetSecrets(nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("want 1 record, got %d (err %v)", len(records), err)
	}
	if len(*delays) != 1 {
		t.Errorf("want 1 sleep, got %d", len(*delays))
	}
}

func TestThrottleMultipleThenSuccess(t *testing.T) {
	defer ResetMockResponseQueue()
	sm := newThrottleSM()
	delays := captureThrottleSleeps()

	MockResponseQueue.AddMockResponse(throttledResponse(""))
	MockResponseQueue.AddMockResponse(throttledResponse(""))
	MockResponseQueue.AddMockResponse(recordResponse())

	records, err := sm.GetSecrets(nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("want 1 record, got %d (err %v)", len(records), err)
	}
	if len(*delays) != 2 {
		t.Fatalf("want 2 sleeps, got %d", len(*delays))
	}
	// Jitter is real here; assert each delay within +/-25% of the exponential base (11s, 22s).
	for i, base := range []time.Duration{11 * time.Second, 22 * time.Second} {
		d := (*delays)[i]
		if d < time.Duration(float64(base)*0.75) || d > time.Duration(float64(base)*1.25) {
			t.Errorf("delay[%d] = %v, outside +/-25%% of %v", i, d, base)
		}
	}
}

func TestThrottleExhaustionReturnsErrThrottled(t *testing.T) {
	defer ResetMockResponseQueue()
	sm := newThrottleSM()
	delays := captureThrottleSleeps()

	for i := 0; i < 6; i++ { // maxThrottleRetries (5) + 1
		MockResponseQueue.AddMockResponse(throttledResponse(""))
	}

	_, err := sm.GetSecrets(nil)
	if !errors.Is(err, ksm.ErrThrottled) {
		t.Fatalf("want errors.Is(err, ErrThrottled), got %v", err)
	}
	if len(*delays) != 5 { // capped at maxThrottleRetries
		t.Errorf("want 5 sleeps, got %d", len(*delays))
	}
}

func TestThrottleRetryAfterHonored(t *testing.T) {
	defer ResetMockResponseQueue()
	sm := newThrottleSM()
	delays := captureThrottleSleeps()

	MockResponseQueue.AddMockResponse(throttledResponse("2")) // retry_after: 2 (seconds)
	MockResponseQueue.AddMockResponse(recordResponse())

	records, err := sm.GetSecrets(nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("want 1 record, got %d (err %v)", len(records), err)
	}
	if len(*delays) != 1 {
		t.Fatalf("want 1 sleep, got %d", len(*delays))
	}
	// retry_after = 2s, with +/-25% jitter.
	if d := (*delays)[0]; d < time.Duration(1.5*float64(time.Second)) || d > time.Duration(2.5*float64(time.Second)) {
		t.Errorf("retry_after delay = %v, want ~2s +/-25%%", d)
	}
}

func TestThrottleThenKeyRotationCompose(t *testing.T) {
	defer ResetMockResponseQueue()
	sm := newThrottleSM()
	delays := captureThrottleSleeps()

	MockResponseQueue.AddMockResponse(throttledResponse(""))
	MockResponseQueue.AddMockResponse(NewMockResponse([]byte(`{"error":"key","key_id":"8"}`), 403, nil))
	MockResponseQueue.AddMockResponse(recordResponse())

	records, err := sm.GetSecrets(nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("want 1 record, got %d (err %v)", len(records), err)
	}
	if sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) != "8" {
		t.Error("key rotation did not apply")
	}
	if len(*delays) != 1 { // only the throttle slept; key rotation does not consume throttle budget
		t.Errorf("want 1 sleep, got %d", len(*delays))
	}
}

func TestThrottleNonThrottleErrorNotRetried(t *testing.T) {
	defer ResetMockResponseQueue()
	sm := newThrottleSM()
	delays := captureThrottleSleeps()

	MockResponseQueue.AddMockResponse(NewMockResponse([]byte(`{"error":"access_denied","message":"nope"}`), 403, nil))

	_, err := sm.GetSecrets(nil)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if errors.Is(err, ksm.ErrThrottled) {
		t.Error("non-throttle error should not be ErrThrottled")
	}
	if len(*delays) != 0 {
		t.Errorf("want 0 sleeps, got %d", len(*delays))
	}
}

func TestThrottleNonJSONNotRetried(t *testing.T) {
	defer ResetMockResponseQueue()
	sm := newThrottleSM()
	delays := captureThrottleSleeps()

	MockResponseQueue.AddMockResponse(NewMockResponse([]byte("Bad Gateway"), 502, nil))

	_, err := sm.GetSecrets(nil)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if len(*delays) != 0 {
		t.Errorf("want 0 sleeps, got %d", len(*delays))
	}
}

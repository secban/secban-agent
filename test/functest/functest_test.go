package functest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"gitlab.com/thequietbot/secban/secban-agent/ban/dummy"
	"gitlab.com/thequietbot/secban/secban-agent/dispatcher"
	"gitlab.com/thequietbot/secban/secban-agent/ip"
	"gitlab.com/thequietbot/secban/secban-agent/offender"
	"gitlab.com/thequietbot/secban/secban-agent/router"
)

var testServer *httptest.Server

func TestMain(m *testing.M) {
	ipErr := ip.Init("", true, true)
	if ipErr != nil {
		panic(ipErr)
	}

	rules := []dispatcher.RuleConfig{
		{
			Name:       "ssh",
			Count:      3,
			Timeout:    "10m",
			TTL:        "1h",
			MaxEntries: 50,
		},
		{
			Name:       "http",
			Count:      1,
			Timeout:    "5m",
			TTL:        "30m",
			MaxEntries: 50,
		},
	}

	actor := dummy.New()

	dispatcherErr := dispatcher.Init(context.Background(), rules, actor, false)
	if dispatcherErr != nil {
		panic(dispatcherErr)
	}

	testServer = httptest.NewServer(router.NewRouter())

	exitCode := m.Run()

	testServer.Close()

	os.Exit(exitCode)
}

func httpGet(ctx context.Context, targetURL string) (*http.Response, error) {
	req, newReqErr := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if newReqErr != nil {
		return nil, newReqErr
	}

	return http.DefaultClient.Do(req)
}

func TestFunctionalPing(t *testing.T) {
	t.Parallel()

	resp, getErr := httpGet(context.Background(), testServer.URL+"/ping")
	if getErr != nil {
		t.Fatalf("ping request failed: %v", getErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", resp.StatusCode)
	}

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}

	if !strings.Contains(string(body), "pong") {
		t.Fatalf("expected pong in body, got: %s", string(body))
	}
}

func TestFunctionalReportAndStatus(t *testing.T) {
	t.Parallel()

	targetIP := "192.0.2.10"

	reportURL := testServer.URL + "/report/" + targetIP + "/ssh?message=auth_failed"

	resp, reportErr := httpGet(context.Background(), reportURL)
	if reportErr != nil {
		t.Fatalf("report request failed: %v", reportErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got: %d", resp.StatusCode)
	}

	statusURL := testServer.URL + "/status/" + targetIP

	statusResp, statusErr := httpGet(context.Background(), statusURL)
	if statusErr != nil {
		t.Fatalf("status request failed: %v", statusErr)
	}
	defer statusResp.Body.Close()

	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on status, got: %d", statusResp.StatusCode)
	}

	var recordedOffender offender.Offender

	decodeErr := json.NewDecoder(statusResp.Body).Decode(&recordedOffender)
	if decodeErr != nil {
		t.Fatalf("decode status: %v", decodeErr)
	}

	if recordedOffender.IP != targetIP {
		t.Fatalf("expected IP %s, got: %s", targetIP, recordedOffender.IP)
	}

	if recordedOffender.Count != 1 {
		t.Fatalf("expected count 1, got: %d", recordedOffender.Count)
	}
}

func TestFunctionalMessageTooLongRejected(t *testing.T) {
	t.Parallel()

	oversizedMessage := strings.Repeat("x", 2049)

	reportURL := testServer.URL + "/report/192.0.2.20/ssh?message=" + oversizedMessage

	resp, reportErr := httpGet(context.Background(), reportURL)
	if reportErr != nil {
		t.Fatalf("report request: %v", reportErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized report, got: %d", resp.StatusCode)
	}

	banURL := testServer.URL + "/ban/192.0.2.20/ssh?message=" + oversizedMessage

	banResp, banErr := httpGet(context.Background(), banURL)
	if banErr != nil {
		t.Fatalf("ban request: %v", banErr)
	}
	defer banResp.Body.Close()

	if banResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized ban, got: %d", banResp.StatusCode)
	}
}

func TestFunctionalConcurrentReports(t *testing.T) {
	t.Parallel()

	targetIP := "192.0.2.30"
	totalRequests := 50

	var waitGroup sync.WaitGroup
	waitGroup.Add(totalRequests)

	for range totalRequests {
		go func() {
			defer waitGroup.Done()

			reportURL := testServer.URL + "/report/" + targetIP + "/ssh?message=burst"

			resp, reportErr := httpGet(context.Background(), reportURL)
			if reportErr != nil {
				t.Errorf("concurrent report error: %v", reportErr)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got: %d", resp.StatusCode)
			}
		}()
	}

	waitGroup.Wait()

	statusURL := testServer.URL + "/status/" + targetIP

	statusResp, statusErr := httpGet(context.Background(), statusURL)
	if statusErr != nil {
		t.Fatalf("status request failed: %v", statusErr)
	}
	defer statusResp.Body.Close()

	var recordedOffender offender.Offender

	decodeErr := json.NewDecoder(statusResp.Body).Decode(&recordedOffender)
	if decodeErr != nil {
		t.Fatalf("decode status: %v", decodeErr)
	}

	if recordedOffender.Count != totalRequests {
		t.Fatalf("expected %d reports recorded, got: %d", totalRequests, recordedOffender.Count)
	}
}

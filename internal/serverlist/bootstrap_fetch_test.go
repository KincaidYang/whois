package serverlist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestFetchBootstrapParsesServices(t *testing.T) {
	// One well-formed service with an HTTPS alternative, plus every malformed
	// service shape the parser must skip without failing the whole file.
	body := `{"services":[
		[["com","net"],["http://insecure.example/","https://secure.example/rdap/"]],
		[["tooshort"]],
		[[123],["https://badids.example/"]],
		[["badurls"],"not-an-array"],
		[["nourls"],[]],
		[["httponly"],["http://plain.example/"]]
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := fetchBootstrap(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchBootstrap: %v", err)
	}

	want := map[string]string{
		"com":      "https://secure.example/rdap/", // HTTPS preferred over first URL
		"net":      "https://secure.example/rdap/",
		"httponly": "http://plain.example/", // no HTTPS available: first URL
	}
	if len(got) != len(want) {
		t.Errorf("got %d entries (%v), want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestFetchBootstrapErrors(t *testing.T) {
	newServer := func(handler http.HandlerFunc) *httptest.Server {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("non-200 status", func(t *testing.T) {
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := fetchBootstrap(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "unexpected status") {
			t.Errorf("err = %v, want unexpected status", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("{not json"))
		})
		if _, err := fetchBootstrap(context.Background(), srv.Client(), srv.URL); err == nil {
			t.Error("want JSON decode error")
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(make([]byte, maxBootstrapResponseSize+1))
		})
		if _, err := fetchBootstrap(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("err = %v, want size limit error", err)
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		if _, err := fetchBootstrap(context.Background(), http.DefaultClient, "://bad"); err == nil {
			t.Error("want request creation error")
		}
	})

	t.Run("unreachable server", func(t *testing.T) {
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {})
		url := srv.URL
		srv.Close()
		if _, err := fetchBootstrap(context.Background(), http.DefaultClient, url); err == nil {
			t.Error("want connection error")
		}
	})
}

// swapBootstrapURLs points every IANA category at test URLs and restores the
// real ones on cleanup.
func swapBootstrapURLs(t *testing.T, urls map[string]string) {
	t.Helper()
	old := ianaBootstrapURLs
	ianaBootstrapURLs = urls
	t.Cleanup(func() { ianaBootstrapURLs = old })
}

func TestFetchIANAPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(`{"services":[[["example"],["https://ok.example/rdap/"]]]}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	swapBootstrapURLs(t, map[string]string{
		"dns":  srv.URL + "/ok",
		"ipv4": srv.URL + "/ok",
		"ipv6": srv.URL + "/broken",
		"asn":  srv.URL + "/broken",
	})

	perCategory, failed := FetchIANA(context.Background(), srv.Client())

	for _, want := range []string{"dns", "ipv4"} {
		if data, ok := perCategory[want]; !ok || data["example"] != "https://ok.example/rdap/" {
			t.Errorf("category %s = %v, want fetched data", want, data)
		}
	}
	sort.Strings(failed)
	if len(failed) != 2 || failed[0] != "asn" || failed[1] != "ipv6" {
		t.Errorf("failed = %v, want [asn ipv6]", failed)
	}
}

func TestStartBootstrapRefreshDisabled(t *testing.T) {
	// interval <= 0 must be a no-op: no goroutine, no fetch.
	swapBootstrapURLs(t, map[string]string{"dns": "http://must-not-be-called.invalid/"})
	StartBootstrapRefresh(context.Background(), http.DefaultClient, 0)
}

func TestStartBootstrapRefreshUpdatesIndex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			// One permanently failing category exercises the partial-update path.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"services":[[["zzrefresh"],["https://refresh.example/rdap/"]]]}`))
	}))

	swapBootstrapURLs(t, map[string]string{
		"dns":  srv.URL + "/ok",
		"ipv4": srv.URL + "/ok",
		"ipv6": srv.URL + "/ok",
		"asn":  srv.URL + "/broken",
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		// Let an in-flight refresh finish before URLs are restored and the
		// index is reset.
		time.Sleep(50 * time.Millisecond)
		srv.Close()
		UpdateFromIANA(nil)
	})

	StartBootstrapRefresh(ctx, srv.Client(), 25*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if url, ok := LookupRdapServer("zzrefresh"); ok {
			if url != "https://refresh.example/rdap/" {
				t.Fatalf("zzrefresh = %q, want refreshed URL", url)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("bootstrap refresh never updated the index")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

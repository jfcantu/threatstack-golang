package threatstack

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	testMux    *http.ServeMux
	testClient *Client
	testServer *httptest.Server
)

func setupTesting() {
	testMux = http.NewServeMux()
	testServer = httptest.NewServer(testMux)
	testClient, _ = NewClient(&Config{BaseURL: testServer.URL, APIKey: "a", OrganizationID: "o", UserID: "u"})
}

func teardownTesting() {
	testServer.Close()
}

func testMethod(test *testing.T, request *http.Request, expected string) {
	if received := request.Method; received != expected {
		test.Errorf("Request method: %v, expected %v", received, expected)
	}
}

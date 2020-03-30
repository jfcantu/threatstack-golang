package threatstack

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	hawk "github.com/tent/hawk-go"
)

// A Request represents a Threat Stack API request.
type Request struct {
	request *http.Request
	creds   *hawk.Credentials
	auth    *hawk.Auth
}

// A Response wraps a response from the Threat Stack API.
type Response struct {
	*http.Response
}

// A Client is an interface for making requests to the Threat Stack API.
type Client struct {
	BaseURL *url.URL
	client  *http.Client
	creds   *Credentials

	Rulesets *RulesetService
	Rules    *RuleService
}

// Credentials contains the secrets needed to authenticate requests to the Threat Stack API.
type Credentials struct {
	APIKey         string
	OrganizationID string
	UserID         string
}

// A ListResponse is a wrapper that can contain a server response for any of these listed object types.
type ListResponse struct {
	Rulesets []*json.RawMessage `json:"rulesets"`
	Rules    []*json.RawMessage `json:"rules"`
	Token    string             `json:"token"`
}

// APIRequest sends an authenticated request to the API and returns the response body.
func (client *Client) APIRequest(method, path string, opts map[string]string, body interface{}) ([]byte, error) {
	var buffer io.ReadWriter
	url := fmt.Sprintf("%s/%s/%s", client.BaseURL, apiVersion, path)

	if body != nil {
		buffer = new(bytes.Buffer)
		err := json.NewEncoder(buffer).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	httpreq, err := http.NewRequest(method, url, buffer)
	if err != nil {
		return nil, err
	}

	log.Debugf("Calling %s on %s", httpreq.Method, httpreq.URL.String())

	if opts != nil {
		for opt, val := range opts {
			httpreq.URL.Query().Add(opt, val)
		}
	}

	req := &Request{
		request: httpreq,
	}

	req.GenerateAuth(client.creds)

	resp, err := client.SendHTTPRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Response.Body.Close()

	data, err := ioutil.ReadAll(resp.Response.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// NewClient creates a new API client.
func NewClient(cfg *Config) (*Client, error) {
	BaseURL := new(url.URL)
	var err error

	viper.SetEnvPrefix("TS")
	viper.BindEnv("LOG")

	switch l := viper.Get("LOG"); l {
	case "trace":
		log.SetLevel(log.TraceLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	}

	if cfg.BaseURL != "" {
		BaseURL, err = url.Parse(cfg.BaseURL)
		if err != nil {
			return nil, err
		}
	} else {
		BaseURL, err = url.Parse(defaultBaseURL)
		if err != nil {
			return nil, err
		}
	}

	newClient := &Client{
		BaseURL: BaseURL,
		client:  http.DefaultClient,
		creds: &Credentials{
			APIKey:         cfg.APIKey,
			OrganizationID: cfg.OrganizationID,
			UserID:         cfg.UserID,
		},
	}

	newClient.Rulesets = &RulesetService{newClient}
	newClient.Rules = &RuleService{newClient}

	return newClient, nil
}

// GenerateAuth generates/adds Hawk credentials to an HTTP request using Threat Stack credentials..
func (req *Request) GenerateAuth(creds *Credentials) error {
	hawkcreds := &hawk.Credentials{
		ID:   creds.UserID,
		Key:  creds.APIKey,
		Hash: sha256.New,
	}

	clientAuth := hawk.NewRequestAuth(req.request, hawkcreds, 0)
	clientAuth.Ext = creds.OrganizationID

	if req.request.Body != nil {
		reqBody, err := ioutil.ReadAll(req.request.Body)
		if err != nil {
			return err
		}
		req.request.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
		if len(reqBody) > 0 {
			log.Debugf("[DEBUG] Payload: %s", string(reqBody))
			payloadHash := clientAuth.PayloadHash("application/json")
			payloadHash.Write(reqBody)
			clientAuth.SetHash(payloadHash)
			req.request.Header.Set("Content-Type", "application/json")
		}
	}

	req.request.Header.Set("Authorization", clientAuth.RequestHeader())
	req.request.Header.Set("Accept", "application/json")

	return nil
}

// SendHTTPRequest sends an HTTP request to the server, and retries if needed.
func (client *Client) SendHTTPRequest(req *Request) (*Response, error) {
	httpResponse := new(http.Response)

	for i := 1; i <= 3; i++ {
		var err error
		httpResponse, err = client.client.Do(req.request)
		if err != nil {
			return nil, err
		}

		log.Tracef("Server response code: %d", httpResponse.StatusCode)

		if httpResponse.StatusCode == 429 {
			if i < 3 {
				log.Warnf("Retrying Received 429 (Too Many Requests) from server trying to access %v (attempt %v) - sleeping 60 seconds",
					req.request.URL, i)
				time.Sleep(60 * time.Second)
			} else {
				return nil, fmt.Errorf("[ERR] Received 429 after three attempts to access %v - aborting", req.request.URL)
			}
		} else if httpResponse.StatusCode == 200 {
			break
		} else {
			respBody, err := ioutil.ReadAll(httpResponse.Body)
			if err != nil {
				return nil, err
			}
			log.Errorf("[ERR] Server returned HTTP %v: %v", httpResponse.StatusCode, string(respBody))
			return nil, fmt.Errorf("Server returned HTTP code %v for %v: %v", httpResponse.StatusCode, req.request.URL, string(respBody))
		}
	}

	return &Response{httpResponse}, nil
}

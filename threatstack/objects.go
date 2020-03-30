package threatstack

import (
	"encoding/json"
)

// ListObjects gets an object list at a given path, handles any pagination, and returns the result as an array of JSON objects.
func (client *Client) ListObjects(path, datatype string, opts map[string]string) ([]*json.RawMessage, error) {
	ret := []*json.RawMessage{}

	// Get the raw response body
	raw, err := client.APIRequest("GET", path, opts, nil)
	if err != nil {
		return nil, err
	}

	// Unmarshal the response into a list struct
	respdata := new(ListResponse)
	if err := json.Unmarshal(raw, respdata); err != nil {
		return nil, err
	}

	// Set return value
	switch datatype {
	case "rulesets":
		ret = respdata.Rulesets
	case "rules":
		ret = respdata.Rules
	}

	// Check if a token was included in the result list - indicates there are more results to fetch
	if respdata.Token != "" {
		// Add token to options for next request
		if opts == nil {
			opts = map[string]string{"token": respdata.Token}
		} else {
			opts["token"] = respdata.Token
		}

		// Recursively get the next page[s] of results
		nextpages, err := client.ListObjects(path, datatype, opts)
		if err != nil {
			return nil, err
		}

		// Add the returned pages to the return value
		ret = append(ret, nextpages...)
	}

	return ret, nil
}

// GetObject gets an object from the given path, and returns the resulting JSON object as a byte array.
func (client *Client) GetObject(path string, opts map[string]string) ([]byte, error) {
	resp, err := client.APIRequest("GET", path, opts, nil)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// CreateObject creates an object at the given path, and returns the resulting JSON object as a byte array.
func (client *Client) CreateObject(path string, opts map[string]string, body interface{}) ([]byte, error) {
	resp, err := client.APIRequest("POST", path, opts, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// UpdateObject updates an object at the given path, and returns the resulting JSON object as a byte array.
func (client *Client) UpdateObject(path string, opts map[string]string, body interface{}) ([]byte, error) {
	resp, err := client.APIRequest("PUT", path, opts, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// DeleteObject deletes the object at the given path.
func (client *Client) DeleteObject(path string, opts map[string]string) error {
	_, err := client.APIRequest("DELETE", path, opts, nil)
	if err != nil {
		return err
	}

	return nil
}

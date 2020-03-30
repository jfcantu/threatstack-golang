package threatstack

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// RulesetService exposes the functions for managing rulesets.
type RulesetService service

// Ruleset represents a Threat Stack ruleset.
type Ruleset struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CreatedAt   string   `json:"createdAt,omitempty"`
	UpdatedAt   string   `json:"updatedAt,omitempty"`
	RuleIDs     []string `json:"ruleIds"`
}

// List returns all the rulesets existing on the server.
func (rs *RulesetService) List() ([]*Ruleset, error) {
	var ret []*Ruleset

	// Retrieve the list of raw JSON objects
	rawlist, err := rs.client.ListObjects(rulesetEndpoint, "rulesets", nil)
	if err != nil {
		return nil, err
	}

	// Unmarshal each JSON object returned and append to results
	for _, raw := range rawlist {
		obj := new(Ruleset)

		if err := json.Unmarshal(*raw, &obj); err != nil {
			return nil, err
		}

		ret = append(ret, obj)
	}

	return ret, nil
}

// Get returns the ruleset with the given ID.
func (rs *RulesetService) Get(id string) (*Ruleset, error) {
	resp := new(Ruleset)

	path := fmt.Sprintf("%s/%s", rulesetEndpoint, id)

	raw, err := rs.client.GetObject(path, nil)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// Create creates a ruleset on the server.
func (rs *RulesetService) Create(ruleset *Ruleset) (*Ruleset, error) {
	resp := new(Ruleset)

	log.Debugf("Creating ruleset %v", ruleset.Name)

	raw, err := rs.client.CreateObject(rulesetEndpoint, nil, ruleset)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// Update updates the given ruleset on the server.
func (rs *RulesetService) Update(ruleset *Ruleset) (*Ruleset, error) {
	resp := new(Ruleset)
	path := fmt.Sprintf("%s/%s", rulesetEndpoint, ruleset.ID)

	log.Debugf("Updating ruleset %v", ruleset.Name)

	raw, err := rs.client.UpdateObject(path, nil, ruleset)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// Delete deletes the ruleset with the given ID from the server.
func (rs *RulesetService) Delete(id string) error {
	path := fmt.Sprintf("%s/%s", rulesetEndpoint, id)

	log.Debugf("Deleting ruleset with ID %v", id)

	err := rs.client.DeleteObject(path, nil)
	if err != nil {
		return err
	}

	return nil
}

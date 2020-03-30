package threatstack

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// RuleService exposes the functions for managing rulesets.
type RuleService service

// RuleList contains a list of all the host and FIM rules for a particular ruleset.
type RuleList struct {
	RulesetID string
	FileRules []*FileRule
	HostRules []*HostRule
}

// A Tag represents a Tag that can be used for inclusion/exclusion of a rule.
type Tag struct {
	Source string `json:"source"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}

// A TagSet represents all the tags associated with a rule.
type TagSet struct {
	Include []*Tag `json:"inclusion"`
	Exclude []*Tag `json:"exclusion"`
}

// A Rule is an interface representing different types of Threat Stack rules.
type Rule interface {
	GetID() string
	GetTags() *TagSet
	SetTags(tags *TagSet)
}

// List returns all the rules belonging to a specific ruleset.
func (rs *RuleService) List(ruleset string) ([]interface{}, error) {
	log.Tracef("RuleService.List(%s)", ruleset)
	var ret []interface{}

	path := fmt.Sprintf("%v/%v/%v", rulesetEndpoint, ruleset, ruleEndpoint)

	// Get the list of raw JSON objects
	rawlist, err := rs.client.ListObjects(path, "rulesets", nil)
	if err != nil {
		return nil, err
	}

	// Iterate through the list
	for _, v := range rawlist {
		// Unmarshal the raw object to an interface
		rule, err := rs.ruleFromJSON(*v)
		if err != nil {
			return nil, err
		}

		ret = append(ret, rule)
	}

	return ret, nil
}

// Get returns the rule data for a specific rule.
func (rs *RuleService) Get(ruleset, id string) (*Rule, error) {
	log.Tracef("RuleService.Get(%s, %s)", ruleset, id)

	var rule *Rule
	rule, err := rs.getRuleObject(ruleset, id)
	if err != nil {
		return nil, err
	}

	var tags *TagSet
	tags, err = rs.getRuleTags(id)
	if err != nil && !strings.Contains(err.Error(), "No tags found for rule") {
		return nil, err
	}

	(*rule).SetTags(tags)

	return rule, nil
}

// Create creates a rule on the server.
func (rs *RuleService) Create(ruleset string, rule Rule) (*Rule, error) {
	log.Tracef("RuleService.Create(%s, ...)", ruleset)
	path := fmt.Sprintf("%v/%v/%v", rulesetEndpoint, ruleset, ruleEndpoint)

	raw, err := rs.client.CreateObject(path, nil, rule)
	if err != nil {
		return nil, err
	}

	resp, err := rs.ruleFromJSON(raw)
	if err != nil {
		return nil, err
	}

	newtags, err := rs.ApplyTags(resp.GetID(), rule.GetTags())
	if err != nil {
		return nil, err
	}
	resp.SetTags(newtags)

	return &resp, nil
}

// Update updates a rule on the server.
func (rs *RuleService) Update(ruleset, id string, rule Rule) (*Rule, error) {
	log.Tracef("RuleService.Update(%s, %s)", ruleset, id)
	path := fmt.Sprintf("%v/%v/%v/%v", rulesetEndpoint, ruleset, ruleEndpoint, id)

	raw, err := rs.client.UpdateObject(path, nil, rule)
	if err != nil {
		return nil, err
	}

	resp, err := rs.ruleFromJSON(raw)
	if err != nil {
		return nil, err
	}

	newtags, err := rs.ApplyTags(resp.GetID(), rule.GetTags())
	if err != nil {
		return nil, err
	}
	resp.SetTags(newtags)

	return &resp, nil
}

// Delete deletes a rule from the server.
func (rs *RuleService) Delete(ruleset, id string) error {
	log.Tracef("RuleService.Delete(%s, %s)", ruleset, id)
	path := fmt.Sprintf("%v/%v/%v/%v", rulesetEndpoint, ruleset, ruleEndpoint, id)
	err := rs.client.DeleteObject(path, nil)
	if err != nil {
		return err
	}

	return nil
}

func (rs *RuleService) getRuleObject(ruleset, id string) (*Rule, error) {
	path := fmt.Sprintf("%v/%v/%v/%v", rulesetEndpoint, ruleset, ruleEndpoint, id)

	raw, err := rs.client.GetObject(path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := rs.ruleFromJSON(raw)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

func (rs *RuleService) getRuleTags(id string) (*TagSet, error) {
	tagpath := fmt.Sprintf("%v/%v/%v", ruleEndpoint, id, tagEndpoint)
	tags := new(TagSet)

	raw, err := rs.client.GetObject(tagpath, nil)
	if strings.Contains(err.Error(), "No tags found for rule") {
		return tags, nil
	} else if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, tags); err != nil {
		return nil, err
	}

	return tags, nil
}

func (rs *RuleService) ruleFromJSON(obj []byte) (Rule, error) {
	// Unmarshal the raw object to an interface
	var temp interface{}
	if err := json.Unmarshal(obj, &temp); err != nil {
		return nil, err
	}

	// Find the rule type
	var rule Rule
	switch t := temp.(map[string]interface{})["type"].(string); t {
	case "File":
		rule = new(FileRule)
	case "Winsec":
		fallthrough
	case "CloudTrail":
		fallthrough
	case "ThreatIntel":
		fallthrough
	case "Host":
		rule = new(HostRule)
	default:
		return nil, fmt.Errorf("[ERR] Unknown rule type in RuleService.JSONToObject() - %v", t)
	}
	if err := json.Unmarshal(obj, rule); err != nil {
		return nil, err
	}

	return rule, nil
}

// ApplyTags applies a TagSet to a rule on the server.
func (rs *RuleService) ApplyTags(id string, tags *TagSet) (*TagSet, error) {
	path := fmt.Sprintf("%v/%v/%v", ruleEndpoint, id, tagEndpoint)

	raw, err := rs.client.CreateObject(path, nil, tags)
	if err != nil {
		return nil, err
	}

	ret := NewTagSet()
	if err := json.Unmarshal(raw, ret); err != nil {
		return nil, err
	}

	return ret, nil
}

// NewTagSet creates a new TagSet.
func NewTagSet() *TagSet {
	return &TagSet{
		Include: []*Tag{},
		Exclude: []*Tag{},
	}
}

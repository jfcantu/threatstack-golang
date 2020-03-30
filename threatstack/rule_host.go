package threatstack

// A HostRule represents a Threat Stack rule.
// Important note: HostRules encompass _all_ rule types that are not FIM rules.
// The reason for this is that all rules except FIM rules share the same schema.
type HostRule struct {
	ID              string   `json:"id,omitempty"`
	RulesetID       string   `json:"rulesetId,omitempty"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	CreatedAt       string   `json:"createdAt,omitempty"`
	UpdatedAt       string   `json:"updatedAt,omitempty"`
	Title           string   `json:"title"`
	Severity        int      `json:"severityOfAlerts"`
	Description     string   `json:"alertDescription,omitempty"`
	AggregateFields []string `json:"aggregateFields,omitempty"`
	Filter          string   `json:"filter,omitempty"`
	Window          int      `json:"window"`
	Threshold       int      `json:"threshold"`
	Suppressions    []string `json:"suppressions,omitempty"`
	Enabled         bool     `json:"enabled"`
	Tags            *TagSet  `json:"-"`
}

// GetTags returns the TagSet for the rule.
func (rule *HostRule) GetTags() *TagSet {
	return rule.Tags
}

// SetTags sets the TagSet for the rule.
func (rule *HostRule) SetTags(tags *TagSet) {
	rule.Tags = tags
}

// GetID returns the rule ID (so we can get the rule ID without knowing its type.)
func (rule *HostRule) GetID() string {
	return rule.ID
}

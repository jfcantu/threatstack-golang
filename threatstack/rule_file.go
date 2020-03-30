package threatstack

// A FileRule represents a Threat Stack FIM rule.
type FileRule struct {
	ID              string      `json:"id,omitempty"`
	RulesetID       string      `json:"rulesetId,omitempty"`
	Name            string      `json:"name"`
	Type            string      `json:"type"`
	CreatedAt       string      `json:"createdAt,omitempty"`
	UpdatedAt       string      `json:"updatedAt,omitempty"`
	Title           string      `json:"title"`
	Severity        int         `json:"severityOfAlerts"`
	Description     string      `json:"alertDescription,omitempty"`
	AggregateFields []string    `json:"aggregateFields,omitempty"`
	Filter          string      `json:"filter,omitempty"`
	Window          int         `json:"window"`
	Threshold       int         `json:"threshold"`
	Suppressions    []string    `json:"suppressions,omitempty"`
	Paths           []*FilePath `json:"fileIntegrityPaths"`
	IgnoreFiles     []string    `json:"ignoreFiles,omitempty"`
	MonitorEvents   []string    `json:"eventsToMonitor"`
	Enabled         bool        `json:"enabled"`
	Tags            *TagSet     `json:"-"`
}

// A FilePath represents a file path to be monitored by a FileRule.
type FilePath struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

// GetTags returns the TagSet for the rule.
func (rule *FileRule) GetTags() *TagSet {
	return rule.Tags
}

// SetTags sets the TagSet for the rule.
func (rule *FileRule) SetTags(tags *TagSet) {
	rule.Tags = tags
}

// GetID returns the rule ID (so we can get the rule ID without knowing its type.)
func (rule *FileRule) GetID() string {
	return rule.ID
}

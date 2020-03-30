package threatstack

// Data for GET file rule requests

const validGetFileRuleResponseJSON = `
{
	"id": "11111111-1111-1111-1111-111111111111",
	"rulesetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULE1",
	"type": "File",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"file"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"fileIntegrityPaths": [
		{
			"path": "PATH1",
			"recursive": true
		},
		{
			"path": "PATH2",
			"recursive": true
		}
	],
	"ignoreFiles": [
		"IGNORE1",
		"IGNORE2"
	],
	"eventsToMonitor": [
		"modify",
		"delete"
	],
	"enabled": true
}`

var validGetFileRuleResponse = &FileRule{
	ID:          "11111111-1111-1111-1111-111111111111",
	RulesetID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULE1",
	Type:        "File",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	Title:       "TITLE1",
	Severity:    1,
	Description: "DESCRIPTION1",
	AggregateFields: []string{
		"file",
	},
	Filter:    "FILTER1",
	Window:    86400,
	Threshold: 1,
	Suppressions: []string{
		"SUPPRESSION1",
		"SUPPRESSION2"},
	Paths: []*FilePath{
		&FilePath{
			Path:      "PATH1",
			Recursive: true,
		},
		&FilePath{
			Path:      "PATH2",
			Recursive: true,
		},
	},
	IgnoreFiles: []string{
		"IGNORE1",
		"IGNORE2",
	},
	MonitorEvents: []string{
		"modify",
		"delete",
	},
	Enabled: true,
	Tags: &TagSet{
		Include: []*Tag{
			&Tag{
				Source: "ec2",
				Key:    "KEY1",
				Value:  "VALUE1",
			},
			&Tag{
				Source: "ec2",
				Key:    "KEY2",
				Value:  "VALUE2",
			},
		},
		Exclude: []*Tag{
			&Tag{
				Source: "ec2",
				Key:    "KEY3",
				Value:  "VALUE3",
			},
			&Tag{
				Source: "ec2",
				Key:    "KEY4",
				Value:  "VALUE4",
			},
		},
	},
}

// Data for POST file rule requests

const validPostFileRuleJSON = `
{
	"name": "RULE1",
	"type": "File",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"file"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"fileIntegrityPaths": [
		{
			"path": "PATH1",
			"recursive": true
		},
		{
			"path": "PATH2",
			"recursive": true
		}
	],
	"ignoreFiles": [
		"IGNORE1",
		"IGNORE2"
	],
	"eventsToMonitor": [
		"modify",
		"delete"
	],
	"enabled": true
}`

var validPostFileRuleResponse = &FileRule{
	ID:          "11111111-1111-1111-1111-111111111111",
	RulesetID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULE1",
	Type:        "File",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	Title:       "TITLE1",
	Severity:    1,
	Description: "DESCRIPTION1",
	AggregateFields: []string{
		"file",
	},
	Filter:    "FILTER1",
	Window:    86400,
	Threshold: 1,
	Suppressions: []string{
		"SUPPRESSION1",
		"SUPPRESSION2"},
	Paths: []*FilePath{
		&FilePath{
			Path:      "PATH1",
			Recursive: true,
		},
		&FilePath{
			Path:      "PATH2",
			Recursive: true,
		},
	},
	IgnoreFiles: []string{
		"IGNORE1",
		"IGNORE2",
	},
	MonitorEvents: []string{
		"modify",
		"delete",
	},
	Enabled: true,
	Tags: &TagSet{
		Include: []*Tag{
			&Tag{
				Source: "ec2",
				Key:    "KEY1",
				Value:  "VALUE1",
			},
			&Tag{
				Source: "ec2",
				Key:    "KEY2",
				Value:  "VALUE2",
			},
		},
		Exclude: []*Tag{
			&Tag{
				Source: "ec2",
				Key:    "KEY3",
				Value:  "VALUE3",
			},
			&Tag{
				Source: "ec2",
				Key:    "KEY4",
				Value:  "VALUE4",
			},
		},
	},
}

var validPostFileRuleResponseJSON = `
{
	"id": "11111111-1111-1111-1111-111111111111",
	"rulesetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULE1",
	"type": "File",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"file"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"fileIntegrityPaths": [
		{
			"path": "PATH1",
			"recursive": true
		},
		{
			"path": "PATH2",
			"recursive": true
		}
	],
	"ignoreFiles": [
		"IGNORE1",
		"IGNORE2"
	],
	"eventsToMonitor": [
		"modify",
		"delete"
	],
	"enabled": true
}`

// Responses for PUT file rule requests

const validPutFileRuleJSON = `
{
	"name": "RULE1",
	"type": "File",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"file"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"fileIntegrityPaths": [
		{
			"path": "PATH1",
			"recursive": true
		},
		{
			"path": "PATH2",
			"recursive": true
		}
	],
	"ignoreFiles": [
		"IGNORE1",
		"IGNORE2"
	],
	"eventsToMonitor": [
		"modify",
		"delete"
	],
	"enabled": true
}`

var validPutFileRuleResponse = &FileRule{
	ID:          "11111111-1111-1111-1111-111111111111",
	RulesetID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULE1",
	Type:        "File",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	Title:       "TITLE1",
	Severity:    1,
	Description: "DESCRIPTION1",
	AggregateFields: []string{
		"file",
	},
	Filter:    "FILTER1",
	Window:    86400,
	Threshold: 1,
	Suppressions: []string{
		"SUPPRESSION1",
		"SUPPRESSION2"},
	Paths: []*FilePath{
		&FilePath{
			Path:      "PATH1",
			Recursive: true,
		},
		&FilePath{
			Path:      "PATH2",
			Recursive: true,
		},
	},
	IgnoreFiles: []string{
		"IGNORE1",
		"IGNORE2",
	},
	MonitorEvents: []string{
		"modify",
		"delete",
	},
	Enabled: true,
	Tags: &TagSet{
		Include: []*Tag{
			&Tag{
				Source: "ec2",
				Key:    "KEY1",
				Value:  "VALUE1",
			},
			&Tag{
				Source: "ec2",
				Key:    "KEY2",
				Value:  "VALUE2",
			},
		},
		Exclude: []*Tag{
			&Tag{
				Source: "ec2",
				Key:    "KEY3",
				Value:  "VALUE3",
			},
			&Tag{
				Source: "ec2",
				Key:    "KEY4",
				Value:  "VALUE4",
			},
		},
	},
}

var validPutFileRuleResponseJSON = `
{
	"id": "11111111-1111-1111-1111-111111111111",
	"rulesetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULE1",
	"type": "File",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"file"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"fileIntegrityPaths": [
		{
			"path": "PATH1",
			"recursive": true
		},
		{
			"path": "PATH2",
			"recursive": true
		}
	],
	"ignoreFiles": [
		"IGNORE1",
		"IGNORE2"
	],
	"eventsToMonitor": [
		"modify",
		"delete"
	],
	"enabled": true
}`

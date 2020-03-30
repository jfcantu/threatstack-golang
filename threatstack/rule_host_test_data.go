package threatstack

// Data for GET host rule requests

const validGetHostRuleResponseJSON = `
{
	"id": "11111111-1111-1111-1111-111111111111",
	"rulesetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULE1",
	"type": "Host",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"command",
		"user"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"enabled": true
}`

var validGetHostRuleResponse = &HostRule{
	ID:          "11111111-1111-1111-1111-111111111111",
	RulesetID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULE1",
	Type:        "Host",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	Title:       "TITLE1",
	Severity:    1,
	Description: "DESCRIPTION1",
	AggregateFields: []string{
		"command",
		"user",
	},
	Filter:    "FILTER1",
	Window:    86400,
	Threshold: 1,
	Suppressions: []string{
		"SUPPRESSION1",
		"SUPPRESSION2"},
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

// Data for POST host rule requests

const validPostHostRuleJSON = `
{
	"name": "RULE1",
	"type": "Host",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"command",
		"user"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"enabled": true
}`

var validPostHostRuleResponse = &HostRule{
	ID:          "11111111-1111-1111-1111-111111111111",
	RulesetID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULE1",
	Type:        "Host",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	Title:       "TITLE1",
	Severity:    1,
	Description: "DESCRIPTION1",
	AggregateFields: []string{
		"command",
		"user",
	},
	Filter:    "FILTER1",
	Window:    86400,
	Threshold: 1,
	Suppressions: []string{
		"SUPPRESSION1",
		"SUPPRESSION2"},
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

var validPostHostRuleResponseJSON = `
{
	"id": "11111111-1111-1111-1111-111111111111",
	"rulesetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULE1",
	"type": "Host",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"command",
		"user"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"enabled": true
}`

// Responses for PUT host rule requests

const validPutHostRuleJSON = `
{
	"name": "RULE1",
	"type": "Host",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"command",
		"user"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"enabled": true
}`

var validPutHostRuleResponse = &HostRule{
	ID:          "11111111-1111-1111-1111-111111111111",
	RulesetID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULE1",
	Type:        "Host",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	Title:       "TITLE1",
	Severity:    1,
	Description: "DESCRIPTION1",
	AggregateFields: []string{
		"command",
		"user",
	},
	Filter:    "FILTER1",
	Window:    86400,
	Threshold: 1,
	Suppressions: []string{
		"SUPPRESSION1",
		"SUPPRESSION2"},
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

var validPutHostRuleResponseJSON = `
{
	"id": "11111111-1111-1111-1111-111111111111",
	"rulesetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULE1",
	"type": "Host",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"title": "TITLE1",
	"severityOfAlerts": 1,
	"alertDescription": "DESCRIPTION1",
	"aggregateFields": [
		"command",
		"user"
	],
	"filter": "FILTER1",
	"window": 86400,
	"threshold": 1,
	"suppressions": [
		"SUPPRESSION1",
		"SUPPRESSION2"
	],
	"enabled": true
}`

package threatstack

const validListHostRulesJSON = `
{
	"rules": [
		{
			"id": "11111111-1111-1111-1111-111111111111",
			"rulesetId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			"name": "RULE1",
			"type": "Host",
			"createdAt":   "1970-01-01T00:00:00.000Z",
			"updatedAt":   "1970-01-01T00:00:00.000Z",
			"title": "TITLE1",
			"severityOfAlerts": "1",
			"alertDescription": "DESCRIPTION1",
			"aggregateFields": [
				"command",
				"user"
			]
			"filter": "FILTER1",
			"window": 86400,
			"threshold": 1,
			"suppressions": [
				"SUPPRESSION1",
				"SUPPRESSION2"
			],
			"enabled": true
		},
		{
			"id": "22222222-2222-2222-2222-222222222222",
			"rulesetId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
			"name": "RULE2",
			"type": "Host",
			"createdAt":   "1970-01-01T00:00:00.000Z",
			"updatedAt":   "1970-01-01T00:00:00.000Z",
			"title": "TITLE2",
			"severityOfAlerts": "2",
			"alertDescription": "DESCRIPTION2",
			"aggregateFields": [
				"command",
				"user"
			]
			"filter": "FILTER2",
			"window": 86400,
			"threshold": 1,
			"suppressions": [
				"SUPPRESSION3",
				"SUPPRESSION4"
			],
			"enabled": true
		}
	]
}`

var validListHostRulesResponse = []*HostRule{
	&HostRule{
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
		},
	},
	&HostRule{
		ID:          "22222222-2222-2222-2222-222222222222",
		RulesetID:   "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		Name:        "RULE2",
		Type:        "Host",
		CreatedAt:   "1970-01-01T00:00:00.000Z",
		UpdatedAt:   "1970-01-01T00:00:00.000Z",
		Title:       "TITLE2",
		Severity:    2,
		Description: "DESCRIPTION2",
		AggregateFields: []string{
			"command",
			"user",
		},
		Filter:    "FILTER2",
		Window:    86400,
		Threshold: 1,
		Suppressions: []string{
			"SUPPRESSION3",
			"SUPPRESSION4"},
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
		},
	},
}

// Response for rule tag requests
const validRuleTagJSON = `
{
	"inclusion": [
		{
			"source": "ec2",
			"key": "KEY1",
			"value": "VALUE1"
		},
		{
			"source": "ec2",
			"key": "KEY2",
			"value": "VALUE2"
		}
	],
	"exclusion": [
		{
			"source": "ec2",
			"key": "KEY3",
			"value": "VALUE3"
		},
		{
			"source": "ec2",
			"key": "KEY4",
			"value": "VALUE4"
		}
	]
}`

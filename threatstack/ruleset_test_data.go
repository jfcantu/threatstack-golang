package threatstack

const validListRulesetsJSON = `
{
	"rulesets": [
		{
			"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			"name": "RULESET1",
			"description": "DESCRIPTION1",
			"createdAt":   "1970-01-01T00:00:00.000Z",
			"updatedAt":   "1970-01-01T00:00:00.000Z",
			"rules": [
				"11111111-1111-1111-1111-111111111111",
				"22222222-2222-2222-2222-222222222222"
			]
		},
		{
			"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
			"name": "RULESET2",
			"description": "DESCRIPTION2",
			"createdAt":   "1970-01-01T00:00:00.000Z",
			"updatedAt":   "1970-01-01T00:00:00.000Z",
			"rules": [
				"33333333-3333-3333-3333-333333333333",
				"44444444-4444-4444-4444-444444444444"
			]
		}
	]
}`

var validListRulesetsResponse = []*Ruleset{
	&Ruleset{
		ID:          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Name:        "RULESET1",
		Description: "DESCRIPTION1",
		CreatedAt:   "1970-01-01T00:00:00.000Z",
		UpdatedAt:   "1970-01-01T00:00:00.000Z",
		RuleIDs: []string{
			"11111111-1111-1111-1111-111111111111",
			"22222222-2222-2222-2222-222222222222",
		},
	},
	&Ruleset{
		ID:          "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		Name:        "RULESET2",
		Description: "DESCRIPTION2",
		CreatedAt:   "1970-01-01T00:00:00.000Z",
		UpdatedAt:   "1970-01-01T00:00:00.000Z",
		RuleIDs: []string{
			"33333333-3333-3333-3333-333333333333",
			"44444444-4444-4444-4444-444444444444",
		},
	},
}

const validGetRulesetJSON = `
{
	"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULESET1",
	"description": "DESCRIPTION1",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"rules": [
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222"
	]
}
`

var validGetRulesetResponse = &Ruleset{
	ID:          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULESET1",
	Description: "DESCRIPTION1",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	RuleIDs: []string{
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222",
	},
}

const validPostRulesetJSON = `
{
	"name": "RULESET1",
	"description": "DESCRIPTION1",
	"rules": [
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222"
	]
}
`

const validPostRulesetResponseJSON = `
{
	"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULESET1",
	"description": "DESCRIPTION1",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"rules": [
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222"
	]
}
`

var validPostRulesetResponse = &Ruleset{
	ID:          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULESET1",
	Description: "DESCRIPTION1",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	RuleIDs: []string{
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222",
	},
}

const validPutRulesetJSON = `
{
	"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULESET1",
	"description": "DESCRIPTION1",
	"rules": [
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222"
	]
}
`

const validPutRulesetResponseJSON = `
{
	"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"name": "RULESET1",
	"description": "DESCRIPTION1",
	"createdAt":   "1970-01-01T00:00:00.000Z",
	"updatedAt":   "1970-01-01T00:00:00.000Z",
	"rules": [
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222"
	]
}
`

var validPutRulesetResponse = &Ruleset{
	ID:          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	Name:        "RULESET1",
	Description: "DESCRIPTION1",
	CreatedAt:   "1970-01-01T00:00:00.000Z",
	UpdatedAt:   "1970-01-01T00:00:00.000Z",
	RuleIDs: []string{
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222",
	},
}

const validDeleteRulesetID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

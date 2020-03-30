package threatstack

const (
	defaultBaseURL = "https://api.threatstack.com"

	apiVersion = "v2"

	rulesetEndpoint = "rulesets"
	ruleEndpoint    = "rules"
	tagEndpoint     = "tags"
)

// Config contains the basic parameters needed to communicate with the server.
type Config struct {
	BaseURL        string
	APIKey         string
	OrganizationID string
	UserID         string
}

type service struct {
	client *Client
}

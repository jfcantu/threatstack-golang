package threatstack

import (
	"fmt"
	"net/http"
	"testing"
)

const validDeleteRuleID = "11111111-1111-1111-1111-111111111111"

func TestRuleDelete(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(fmt.Sprintf("/%s/%s/%s/%s/%s", apiVersion, rulesetEndpoint, validDeleteRulesetID, ruleEndpoint, validDeleteRuleID),
		func(writer http.ResponseWriter, req *http.Request) {
			testMethod(test, req, "DELETE")
			writer.Write([]byte(`{}`))
		})

	if err := testClient.Rules.Delete(validDeleteRulesetID, validDeleteRuleID); err != nil {
		test.Fatal(err)
	}
}

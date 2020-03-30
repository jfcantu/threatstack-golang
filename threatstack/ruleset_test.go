package threatstack

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

func TestRulesetList(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s", apiVersion, rulesetEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "GET")
			writer.Write([]byte(validListRulesetsJSON))
		})

	resp, err := testClient.Rulesets.List()
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual(resp, validListRulesetsResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", resp, validListRulesetsResponse)
	}
}

func TestRulesetGet(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s", apiVersion, rulesetEndpoint, validGetRulesetResponse.ID),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "GET")
			writer.Write([]byte(validGetRulesetJSON))
		})

	resp, err := testClient.Rulesets.Get(validGetRulesetResponse.ID)
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual(resp, validGetRulesetResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", resp, validGetRulesetResponse)
	}
}

func TestRulesetCreate(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s", apiVersion, rulesetEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "POST")

			rawbody, err := ioutil.ReadAll(request.Body)
			if err != nil {
				test.Error(err.Error())
			}

			var body interface{}
			if err := json.Unmarshal(rawbody, &body); err != nil {
				test.Error(err.Error())
			}

			var expected interface{}
			if err := json.Unmarshal([]byte(validPostRulesetJSON), &expected); err != nil {
				test.Error(err.Error())
			}

			if !reflect.DeepEqual(body, expected) {
				test.Errorf("Request body:\n%v\n\nExpected %v\n", body, expected)
			}
			writer.Write([]byte(validPostRulesetResponseJSON))
		})

	resp, err := testClient.Rulesets.Create(&Ruleset{
		Name:        "RULESET1",
		Description: "DESCRIPTION1",
		RuleIDs: []string{
			"11111111-1111-1111-1111-111111111111",
			"22222222-2222-2222-2222-222222222222",
		},
	})
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual(resp, validPostRulesetResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", resp, validPostRulesetResponse)
	}
}

func TestRulesetUpdate(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s", apiVersion, rulesetEndpoint, validPutRulesetResponse.ID),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "PUT")

			rawbody, err := ioutil.ReadAll(request.Body)
			if err != nil {
				test.Error(err.Error())
			}

			var body interface{}
			if err := json.Unmarshal(rawbody, &body); err != nil {
				test.Error(err.Error())
			}

			var expected interface{}
			if err := json.Unmarshal([]byte(validPutRulesetJSON), &expected); err != nil {
				test.Error(err.Error())
			}

			if !reflect.DeepEqual(body, expected) {
				test.Errorf("Request body:\n%v\n\nExpected %v\n", body, expected)
			}
			writer.Write([]byte(validPutRulesetResponseJSON))
		})

	resp, err := testClient.Rulesets.Update(&Ruleset{
		ID:          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Name:        "RULESET1",
		Description: "DESCRIPTION1",
		RuleIDs: []string{
			"11111111-1111-1111-1111-111111111111",
			"22222222-2222-2222-2222-222222222222",
		},
	})
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual(resp, validPostRulesetResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", resp, validPostRulesetResponse)
	}
}

func TestRulesetDelete(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(fmt.Sprintf("/%s/%s/%s", apiVersion, rulesetEndpoint, validDeleteRulesetID), func(writer http.ResponseWriter, req *http.Request) {
		testMethod(test, req, "DELETE")
		writer.Write([]byte(`{}`))
	})

	if err := testClient.Rulesets.Delete(validDeleteRulesetID); err != nil {
		test.Fatal(err)
	}
}

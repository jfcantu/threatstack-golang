package threatstack

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

func TestHostRuleGet(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s/%s", apiVersion, rulesetEndpoint, validGetHostRuleResponse.RulesetID, ruleEndpoint, validGetHostRuleResponse.ID),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "GET")
			writer.Write([]byte(validGetHostRuleResponseJSON))
		})

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, ruleEndpoint, validGetHostRuleResponse.ID, tagEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "GET")
			writer.Write([]byte(validRuleTagJSON))
		})

	resp, err := testClient.Rules.Get(validGetHostRuleResponse.RulesetID, validGetHostRuleResponse.ID)
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual((*resp).(*HostRule), validGetHostRuleResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", (*resp).(*HostRule), validGetHostRuleResponse)
	}
}

func TestHostRuleCreate(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, rulesetEndpoint, validPostHostRuleResponse.RulesetID, ruleEndpoint),
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
			if err := json.Unmarshal([]byte(validPostHostRuleJSON), &expected); err != nil {
				test.Error(err.Error())
			}

			if !reflect.DeepEqual(body, expected) {
				test.Errorf("Request body:\n%v\n\nExpected:\n%v\n", body, expected)
			}
			writer.Write([]byte(validPostHostRuleResponseJSON))
		})

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, ruleEndpoint, validPostHostRuleResponse.ID, tagEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "POST")
			writer.Write([]byte(validRuleTagJSON))
		})

	resp, err := testClient.Rules.Create(validPostHostRuleResponse.RulesetID,
		&HostRule{
			Name:        "RULE1",
			Type:        "Host",
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
		})
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual((*resp).(*HostRule), validGetHostRuleResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", (*resp).(*HostRule), validGetHostRuleResponse)
	}
}

func TestHostRuleUpdate(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s/%s", apiVersion, rulesetEndpoint, validPostHostRuleResponse.RulesetID, ruleEndpoint, validPostHostRuleResponse.ID),
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
			if err := json.Unmarshal([]byte(validPutHostRuleJSON), &expected); err != nil {
				test.Error(err.Error())
			}

			if !reflect.DeepEqual(body, expected) {
				test.Errorf("Request body:\n%v\n\nExpected:\n%v\n", body, expected)
			}
			writer.Write([]byte(validPutHostRuleResponseJSON))
		})

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, ruleEndpoint, validPutHostRuleResponse.ID, tagEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "POST")
			writer.Write([]byte(validRuleTagJSON))
		})

	resp, err := testClient.Rules.Update(
		validPutHostRuleResponse.RulesetID,
		validPutHostRuleResponse.ID,
		&HostRule{
			Name:        "RULE1",
			Type:        "Host",
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
		})
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual((*resp).(*HostRule), validPutHostRuleResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", (*resp).(*HostRule), validPutHostRuleResponse)
	}

}

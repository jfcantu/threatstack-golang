package threatstack

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

func TestFileRuleGet(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s/%s", apiVersion, rulesetEndpoint, validGetFileRuleResponse.RulesetID, ruleEndpoint, validGetFileRuleResponse.ID),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "GET")
			writer.Write([]byte(validGetFileRuleResponseJSON))
		})

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, ruleEndpoint, validGetFileRuleResponse.ID, tagEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "GET")
			writer.Write([]byte(validRuleTagJSON))
		})

	resp, err := testClient.Rules.Get(validGetFileRuleResponse.RulesetID, validGetFileRuleResponse.ID)
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual((*resp).(*FileRule), validGetFileRuleResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", (*resp).(*FileRule), validGetFileRuleResponse)
	}
}

func TestFileRuleCreate(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, rulesetEndpoint, validPostFileRuleResponse.RulesetID, ruleEndpoint),
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
			if err := json.Unmarshal([]byte(validPostFileRuleJSON), &expected); err != nil {
				test.Error(err.Error())
			}

			if !reflect.DeepEqual(body, expected) {
				test.Errorf("Request body:\n%v\n\nExpected:\n%v\n", body, expected)
			}
			writer.Write([]byte(validPostFileRuleResponseJSON))
		})

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, ruleEndpoint, validPostFileRuleResponse.ID, tagEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "POST")
			writer.Write([]byte(validRuleTagJSON))
		})

	resp, err := testClient.Rules.Create(validPostFileRuleResponse.RulesetID,
		&FileRule{
			Name:        "RULE1",
			Type:        "File",
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
		})
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual((*resp).(*FileRule), validGetFileRuleResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", (*resp).(*FileRule), validGetFileRuleResponse)
	}
}

func TestFileRuleUpdate(test *testing.T) {
	setupTesting()
	defer teardownTesting()

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s/%s", apiVersion, rulesetEndpoint, validPostFileRuleResponse.RulesetID, ruleEndpoint, validPostFileRuleResponse.ID),
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
			if err := json.Unmarshal([]byte(validPutFileRuleJSON), &expected); err != nil {
				test.Error(err.Error())
			}

			if !reflect.DeepEqual(body, expected) {
				test.Errorf("Request body:\n%v\n\nExpected:\n%v\n", body, expected)
			}
			writer.Write([]byte(validPutFileRuleResponseJSON))
		})

	testMux.HandleFunc(
		fmt.Sprintf("/%s/%s/%s/%s", apiVersion, ruleEndpoint, validPutFileRuleResponse.ID, tagEndpoint),
		func(writer http.ResponseWriter, request *http.Request) {
			testMethod(test, request, "POST")
			writer.Write([]byte(validRuleTagJSON))
		})

	resp, err := testClient.Rules.Update(
		validPutFileRuleResponse.RulesetID,
		validPutFileRuleResponse.ID,
		&FileRule{
			Name:        "RULE1",
			Type:        "File",
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
		})
	if err != nil {
		test.Fatal(err)
	}

	if !reflect.DeepEqual((*resp).(*FileRule), validPutFileRuleResponse) {
		test.Errorf("Response:\n%#v\n\nExpected:\n%#v\n", (*resp).(*FileRule), validPutFileRuleResponse)
	}

}

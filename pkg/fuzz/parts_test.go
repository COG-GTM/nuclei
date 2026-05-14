package fuzz

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// --- TestExecuteRuleTypes ---

func TestExecuteRuleTypes(t *testing.T) {
	tests := []struct {
		name        string
		ruleType    ruleType
		regex       *regexp.Regexp
		value       string
		replacement string
		expected    string
	}{
		// replace
		{name: "replace-normal", ruleType: replaceRuleType, value: "original", replacement: "new", expected: "new"},
		{name: "replace-empty-value", ruleType: replaceRuleType, value: "", replacement: "new", expected: "new"},
		{name: "replace-empty-replacement", ruleType: replaceRuleType, value: "original", replacement: "", expected: ""},
		{name: "replace-both-empty", ruleType: replaceRuleType, value: "", replacement: "", expected: ""},

		// prefix
		{name: "prefix-normal", ruleType: prefixRuleType, value: "world", replacement: "hello-", expected: "hello-world"},
		{name: "prefix-empty-value", ruleType: prefixRuleType, value: "", replacement: "prefix", expected: "prefix"},
		{name: "prefix-empty-replacement", ruleType: prefixRuleType, value: "value", replacement: "", expected: "value"},
		{name: "prefix-both-empty", ruleType: prefixRuleType, value: "", replacement: "", expected: ""},

		// postfix
		{name: "postfix-normal", ruleType: postfixRuleType, value: "hello", replacement: "-world", expected: "hello-world"},
		{name: "postfix-empty-value", ruleType: postfixRuleType, value: "", replacement: "postfix", expected: "postfix"},
		{name: "postfix-empty-replacement", ruleType: postfixRuleType, value: "value", replacement: "", expected: "value"},
		{name: "postfix-both-empty", ruleType: postfixRuleType, value: "", replacement: "", expected: ""},

		// infix
		{name: "infix-normal", ruleType: infixRuleType, value: "abcd", replacement: "XX", expected: "abXXcd"},
		{name: "infix-odd-length-value", ruleType: infixRuleType, value: "abc", replacement: "X", expected: "aXbc"},
		{name: "infix-single-char-value", ruleType: infixRuleType, value: "a", replacement: "X", expected: "aX"},
		{name: "infix-empty-value", ruleType: infixRuleType, value: "", replacement: "X", expected: "X"},
		{name: "infix-empty-replacement", ruleType: infixRuleType, value: "abcd", replacement: "", expected: "abcd"},
		{name: "infix-two-char-value", ruleType: infixRuleType, value: "ab", replacement: "X", expected: "aXb"},

		// replace-regex
		{name: "regex-simple", ruleType: replaceRegexRuleType, regex: regexp.MustCompile(`\d+`), value: "abc123def", replacement: "NUM", expected: "abcNUMdef"},
		{name: "regex-no-match", ruleType: replaceRegexRuleType, regex: regexp.MustCompile(`\d+`), value: "abcdef", replacement: "NUM", expected: "abcdef"},
		{name: "regex-full-match", ruleType: replaceRegexRuleType, regex: regexp.MustCompile(`^.*$`), value: "anything", replacement: "replaced", expected: "replaced"},
		{name: "regex-empty-value", ruleType: replaceRegexRuleType, regex: regexp.MustCompile(`^$`), value: "", replacement: "filled", expected: "filled"},
		{name: "regex-multiple-matches", ruleType: replaceRegexRuleType, regex: regexp.MustCompile(`[aeiou]`), value: "hello", replacement: "*", expected: "h*ll*"},
		{name: "regex-url-pattern", ruleType: replaceRegexRuleType, regex: regexp.MustCompile(`https?://[^\s]+`), value: "visit http://example.com now", replacement: "REDACTED", expected: "visit REDACTED now"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &Rule{
				ruleType:     tt.ruleType,
				replaceRegex: tt.regex,
			}
			result := rule.executeRuleTypes(nil, tt.value, tt.replacement)
			require.Equal(t, tt.expected, result)
		})
	}
}

// --- TestExecutePartComponentOnValues ---

// newTestExecutorOptions returns a minimal ExecutorOptions suitable for tests
// that call executePartComponentOnValues (which calls executeEvaluate internally).
func newTestExecutorOptions(t *testing.T) *protocols.ExecutorOptions {
	t.Helper()

	vars := variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0),
	}

	interactClient, err := interactsh.New(&interactsh.Options{
		CacheSize: 100,
	})
	require.NoError(t, err)

	return &protocols.ExecutorOptions{
		Variables:  vars,
		Options:    &types.Options{},
		Interactsh: interactClient,
	}
}

// newQueryComponent creates a query component parsed from the given URL.
func newQueryComponent(t *testing.T, rawURL string) component.Component {
	t.Helper()
	req, err := retryablehttp.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)

	q := component.NewQuery()
	ok, err := q.Parse(req)
	require.NoError(t, err)
	require.True(t, ok, "query component should parse successfully")
	return q
}

func TestExecutePartComponentOnValues_SingleMode(t *testing.T) {
	opts := newTestExecutorOptions(t)
	rule := &Rule{
		ruleType: replaceRuleType,
		modeType: singleModeType,
		options:  opts,
	}

	comp := newQueryComponent(t, "https://example.com?a=1&b=2&c=3")

	var callbackCalls []GeneratedRequest
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			callbackCalls = append(callbackCalls, gr)
			return true
		},
		Values: map[string]interface{}{},
	}

	err := rule.executePartComponentOnValues(input, "FUZZ", "FUZZ", comp)
	require.NoError(t, err)

	// In single mode, each parameter should be fuzzed individually.
	require.Equal(t, 3, len(callbackCalls), "single mode should call callback once per parameter")

	// After execution, the component values should be restored to originals.
	var restoredValues []string
	_ = comp.Iterate(func(key string, value interface{}) error {
		restoredValues = append(restoredValues, value.(string))
		return nil
	})
	require.ElementsMatch(t, []string{"1", "2", "3"}, restoredValues, "values should be restored after single mode execution")
}

func TestExecutePartComponentOnValues_MultipleMode(t *testing.T) {
	opts := newTestExecutorOptions(t)
	rule := &Rule{
		ruleType: replaceRuleType,
		modeType: multipleModeType,
		options:  opts,
	}

	comp := newQueryComponent(t, "https://example.com?a=1&b=2&c=3")

	var callbackCalls []GeneratedRequest
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			callbackCalls = append(callbackCalls, gr)
			return true
		},
		Values: map[string]interface{}{},
	}

	err := rule.executePartComponentOnValues(input, "FUZZ", "FUZZ", comp)
	require.NoError(t, err)

	// In multiple mode, all parameters are mutated then a single request is sent.
	require.Equal(t, 1, len(callbackCalls), "multiple mode should call callback once with all parameters mutated")
}

func TestExecutePartComponentOnValues_KeyFiltering(t *testing.T) {
	opts := newTestExecutorOptions(t)
	rule := &Rule{
		ruleType: replaceRuleType,
		modeType: singleModeType,
		options:  opts,
		keysMap:  map[string]struct{}{"a": {}},
	}

	comp := newQueryComponent(t, "https://example.com?a=1&b=2&c=3")

	var fuzzedParams []string
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			fuzzedParams = append(fuzzedParams, gr.Parameter)
			return true
		},
		Values: map[string]interface{}{},
	}

	err := rule.executePartComponentOnValues(input, "FUZZ", "FUZZ", comp)
	require.NoError(t, err)

	require.Equal(t, 1, len(fuzzedParams), "only matching key 'a' should be fuzzed")
	require.Equal(t, "a", fuzzedParams[0])
}

func TestExecutePartComponentOnValues_KeyRegexFiltering(t *testing.T) {
	opts := newTestExecutorOptions(t)
	rule := &Rule{
		ruleType:  replaceRuleType,
		modeType:  singleModeType,
		options:   opts,
		keysRegex: []*regexp.Regexp{regexp.MustCompile(`^url`)},
	}

	comp := newQueryComponent(t, "https://example.com?url_param=val1&name=val2&url_path=val3")

	var fuzzedParams []string
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			fuzzedParams = append(fuzzedParams, gr.Parameter)
			return true
		},
		Values: map[string]interface{}{},
	}

	err := rule.executePartComponentOnValues(input, "FUZZ", "FUZZ", comp)
	require.NoError(t, err)

	require.Equal(t, 2, len(fuzzedParams), "only keys matching ^url regex should be fuzzed")
}

func TestExecutePartComponentOnValues_CallbackReturnsFalse(t *testing.T) {
	opts := newTestExecutorOptions(t)
	rule := &Rule{
		ruleType: replaceRuleType,
		modeType: singleModeType,
		options:  opts,
	}

	comp := newQueryComponent(t, "https://example.com?a=1&b=2&c=3")

	callCount := 0
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			callCount++
			return false // stop after first
		},
		Values: map[string]interface{}{},
	}

	err := rule.executePartComponentOnValues(input, "FUZZ", "FUZZ", comp)
	// When callback returns false, execWithInput returns ErrNoMoreRequests
	require.Error(t, err)
	require.Equal(t, 1, callCount, "should stop after first callback returns false")
}

func TestExecutePartComponentOnValues_NoMatchingKeys(t *testing.T) {
	opts := newTestExecutorOptions(t)
	rule := &Rule{
		ruleType: replaceRuleType,
		modeType: singleModeType,
		options:  opts,
		keysMap:  map[string]struct{}{"nonexistent": {}},
	}

	comp := newQueryComponent(t, "https://example.com?a=1&b=2")

	callCount := 0
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			callCount++
			return true
		},
		Values: map[string]interface{}{},
	}

	err := rule.executePartComponentOnValues(input, "FUZZ", "FUZZ", comp)
	require.NoError(t, err)
	require.Equal(t, 0, callCount, "no callback should be invoked when no keys match")
}

// --- TestExecWithInput ---

func TestExecWithInput_NormalExecution(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	called := false
	rule := &Rule{
		options: &protocols.ExecutorOptions{},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			called = true
			require.Equal(t, req, gr.Request)
			return true
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "param", "value", "", "", "key1", "val1")
	require.NoError(t, err)
	require.True(t, called, "callback should be invoked")
}

func TestExecWithInput_CallbackReturnsFalse(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	rule := &Rule{
		options: &protocols.ExecutorOptions{},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			return false
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "param", "", "", "", "", "")
	require.ErrorIs(t, err, types.ErrNoMoreRequests)
}

func TestExecWithInput_FrequencySkip(t *testing.T) {
	tracker := frequency.New(64, 1)
	defer tracker.Close()

	const target = "https://example.com/test"
	const templateID = "tmpl-freq-skip"

	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)

	// Mark the parameter value as frequent
	tracker.MarkParameter("paramValue", req.String(), templateID)

	called := false
	rule := &Rule{
		options: &protocols.ExecutorOptions{
			TemplateID:          templateID,
			FuzzParamsFrequency: tracker,
		},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			called = true
			return true
		},
	}

	// parameter is "idx", parameterValue is "paramValue"
	// Since idx is numeric, actualParameter becomes "paramValue"
	// which is marked frequent → should be skipped
	err = rule.execWithInput(input, req, nil, nil, "0", "paramValue", "", "", "", "")
	require.NoError(t, err)
	require.False(t, called, "callback should not be invoked for frequent parameter")
}

func TestExecWithInput_EmptyParameterBypassesFrequency(t *testing.T) {
	tracker := frequency.New(64, 1)
	defer tracker.Close()

	const target = "https://example.com/test"
	const templateID = "tmpl-freq-bypass"

	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)

	called := false
	rule := &Rule{
		options: &protocols.ExecutorOptions{
			TemplateID:          templateID,
			FuzzParamsFrequency: tracker,
		},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			called = true
			return true
		},
	}

	// Both parameter and parameterValue are empty → actualParameter remains ""
	// Frequency check is bypassed for empty parameters
	err = rule.execWithInput(input, req, nil, nil, "", "", "", "", "", "")
	require.NoError(t, err)
	require.True(t, called, "empty parameter should bypass frequency check")
}

func TestExecWithInput_NumericParameterUsesValue(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	var capturedParam string
	rule := &Rule{
		options: &protocols.ExecutorOptions{},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			capturedParam = gr.Parameter
			return true
		},
	}

	// When parameter is numeric ("3"), actualParameter should become parameterValue ("users")
	err = rule.execWithInput(input, req, nil, nil, "3", "users", "", "", "", "")
	require.NoError(t, err)
	require.Equal(t, "users", capturedParam, "numeric parameter should be replaced by parameter value")
}

func TestExecWithInput_EmptyParamWithNonEmptyValue(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	var capturedParam string
	rule := &Rule{
		options: &protocols.ExecutorOptions{},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			capturedParam = gr.Parameter
			return true
		},
	}

	// When parameter is "" but parameterValue is "myval", actualParameter becomes "myval"
	err = rule.execWithInput(input, req, nil, nil, "", "myval", "", "", "", "")
	require.NoError(t, err)
	require.Equal(t, "myval", capturedParam)
}

func TestExecWithInput_InteractURLsPropagated(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	interactURLs := []string{"https://interact1.example.com", "https://interact2.example.com"}

	var capturedURLs []string
	rule := &Rule{
		options: &protocols.ExecutorOptions{},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			capturedURLs = gr.InteractURLs
			return true
		},
	}

	err = rule.execWithInput(input, req, interactURLs, nil, "param", "", "", "", "", "")
	require.NoError(t, err)
	require.Equal(t, interactURLs, capturedURLs, "interact URLs should be propagated to generated request")
}

func TestExecWithInput_DynamicValuesPropagated(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	dynamicValues := map[string]interface{}{
		"token":  "abc123",
		"count":  42,
	}

	var capturedValues map[string]interface{}
	rule := &Rule{
		options: &protocols.ExecutorOptions{},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			capturedValues = gr.DynamicValues
			return true
		},
		Values: dynamicValues,
	}

	err = rule.execWithInput(input, req, nil, nil, "param", "", "", "", "", "")
	require.NoError(t, err)
	require.Equal(t, dynamicValues, capturedValues, "dynamic values should be propagated to generated request")
}

func TestExecWithInput_FieldMapping(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	rule := &Rule{
		options: &protocols.ExecutorOptions{},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			require.Equal(t, "theKey", gr.Key)
			require.Equal(t, "theValue", gr.Value)
			require.Equal(t, "origVal", gr.OriginalValue)
			require.Equal(t, "origPayload", gr.OriginalPayload)
			return true
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "param", "", "origPayload", "origVal", "theKey", "theValue")
	require.NoError(t, err)
}

func TestExecWithInput_NoFrequencyTracker(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)

	called := false
	rule := &Rule{
		options: &protocols.ExecutorOptions{
			FuzzParamsFrequency: nil,
		},
	}
	input := &ExecuteRuleInput{
		Callback: func(gr GeneratedRequest) bool {
			called = true
			return true
		},
	}

	err = rule.execWithInput(input, req, nil, nil, "param", "", "", "", "", "")
	require.NoError(t, err)
	require.True(t, called, "callback should be invoked when no frequency tracker is set")
}

// --- TestCheckRuleApplicableOnComponent ---

func TestCheckRuleApplicableOnComponent(t *testing.T) {
	t.Run("matching-part-name", func(t *testing.T) {
		rule := &Rule{
			Part: "query",
		}
		comp := newQueryComponent(t, "https://example.com?key=val")
		require.True(t, rule.checkRuleApplicableOnComponent(comp))
	})

	t.Run("non-matching-part-name", func(t *testing.T) {
		rule := &Rule{
			Part:     "header",
			partType: headersPartType,
		}
		comp := newQueryComponent(t, "https://example.com?key=val")
		require.False(t, rule.checkRuleApplicableOnComponent(comp))
	})

	t.Run("request-part-type-matches-any", func(t *testing.T) {
		rule := &Rule{
			Part:     "request",
			partType: requestPartType,
		}
		comp := newQueryComponent(t, "https://example.com?key=val")
		require.True(t, rule.checkRuleApplicableOnComponent(comp))
	})

	t.Run("parts-list-match", func(t *testing.T) {
		rule := &Rule{
			Parts: []string{"query", "body"},
		}
		comp := newQueryComponent(t, "https://example.com?key=val")
		require.True(t, rule.checkRuleApplicableOnComponent(comp))
	})

	t.Run("key-filter-no-match", func(t *testing.T) {
		rule := &Rule{
			Part:    "query",
			keysMap: map[string]struct{}{"nonexistent": {}},
		}
		comp := newQueryComponent(t, "https://example.com?key=val")
		require.False(t, rule.checkRuleApplicableOnComponent(comp))
	})

	t.Run("key-filter-match", func(t *testing.T) {
		rule := &Rule{
			Part:    "query",
			keysMap: map[string]struct{}{"key": {}},
		}
		comp := newQueryComponent(t, "https://example.com?key=val")
		require.True(t, rule.checkRuleApplicableOnComponent(comp))
	})
}

// --- TestExecutePartComponentOnKV ---

func TestExecutePartComponentOnKV(t *testing.T) {
	opts := newTestExecutorOptions(t)

	t.Run("existing-key-replaced", func(t *testing.T) {
		rule := &Rule{
			ruleType: replaceRuleType,
			modeType: singleModeType,
			options:  opts,
		}

		comp := newQueryComponent(t, "https://example.com?a=1&b=2")

		var capturedRequests []GeneratedRequest
		input := &ExecuteRuleInput{
			Callback: func(gr GeneratedRequest) bool {
				capturedRequests = append(capturedRequests, gr)
				return true
			},
			Values: map[string]interface{}{},
		}

		payload := ValueOrKeyValue{Key: "a", Value: "FUZZED"}
		err := rule.executePartComponentOnKV(input, payload, comp)
		require.NoError(t, err)
		require.Equal(t, 1, len(capturedRequests))
	})

	t.Run("new-key-added-and-removed", func(t *testing.T) {
		rule := &Rule{
			ruleType: replaceRuleType,
			modeType: singleModeType,
			options:  opts,
		}

		comp := newQueryComponent(t, "https://example.com?a=1")

		var capturedRequests []GeneratedRequest
		input := &ExecuteRuleInput{
			Callback: func(gr GeneratedRequest) bool {
				capturedRequests = append(capturedRequests, gr)
				return true
			},
			Values: map[string]interface{}{},
		}

		payload := ValueOrKeyValue{Key: "newkey", Value: "newval"}
		err := rule.executePartComponentOnKV(input, payload, comp)
		require.NoError(t, err)
		require.Equal(t, 1, len(capturedRequests))
	})
}

// --- TestMatchKeyOrValue (additional coverage) ---

func TestMatchKeyOrValue_Additional(t *testing.T) {
	t.Run("no-filters-returns-true", func(t *testing.T) {
		rule := &Rule{}
		require.True(t, rule.matchKeyOrValue("anykey", "anyvalue"))
	})

	t.Run("case-insensitive-key-match", func(t *testing.T) {
		rule := &Rule{
			keysMap: map[string]struct{}{"mykey": {}},
		}
		require.True(t, rule.matchKeyOrValue("MyKey", ""))
		require.True(t, rule.matchKeyOrValue("MYKEY", ""))
		require.True(t, rule.matchKeyOrValue("mykey", ""))
		require.False(t, rule.matchKeyOrValue("otherkey", ""))
	})

	t.Run("value-regex-match", func(t *testing.T) {
		rule := &Rule{
			valuesRegex: []*regexp.Regexp{regexp.MustCompile(`^\d+$`)},
		}
		require.True(t, rule.matchKeyOrValue("key", "12345"))
		require.False(t, rule.matchKeyOrValue("key", "abc"))
	})

	t.Run("key-regex-match", func(t *testing.T) {
		rule := &Rule{
			keysRegex: []*regexp.Regexp{regexp.MustCompile(`^url`)},
		}
		require.True(t, rule.matchKeyOrValue("url_param", ""))
		require.True(t, rule.matchKeyOrValue("url", ""))
		require.False(t, rule.matchKeyOrValue("name", ""))
	})

	t.Run("empty-key-with-keysMap-returns-false", func(t *testing.T) {
		rule := &Rule{
			keysMap: map[string]struct{}{"key": {}},
		}
		require.False(t, rule.matchKeyOrValue("", ""))
	})

	t.Run("empty-value-with-valuesRegex-returns-false", func(t *testing.T) {
		rule := &Rule{
			valuesRegex: []*regexp.Regexp{regexp.MustCompile(`something`)},
		}
		require.False(t, rule.matchKeyOrValue("key", ""))
	})

	t.Run("multiple-value-regexes-any-match", func(t *testing.T) {
		rule := &Rule{
			valuesRegex: []*regexp.Regexp{
				regexp.MustCompile(`^https?://`),
				regexp.MustCompile(`^\d+$`),
			},
		}
		require.True(t, rule.matchKeyOrValue("key", "http://example.com"))
		require.True(t, rule.matchKeyOrValue("key", "12345"))
		require.False(t, rule.matchKeyOrValue("key", "plain-text"))
	})
}

// --- TestExecutePartRule ---

func TestExecutePartRule(t *testing.T) {
	opts := newTestExecutorOptions(t)

	t.Run("delegates-value-payload", func(t *testing.T) {
		rule := &Rule{
			ruleType: replaceRuleType,
			modeType: singleModeType,
			options:  opts,
		}

		comp := newQueryComponent(t, "https://example.com?x=1")

		called := false
		input := &ExecuteRuleInput{
			Callback: func(gr GeneratedRequest) bool {
				called = true
				return true
			},
			Values: map[string]interface{}{},
		}

		payload := ValueOrKeyValue{Value: "FUZZ", OriginalPayload: "FUZZ"}
		err := rule.executePartRule(input, payload, comp)
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("delegates-kv-payload", func(t *testing.T) {
		rule := &Rule{
			ruleType: replaceRuleType,
			modeType: singleModeType,
			options:  opts,
		}

		comp := newQueryComponent(t, "https://example.com?x=1")

		called := false
		input := &ExecuteRuleInput{
			Callback: func(gr GeneratedRequest) bool {
				called = true
				return true
			},
			Values: map[string]interface{}{},
		}

		payload := ValueOrKeyValue{Key: "x", Value: "FUZZ"}
		err := rule.executePartRule(input, payload, comp)
		require.NoError(t, err)
		require.True(t, called)
	})
}

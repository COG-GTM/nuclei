package scan

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestNewScanContext(t *testing.T) {
	ctx := context.Background()
	input := &contextargs.Context{}
	sc := NewScanContext(ctx, input)

	require.NotNil(t, sc)
	require.Equal(t, ctx, sc.Context())
	require.Equal(t, input, sc.Input)
}

func TestScanContextLogEventNil(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)
	// should not panic on nil event
	sc.LogEvent(nil)
	require.Empty(t, sc.GenerateResult())
}

func TestScanContextLogEvent(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)

	result := &output.ResultEvent{
		TemplateID: "test-template",
		Host:       "example.com",
	}
	event := &output.InternalWrappedEvent{
		Results: []*output.ResultEvent{result},
	}

	sc.LogEvent(event)

	results := sc.GenerateResult()
	require.Len(t, results, 1)
	require.Equal(t, "test-template", results[0].TemplateID)
}

func TestScanContextLogEventCallback(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)

	var callbackEvent *output.InternalWrappedEvent
	sc.OnResult = func(e *output.InternalWrappedEvent) {
		callbackEvent = e
	}

	event := &output.InternalWrappedEvent{
		Results: []*output.ResultEvent{{TemplateID: "callback-test"}},
	}
	sc.LogEvent(event)

	require.NotNil(t, callbackEvent)
	require.Equal(t, event, callbackEvent)
}

func TestScanContextLogError(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)

	// nil error should be ignored
	sc.LogError(nil)
	require.Nil(t, sc.GenerateErrorMessage())

	// log a real error
	sc.LogError(errors.New("first error"))
	require.Contains(t, sc.GenerateErrorMessage().Error(), "first error")

	// log another error - should append
	sc.LogError(errors.New("second error"))
	errMsg := sc.GenerateErrorMessage().Error()
	require.Contains(t, errMsg, "first error")
	require.Contains(t, errMsg, "second error")
}

func TestScanContextLogErrorCallback(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)

	var callbackErr error
	sc.OnError = func(err error) {
		callbackErr = err
	}

	testErr := errors.New("test error")
	sc.LogError(testErr)

	require.Equal(t, testErr, callbackErr)
}

func TestScanContextLogWarning(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)

	var callbackWarning string
	sc.OnWarning = func(s string) {
		callbackWarning = s
	}

	sc.LogWarning("warning %d: %s", 1, "test")

	require.Equal(t, "warning 1: test", callbackWarning)
}

func TestScanContextConcurrentAccess(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			event := &output.InternalWrappedEvent{
				Results: []*output.ResultEvent{{TemplateID: "concurrent-test"}},
			}
			sc.LogEvent(event)
		}(i)
	}
	wg.Wait()

	results := sc.GenerateResult()
	require.Len(t, results, 50)
}

func TestScanContextGenerateResultEmpty(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)
	results := sc.GenerateResult()
	require.Nil(t, results)
}

func TestScanContextGenerateErrorMessageNil(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)
	require.Nil(t, sc.GenerateErrorMessage())
}

func TestScanContextLogErrorUpdatesResults(t *testing.T) {
	sc := NewScanContext(context.Background(), nil)

	event := &output.InternalWrappedEvent{
		Results: []*output.ResultEvent{{TemplateID: "test"}},
	}
	sc.LogEvent(event)

	sc.LogError(errors.New("some error"))

	results := sc.GenerateResult()
	require.Len(t, results, 1)
	require.Contains(t, results[0].Error, "some error")
}

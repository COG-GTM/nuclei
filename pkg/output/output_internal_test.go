package output

import (
	"maps"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/stretchr/testify/require"
)

func TestInternalEventSet(t *testing.T) {
	ie := InternalEvent{}
	ie.Set("key", "value")
	require.Equal(t, "value", ie["key"])

	ie.Set("key", "updated")
	require.Equal(t, "updated", ie["key"])
}

func TestInternalWrappedEventHasOperatorResult(t *testing.T) {
	iwe := &InternalWrappedEvent{}
	require.False(t, iwe.HasOperatorResult())

	iwe.SetOperatorResult(&operators.Result{})
	require.True(t, iwe.HasOperatorResult())
}

func TestInternalWrappedEventHasResults(t *testing.T) {
	iwe := &InternalWrappedEvent{}
	require.False(t, iwe.HasResults())

	iwe.Results = []*ResultEvent{{TemplateID: "test"}}
	require.True(t, iwe.HasResults())
}

func TestInternalWrappedEventCloneShallow(t *testing.T) {
	original := &InternalWrappedEvent{
		InternalEvent:  InternalEvent{"key": "value"},
		Results:        []*ResultEvent{{TemplateID: "test"}},
		UsesInteractsh: true,
	}
	original.SetOperatorResult(&operators.Result{})

	cloned := original.CloneShallow()

	require.Equal(t, maps.Clone(original.InternalEvent), cloned.InternalEvent)
	require.Nil(t, cloned.Results)
	require.Nil(t, cloned.OperatorsResult)
	require.True(t, cloned.UsesInteractsh)

	// verify shallow independence of InternalEvent
	cloned.InternalEvent["new_key"] = "new_value"
	_, exists := original.InternalEvent["new_key"]
	require.False(t, exists)
}

func TestInternalWrappedEventSetOperatorResult(t *testing.T) {
	iwe := &InternalWrappedEvent{}
	result := &operators.Result{Matched: true}
	iwe.SetOperatorResult(result)

	require.True(t, iwe.HasOperatorResult())
	require.True(t, iwe.OperatorsResult.Matched)
}

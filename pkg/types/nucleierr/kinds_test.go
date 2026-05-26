package nucleierr

import (
	"testing"

	"github.com/projectdiscovery/utils/errkit"
	"github.com/stretchr/testify/require"
)

func TestErrTemplateLogicKind(t *testing.T) {
	require.NotNil(t, ErrTemplateLogic)
}

func TestIsTemplateLogicKindWithTimeoutAnnotation(t *testing.T) {
	err := errkit.New("timeout annotation deadline exceeded").SetKind(ErrTemplateLogic).Build()
	errX, ok := err.(*errkit.ErrorX)
	require.True(t, ok)
	require.True(t, ErrTemplateLogic.Represents(errX))
}

func TestIsTemplateLogicKindWithUnresolvedVariables(t *testing.T) {
	err := errkit.New("stop execution due to unresolved variables").SetKind(ErrTemplateLogic).Build()
	errX, ok := err.(*errkit.ErrorX)
	require.True(t, ok)
	require.True(t, ErrTemplateLogic.Represents(errX))
}

func TestIsTemplateLogicKindWithOtherError(t *testing.T) {
	err := errkit.New("some other error").Build()
	errX, ok := err.(*errkit.ErrorX)
	require.True(t, ok)
	require.False(t, ErrTemplateLogic.Represents(errX))
}

func TestIsTemplateLogicKindWithNil(t *testing.T) {
	require.False(t, isTemplateLogicKind(nil))
}

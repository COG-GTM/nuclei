package types

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewResumeCfg(t *testing.T) {
	cfg := NewResumeCfg()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.ResumeFrom)
	require.NotNil(t, cfg.Current)
	require.Empty(t, cfg.ResumeFrom)
	require.Empty(t, cfg.Current)
}

func TestResumeInfoIsCompleted(t *testing.T) {
	ri := &ResumeInfo{Completed: false}
	require.False(t, ri.IsCompleted())

	ri.Completed = true
	require.True(t, ri.IsCompleted())
}

func TestResumeInfoGetSkipUnder(t *testing.T) {
	ri := &ResumeInfo{SkipUnder: 42}
	require.Equal(t, uint32(42), ri.GetSkipUnder())
}

func TestResumeInfoGetDoAbove(t *testing.T) {
	ri := &ResumeInfo{DoAbove: 100}
	require.Equal(t, uint32(100), ri.GetDoAbove())
}

func TestResumeInfoInitInFlight(t *testing.T) {
	ri := &ResumeInfo{}
	require.Nil(t, ri.InFlight)

	ri.InitInFlight()
	require.NotNil(t, ri.InFlight)
	require.Empty(t, ri.InFlight)

	// calling again should not reset
	ri.InFlight[1] = struct{}{}
	ri.InitInFlight()
	require.Len(t, ri.InFlight, 1)
}

func TestResumeInfoIsInFlight(t *testing.T) {
	ri := &ResumeInfo{
		InFlight: map[uint32]struct{}{5: {}, 10: {}},
	}
	require.True(t, ri.IsInFlight(5))
	require.True(t, ri.IsInFlight(10))
	require.False(t, ri.IsInFlight(1))
}

func TestResumeInfoClone(t *testing.T) {
	original := &ResumeInfo{
		Completed: true,
		InFlight:  map[uint32]struct{}{1: {}, 2: {}},
		SkipUnder: 10,
		Repeat:    map[uint32]struct{}{3: {}},
		DoAbove:   20,
	}

	cloned := original.Clone()
	require.Equal(t, original.Completed, cloned.Completed)
	require.Equal(t, original.SkipUnder, cloned.SkipUnder)
	require.Equal(t, original.DoAbove, cloned.DoAbove)
	require.Equal(t, original.InFlight, cloned.InFlight)
	require.Equal(t, original.Repeat, cloned.Repeat)

	// verify deep copy
	cloned.InFlight[99] = struct{}{}
	require.NotContains(t, original.InFlight, uint32(99))
}

func TestResumeCfgClone(t *testing.T) {
	cfg := NewResumeCfg()
	cfg.ResumeFrom["template1"] = &ResumeInfo{
		Completed: true,
		InFlight:  map[uint32]struct{}{1: {}},
		Repeat:    map[uint32]struct{}{},
	}
	cfg.Current["template2"] = &ResumeInfo{
		Completed: false,
		InFlight:  map[uint32]struct{}{2: {}},
		Repeat:    map[uint32]struct{}{},
	}

	cloned := cfg.Clone()
	require.Len(t, cloned.ResumeFrom, 1)
	require.Len(t, cloned.Current, 1)
	require.True(t, cloned.ResumeFrom["template1"].Completed)
	require.False(t, cloned.Current["template2"].Completed)

	// verify deep copy
	cloned.ResumeFrom["template1"].Completed = false
	require.True(t, cfg.ResumeFrom["template1"].Completed)
}

func TestResumeCfgCompile(t *testing.T) {
	cfg := NewResumeCfg()

	// completed template with leftover in-flight should be cleaned
	cfg.ResumeFrom["completed"] = &ResumeInfo{
		Completed: true,
		InFlight:  map[uint32]struct{}{5: {}, 10: {}},
	}

	// uncompleted template with in-flight should compute SkipUnder/DoAbove
	cfg.ResumeFrom["partial"] = &ResumeInfo{
		Completed: false,
		InFlight:  map[uint32]struct{}{3: {}, 7: {}, 15: {}},
	}

	cfg.Compile()

	// completed: InFlight should be cleared
	require.Empty(t, cfg.ResumeFrom["completed"].InFlight)

	// partial: SkipUnder=3 (min), DoAbove=15 (max), Repeat contains all in-flight
	require.Equal(t, uint32(3), cfg.ResumeFrom["partial"].SkipUnder)
	require.Equal(t, uint32(15), cfg.ResumeFrom["partial"].DoAbove)
	require.Contains(t, cfg.ResumeFrom["partial"].Repeat, uint32(3))
	require.Contains(t, cfg.ResumeFrom["partial"].Repeat, uint32(7))
	require.Contains(t, cfg.ResumeFrom["partial"].Repeat, uint32(15))
}

func TestResumeCfgCompileEmpty(t *testing.T) {
	cfg := NewResumeCfg()
	cfg.ResumeFrom["empty"] = &ResumeInfo{
		Completed: false,
		InFlight:  map[uint32]struct{}{},
	}

	cfg.Compile()

	require.Equal(t, uint32(math.MaxUint32), cfg.ResumeFrom["empty"].SkipUnder)
	require.Equal(t, uint32(0), cfg.ResumeFrom["empty"].DoAbove)
}

package builtin

import (
	"testing"

	"github.com/Mzack9999/goja"
	"github.com/stretchr/testify/require"
)

func TestNewDedupe(t *testing.T) {
	vm := goja.New()
	d := NewDedupe(vm)
	require.NotNil(t, d)
	require.NotNil(t, d.m)
	require.Equal(t, vm, d.VM)
}

func TestDedupeAddAndValues(t *testing.T) {
	vm := goja.New()
	d := NewDedupe(vm)

	call := goja.FunctionCall{
		Arguments: []goja.Value{
			vm.ToValue("hello"),
			vm.ToValue("world"),
		},
	}

	result := d.Add(call)
	require.Equal(t, true, result.Export())

	values := d.Values(goja.FunctionCall{})
	exported := values.Export()
	arr, ok := exported.([]goja.Value)
	require.True(t, ok)
	require.Len(t, arr, 2)
}

func TestDedupeAddDuplicates(t *testing.T) {
	vm := goja.New()
	d := NewDedupe(vm)

	call := goja.FunctionCall{
		Arguments: []goja.Value{
			vm.ToValue("same"),
			vm.ToValue("same"),
			vm.ToValue("same"),
		},
	}

	d.Add(call)

	values := d.Values(goja.FunctionCall{})
	exported := values.Export()
	arr, ok := exported.([]goja.Value)
	require.True(t, ok)
	require.Len(t, arr, 1)
}

func TestDedupeAddSlice(t *testing.T) {
	vm := goja.New()
	d := NewDedupe(vm)

	call := goja.FunctionCall{
		Arguments: []goja.Value{
			vm.ToValue([]string{"a", "b", "c"}),
		},
	}

	d.Add(call)

	values := d.Values(goja.FunctionCall{})
	exported := values.Export()
	arr, ok := exported.([]goja.Value)
	require.True(t, ok)
	require.Len(t, arr, 3)
}

func TestDedupeAddSliceWithDuplicates(t *testing.T) {
	vm := goja.New()
	d := NewDedupe(vm)

	call := goja.FunctionCall{
		Arguments: []goja.Value{
			vm.ToValue([]string{"x", "y", "x"}),
		},
	}

	d.Add(call)

	values := d.Values(goja.FunctionCall{})
	exported := values.Export()
	arr, ok := exported.([]goja.Value)
	require.True(t, ok)
	require.Len(t, arr, 2)
}

func TestDedupeAddNilArgument(t *testing.T) {
	vm := goja.New()
	d := NewDedupe(vm)

	call := goja.FunctionCall{
		Arguments: []goja.Value{
			goja.Null(),
			vm.ToValue("valid"),
		},
	}

	d.Add(call)

	values := d.Values(goja.FunctionCall{})
	exported := values.Export()
	arr, ok := exported.([]goja.Value)
	require.True(t, ok)
	require.Len(t, arr, 1)
}

func TestDedupeMultipleAddCalls(t *testing.T) {
	vm := goja.New()
	d := NewDedupe(vm)

	d.Add(goja.FunctionCall{Arguments: []goja.Value{vm.ToValue("a")}})
	d.Add(goja.FunctionCall{Arguments: []goja.Value{vm.ToValue("b")}})
	d.Add(goja.FunctionCall{Arguments: []goja.Value{vm.ToValue("a")}})

	values := d.Values(goja.FunctionCall{})
	arr := values.Export().([]goja.Value)
	require.Len(t, arr, 2)
}

func TestHashValueDeterministic(t *testing.T) {
	hash1 := hashValue("test")
	hash2 := hashValue("test")
	require.Equal(t, hash1, hash2)
}

func TestHashValueDifferentInputs(t *testing.T) {
	hash1 := hashValue("test1")
	hash2 := hashValue("test2")
	require.NotEqual(t, hash1, hash2)
}

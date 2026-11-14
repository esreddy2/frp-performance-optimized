package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandId(t *testing.T) {
	require := require.New(t)
	id, err := RandID()
	require.NoError(err)
	t.Log(id)
	require.Equal(16, len(id))
}

func TestGetAuthKey(t *testing.T) {
	require := require.New(t)
	key := GetAuthKey("1234", 1488720000)
	require.Equal("6df41a43725f0c770fd56379e12acf8c", key)
}

func TestParseRangeNumbers(t *testing.T) {
	require := require.New(t)
	numbers, err := ParseRangeNumbers("2-5")
	require.NoError(err)
	require.Equal([]int64{2, 3, 4, 5}, numbers)

	numbers, err = ParseRangeNumbers("1")
	require.NoError(err)
	require.Equal([]int64{1}, numbers)

	numbers, err = ParseRangeNumbers("3-5,8")
	require.NoError(err)
	require.Equal([]int64{3, 4, 5, 8}, numbers)

	numbers, err = ParseRangeNumbers(" 3-5,8, 10-12 ")
	require.NoError(err)
	require.Equal([]int64{3, 4, 5, 8, 10, 11, 12}, numbers)

	_, err = ParseRangeNumbers("3-a")
	require.Error(err)

	// Inverted range
	_, err = ParseRangeNumbers("5-2")
	require.Error(err)

	// Negative numbers
	_, err = ParseRangeNumbers("-1")
	require.Error(err)

	// Range span exceeding maximum 65535
	_, err = ParseRangeNumbers("1-1000000000")
	require.Error(err)

	_, err = ParseRangeNumbers("0-65535")
	require.Error(err)

	// Valid span (< 65535)
	numbers, err = ParseRangeNumbers("1-65535")
	require.NoError(err)
	require.Equal(65535, len(numbers))
	require.Equal(int64(1), numbers[0])
	require.Equal(int64(65535), numbers[65534])
}

func TestClonePtr(t *testing.T) {
	require := require.New(t)

	var nilInt *int
	require.Nil(ClonePtr(nilInt))

	v := 42
	cloned := ClonePtr(&v)
	require.NotNil(cloned)
	require.Equal(v, *cloned)
	require.NotSame(&v, cloned)
}

// Copyright 2019 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type Wrap struct {
	B   BandwidthQuantity `json:"b"`
	Int int               `json:"int"`
}

func TestBandwidthQuantity(t *testing.T) {
	require := require.New(t)

	var w Wrap
	err := json.Unmarshal([]byte(`{"b":"1KB","int":5}`), &w)
	require.NoError(err)
	require.EqualValues(1*KB, w.B.Bytes())

	buf, err := json.Marshal(&w)
	require.NoError(err)
	require.Equal(`{"b":"1KB","int":5}`, string(buf))
}

func TestBandwidthQuantity_MB(t *testing.T) {
	require := require.New(t)

	var w Wrap
	err := json.Unmarshal([]byte(`{"b":"2MB","int":1}`), &w)
	require.NoError(err)
	require.EqualValues(2*MB, w.B.Bytes())

	buf, err := json.Marshal(&w)
	require.NoError(err)
	require.Equal(`{"b":"2MB","int":1}`, string(buf))
}

func TestBandwidthQuantity_InvalidUnit(t *testing.T) {
	var w Wrap
	err := json.Unmarshal([]byte(`{"b":"1GB","int":1}`), &w)
	require.Error(t, err)
}

func TestBandwidthQuantity_InvalidNumber(t *testing.T) {
	var w Wrap
	err := json.Unmarshal([]byte(`{"b":"abcKB","int":1}`), &w)
	require.Error(t, err)
}

func TestPortsRangeSlice2String(t *testing.T) {
	require := require.New(t)

	require.Equal("", PortsRangeSlice(nil).String())
	require.Equal("", PortsRangeSlice{}.String())

	ports := []PortsRange{
		{
			Start: 1000,
			End:   2000,
		},
		{
			Single: 3000,
		},
	}
	str := PortsRangeSlice(ports).String()
	require.Equal("1000-2000,3000", str)
}

func TestNewPortsRangeSliceFromString(t *testing.T) {
	require := require.New(t)

	ports, err := NewPortsRangeSliceFromString("1000-2000,3000")
	require.NoError(err)
	require.Equal([]PortsRange{
		{
			Start: 1000,
			End:   2000,
		},
		{
			Single: 3000,
		},
	}, ports)

	// Invalid range strings must fail
	for _, invalid := range []string{
		"",
		"abc",
		"1000-abc",
		"abc-2000",
		"2000-1000",
		"1000-2000-3000",
		"1000,",
		"0",
		"-1",
		"65536",
		"70000",
		"0-100",
		"100-70000",
		"-100-200",
	} {
		_, err := NewPortsRangeSliceFromString(invalid)
		require.Error(err, "expected error for input %q", invalid)
	}
}

func TestBandwidthQuantityContract(t *testing.T) {
	require := require.New(t)

	// 1. NewBandwidthQuantity valid and invalid
	q1, err := NewBandwidthQuantity("1MB")
	require.NoError(err)
	require.Equal("1MB", q1.String())
	require.Equal(int64(MB), q1.Bytes())

	q2, err := NewBandwidthQuantity("1024KB")
	require.NoError(err)
	require.Equal("1024KB", q2.String())
	require.Equal(int64(1024*KB), q2.Bytes())

	// 2. Equal checks byte equivalence and nil handling
	require.True(q1.Equal(&q2))
	var nilQ *BandwidthQuantity
	require.True(nilQ.Equal(nil))
	require.False(q1.Equal(nil))
	require.False(nilQ.Equal(&q1))

	q3, err := NewBandwidthQuantity("512KB")
	require.NoError(err)
	require.False(q1.Equal(&q3))

	// 3. Empty string resets quantity to 0
	qReset := q1
	require.NoError(qReset.UnmarshalString("   "))
	require.Equal("", qReset.String())
	require.Equal(int64(0), qReset.Bytes())

	// 4. Negative, NaN, Inf, int64-overflowing values, and non-string JSON are rejected
	for _, bad := range []string{"-1KB", "-5MB", "NaNKB", "InfMB", "-InfKB", "1e15MB", "10000000000000000KB", "100B"} {
		_, err := NewBandwidthQuantity(bad)
		require.Error(err, "expected error for %q", bad)
	}

	var qJSON BandwidthQuantity
	require.NoError(qJSON.UnmarshalJSON([]byte("null")))
	require.Error(qJSON.UnmarshalJSON([]byte("12345")))
}

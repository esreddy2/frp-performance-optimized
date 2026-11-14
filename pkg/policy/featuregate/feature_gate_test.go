// Copyright 2026 The frp Authors
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

package featuregate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFeatureGateLifecycleAndInvariants(t *testing.T) {
	fg := NewFeatureGate()

	// VirtualNet is registered as Alpha and disabled by default.
	require.False(t, fg.Enabled(VirtualNet))
	require.False(t, fg.Enabled(Feature("NonExistentFeature")))
	require.Equal(t, "", fg.String())
	require.Equal(t, []string{"VirtualNet=true|false (ALPHA - default=false)"}, fg.KnownFeatures())

	// Add custom Alpha, Beta, and GA features, including a LockToDefault feature.
	const (
		alphaFeat  = Feature("CustomAlpha")
		betaFeat   = Feature("CustomBeta")
		gaFeat     = Feature("CustomGA")
		lockedFeat = Feature("LockedGA")
	)
	err := fg.Add(map[Feature]FeatureSpec{
		alphaFeat:  {Default: false, Stage: Alpha},
		betaFeat:   {Default: true, Stage: Beta},
		gaFeat:     {Default: true, Stage: GA},
		lockedFeat: {Default: true, LockToDefault: true, Stage: GA},
	})
	require.NoError(t, err)

	// Re-adding identical spec is idempotent; conflicting spec returns an error.
	require.NoError(t, fg.Add(map[Feature]FeatureSpec{
		alphaFeat: {Default: false, Stage: Alpha},
	}))
	require.ErrorContains(t, fg.Add(map[Feature]FeatureSpec{
		alphaFeat: {Default: true, Stage: Alpha},
	}), "different spec already exists")

	// Verify defaults before SetFromMap.
	require.False(t, fg.Enabled(alphaFeat))
	require.True(t, fg.Enabled(betaFeat))
	require.True(t, fg.Enabled(gaFeat))
	require.True(t, fg.Enabled(lockedFeat))

	// GA features are hidden from KnownFeatures; Alpha and Beta are sorted.
	require.Equal(t, []string{
		"CustomAlpha=true|false (ALPHA - default=false)",
		"CustomBeta=true|false (BETA - default=true)",
		"VirtualNet=true|false (ALPHA - default=false)",
	}, fg.KnownFeatures())

	// Enabling/disabling unlocked features via SetFromMap.
	require.NoError(t, fg.SetFromMap(map[string]bool{
		string(alphaFeat):  true,
		string(betaFeat):   false,
		string(lockedFeat): true, // matches default, allowed
	}))
	require.True(t, fg.Enabled(alphaFeat))
	require.False(t, fg.Enabled(betaFeat))
	require.Equal(t, "CustomAlpha=true,CustomBeta=false,LockedGA=true", fg.String())

	// Unrecognized feature gate returns an error and does not mutate existing state.
	require.ErrorContains(t, fg.SetFromMap(map[string]bool{
		"UnknownFeature": true,
	}), "unrecognized feature gate")

	// Locked feature gate rejects changes away from its default.
	require.ErrorContains(t, fg.SetFromMap(map[string]bool{
		string(lockedFeat): false,
	}), "feature is locked to true")
	require.True(t, fg.Enabled(lockedFeat))

	// Closed/Frozen featureGate rejects new Add and SetFromMap calls.
	fg.Close()
	require.ErrorContains(t, fg.Add(map[Feature]FeatureSpec{
		Feature("AfterClose"): {Default: false, Stage: Alpha},
	}), "closed")
	require.ErrorContains(t, fg.SetFromMap(map[string]bool{
		string(alphaFeat): false,
	}), "closed")

	fg2 := NewFeatureGate()
	fg2.Freeze()
	require.ErrorContains(t, fg2.SetFromMap(map[string]bool{
		string(VirtualNet): true,
	}), "closed")
}

func TestDefaultFeatureGatesHelpers(t *testing.T) {
	orig := DefaultFeatureGates
	DefaultFeatureGates = NewFeatureGate()
	t.Cleanup(func() {
		DefaultFeatureGates = orig
	})

	require.False(t, Enabled(VirtualNet))
	require.NoError(t, SetFromMap(map[string]bool{string(VirtualNet): true}))
	require.True(t, Enabled(VirtualNet))
}

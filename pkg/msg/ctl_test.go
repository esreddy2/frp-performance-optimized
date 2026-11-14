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

package msg

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

type unregisteredTestMsg struct{}

func TestReadMsgIntoTypeValidation(t *testing.T) {
	t.Run("rejects type confusion", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteMsg(&buf, &Ping{PrivilegeKey: "k", Timestamp: 123}))

		var target Pong
		err := ReadMsgInto(&buf, &target)
		require.ErrorContains(t, err, "unexpected message type")
	})

	t.Run("accepts matching target", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteMsg(&buf, &Ping{PrivilegeKey: "k", Timestamp: 123}))

		var target Ping
		require.NoError(t, ReadMsgInto(&buf, &target))
		require.Equal(t, Ping{PrivilegeKey: "k", Timestamp: 123}, target)
	})

	t.Run("rejects invalid targets", func(t *testing.T) {
		var buf bytes.Buffer
		require.ErrorContains(t, ReadMsgInto(&buf, nil), "non-nil pointer")
		require.ErrorContains(t, ReadMsgInto(&buf, Pong{}), "non-nil pointer")

		var nilPong *Pong
		require.ErrorContains(t, ReadMsgInto(&buf, nilPong), "non-nil pointer")
		require.ErrorContains(t, ReadMsgInto(&buf, &unregisteredTestMsg{}), "unknown message type")
	})
}

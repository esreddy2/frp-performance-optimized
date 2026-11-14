// Copyright 2018 fatedier, fatedier@gmail.com
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
	"fmt"
	"io"
	"reflect"

	jsonMsg "github.com/fatedier/golib/msg/json"
)

type Message = jsonMsg.Message

var (
	msgCtl     *jsonMsg.MsgCtl
	msgTypeSet = make(map[reflect.Type]struct{})
)

func init() {
	msgCtl = jsonMsg.NewMsgCtl()
	for typeByte, msg := range msgTypeMap {
		msgCtl.RegisterMsg(typeByte, msg)
		msgTypeSet[reflect.TypeOf(msg)] = struct{}{}
	}
}

func ReadMsg(c io.Reader) (msg Message, err error) {
	return msgCtl.ReadMsg(c)
}

func ReadMsgInto(c io.Reader, msg Message) (err error) {
	if msg == nil {
		return fmt.Errorf("message target must be a non-nil pointer")
	}
	outVal := reflect.ValueOf(msg)
	if outVal.Kind() != reflect.Pointer || outVal.IsNil() {
		return fmt.Errorf("message target must be a non-nil pointer")
	}
	elemType := outVal.Elem().Type()
	if _, ok := msgTypeSet[elemType]; !ok {
		return fmt.Errorf("unknown message type %s", elemType.String())
	}

	m, err := msgCtl.ReadMsg(c)
	if err != nil {
		return err
	}
	if reflect.TypeOf(m) != outVal.Type() {
		return fmt.Errorf("unexpected message type %T, want %T", m, msg)
	}
	outVal.Elem().Set(reflect.ValueOf(m).Elem())
	return nil
}

func WriteMsg(c io.Writer, msg any) (err error) {
	return msgCtl.WriteMsg(c, msg)
}

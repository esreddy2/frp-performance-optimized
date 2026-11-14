// Copyright 2020 guylewin, guy@lewin.co.il
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

package auth

import (
	"crypto/subtle"
	"fmt"
	"slices"
	"sync"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

const defaultAuthTimeout = 15 * time.Minute

type TokenAuthSetterVerifier struct {
	additionalAuthScopes []v1.AuthScope
	token                string
	now                  func() time.Time

	mu         sync.Mutex
	seenTokens map[string]int64
}

func NewTokenAuth(additionalAuthScopes []v1.AuthScope, token string) *TokenAuthSetterVerifier {
	return &TokenAuthSetterVerifier{
		additionalAuthScopes: additionalAuthScopes,
		token:                token,
		now:                  time.Now,
		seenTokens:           make(map[string]int64),
	}
}

func (auth *TokenAuthSetterVerifier) currentTime() time.Time {
	if auth.now != nil {
		return auth.now()
	}
	return time.Now()
}

func (auth *TokenAuthSetterVerifier) verifyTimestamp(timestamp int64) error {
	now := auth.currentTime().Unix()
	maxSkew := int64(defaultAuthTimeout.Seconds())
	if timestamp <= 0 || timestamp < now-maxSkew || timestamp > now+maxSkew {
		return fmt.Errorf("authentication timestamp expired or out of window")
	}
	return nil
}

func (auth *TokenAuthSetterVerifier) checkAndRecordReplay(key string, allowConcurrentSec bool) error {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	now := auth.currentTime().Unix()
	maxSkew := int64(defaultAuthTimeout.Seconds())

	// Periodically prune stale entries outside the allowable skew window.
	if len(auth.seenTokens) > 1000 {
		for k, seenAt := range auth.seenTokens {
			if seenAt < now-maxSkew || seenAt > now+maxSkew {
				delete(auth.seenTokens, k)
			}
		}
	}

	if seenAt, exists := auth.seenTokens[key]; exists {
		if !allowConcurrentSec || now > seenAt+1 {
			return fmt.Errorf("token replay detected: authentication message has already been processed")
		}
	} else {
		if auth.seenTokens == nil {
			auth.seenTokens = make(map[string]int64)
		}
		auth.seenTokens[key] = now
	}
	return nil
}

func (auth *TokenAuthSetterVerifier) SetLogin(loginMsg *msg.Login) error {
	if loginMsg == nil {
		return fmt.Errorf("login message is nil")
	}
	if loginMsg.Timestamp == 0 {
		loginMsg.Timestamp = auth.currentTime().Unix()
	}
	loginMsg.PrivilegeKey = util.GetAuthKey(auth.token, loginMsg.Timestamp)
	return nil
}

func (auth *TokenAuthSetterVerifier) SetPing(pingMsg *msg.Ping) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}
	if pingMsg == nil {
		return fmt.Errorf("ping message is nil")
	}

	pingMsg.Timestamp = auth.currentTime().Unix()
	pingMsg.PrivilegeKey = util.GetAuthKey(auth.token, pingMsg.Timestamp)
	return nil
}

func (auth *TokenAuthSetterVerifier) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}
	if newWorkConnMsg == nil {
		return fmt.Errorf("newWorkConn message is nil")
	}

	newWorkConnMsg.Timestamp = auth.currentTime().Unix()
	newWorkConnMsg.PrivilegeKey = util.GetAuthKey(auth.token, newWorkConnMsg.Timestamp)
	return nil
}

func (auth *TokenAuthSetterVerifier) VerifyLogin(m *msg.Login) error {
	if m == nil {
		return fmt.Errorf("login message is nil")
	}
	if err := auth.verifyTimestamp(m.Timestamp); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(util.GetAuthKey(auth.token, m.Timestamp)), []byte(m.PrivilegeKey)) != 1 {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}
	key := fmt.Sprintf("login:%d:%s", m.Timestamp, m.PrivilegeKey)
	return auth.checkAndRecordReplay(key, true)
}

func (auth *TokenAuthSetterVerifier) VerifyPing(m *msg.Ping) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}
	if m == nil {
		return fmt.Errorf("ping message is nil")
	}

	if err := auth.verifyTimestamp(m.Timestamp); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(util.GetAuthKey(auth.token, m.Timestamp)), []byte(m.PrivilegeKey)) != 1 {
		return fmt.Errorf("token in heartbeat doesn't match token from configuration")
	}
	key := fmt.Sprintf("ping:%d:%s", m.Timestamp, m.PrivilegeKey)
	return auth.checkAndRecordReplay(key, true)
}

func (auth *TokenAuthSetterVerifier) VerifyNewWorkConn(m *msg.NewWorkConn) error {
	if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}
	if m == nil {
		return fmt.Errorf("newWorkConn message is nil")
	}

	if err := auth.verifyTimestamp(m.Timestamp); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(util.GetAuthKey(auth.token, m.Timestamp)), []byte(m.PrivilegeKey)) != 1 {
		return fmt.Errorf("token in NewWorkConn doesn't match token from configuration")
	}
	key := fmt.Sprintf("workconn:%d:%s", m.Timestamp, m.PrivilegeKey)
	return auth.checkAndRecordReplay(key, true)
}

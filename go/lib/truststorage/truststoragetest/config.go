// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package truststoragetest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
)

func InitTestConfig(cfg *truststorage.TrustDBConf) {
	if *cfg == nil {
		*cfg = make(truststorage.TrustDBConf)
	}
	(*cfg)[db.MaxOpenConnsKey] = "maxOpenConns"
	(*cfg)[db.MaxIdleConnsKey] = "maxIdleConns"
}

func CheckTestConfig(t *testing.T, cfg *truststorage.TrustDBConf, id string) {
	util.LowerKeys(*cfg)
	assert.False(t, isSet(cfg.MaxOpenConns()))
	assert.False(t, isSet(cfg.MaxIdleConns()))
	assert.Equal(t, truststorage.BackendSqlite, cfg.Backend())
	assert.Equal(t, fmt.Sprintf("/var/lib/scion/spki/%s.trust.db", id), cfg.Connection())
}

func isSet(_ int, set bool) bool {
	return set
}

// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firestoreevents

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/events/test"
	"github.com/gravitational/teleport/lib/utils"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

type firestoreContext struct {
	log   *Log
	suite test.EventsSuite
}

func setupFirestoreContext(t *testing.T) *firestoreContext {
	if !emulatorRunning() {
		t.Skip("Firestore emulator is not running, start it with: gcloud beta emulators firestore start --host-port=localhost:8618")
	}

	fakeClock := clockwork.NewFakeClock()

	config := EventsConfig{}
	config.SetFromParams(map[string]interface{}{
		"collection_name":                   "tp-events-test",
		"project_id":                        "tp-testproj",
		"endpoint":                          "localhost:8618",
		"purgeExpiredDocumentsPollInterval": time.Second,
	})

	config.Clock = fakeClock
	config.UIDGenerator = utils.NewFakeUID()

	log, err := New(config)
	require.NoError(t, err)

	return &firestoreContext{
		log: log,
		suite: test.EventsSuite{
			Log:        log,
			Clock:      fakeClock,
			QueryDelay: time.Second * 5,
		},
	}
}

func (tt *firestoreContext) Close() error {
	if tt.log != nil {
		if err := tt.log.Close(); err != nil {
			return tt.log.Close()
		}
	}

	return nil
}

func (tt *firestoreContext) Cleanup(t *testing.T) {
	ctx := context.Background()

	// Delete all documents.
	docSnaps, err := tt.log.svc.Collection(tt.log.CollectionName).Documents(ctx).GetAll()
	require.NoError(t, err)
	if len(docSnaps) == 0 {
		return
	}
	batch := tt.log.svc.Batch()
	for _, docSnap := range docSnaps {
		batch.Delete(docSnap.Ref)
	}
	_, err = batch.Commit(ctx)
	require.NoError(t, err)
}

func TestSessionEventsCRUD(t *testing.T) {
	tt := setupFirestoreContext(t)
	t.Cleanup(func() {
		tt.Cleanup(t)
		tt.Close()
	})

	tt.suite.SessionEventsCRUD(t)
}

func TestPagination(t *testing.T) {
	tt := setupFirestoreContext(t)
	t.Cleanup(func() {
		tt.Cleanup(t)
		tt.Close()
	})

	tt.suite.EventPagination(t)
}

func TestSearchSessionEvensBySessionID(t *testing.T) {
	tt := setupFirestoreContext(t)
	t.Cleanup(func() {
		tt.Cleanup(t)
		tt.Close()
	})

	tt.suite.SearchSessionEvensBySessionID(t)
}

func emulatorRunning() bool {
	con, err := net.Dial("tcp", "localhost:8618")
	if err != nil {
		return false
	}
	con.Close()
	return true
}

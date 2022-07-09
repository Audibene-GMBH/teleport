/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"os"
	"testing"

	"github.com/gravitational/trace"

	"github.com/stretchr/testify/require"
)

func TestRejectsInvalidPEMData(t *testing.T) {
	t.Parallel()

	_, err := ReadCertificateChain([]byte("no data"))
	require.IsType(t, trace.Unwrap(err), &trace.NotFoundError{})
}

func TestRejectsSelfSignedCertificate(t *testing.T) {
	t.Parallel()

	certificateChainBytes, err := os.ReadFile("../../fixtures/certs/ca.pem")
	require.NoError(t, err)

	certificateChain, err := ReadCertificateChain(certificateChainBytes)
	require.NoError(t, err)

	err = VerifyCertificateChain(certificateChain)
	require.ErrorContains(t, err, "certificate is not standards compliant")
}

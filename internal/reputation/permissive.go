// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation

import "context"

// Permissive is a Policy implementation that always allows every send and
// ignores all feedback.  It is the default for standalone self-hosted
// deployments that have no external reputation backend.
type Permissive struct{}

// CheckSend always returns an allow Decision with no restrictions.
func (Permissive) CheckSend(_ context.Context, _ string, _ Message) (Decision, error) {
	return Decision{Allow: true, Reason: "permissive policy"}, nil
}

// RecordResult is a no-op; the permissive policy does not track outcomes.
func (Permissive) RecordResult(_ context.Context, _ string, _ SendResult) error {
	return nil
}

var _ Policy = Permissive{}

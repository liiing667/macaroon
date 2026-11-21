package macaroon_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"

	"gopkg.in/macaroon.v2"
)

func localThirdPartyBudgetChain(depth, cancelAt int) []macaroonSpec {
	specs := make([]macaroonSpec, depth+1)
	for i := 0; i <= depth; i++ {
		spec := macaroonSpec{
			rootKey:  fmt.Sprintf("budget-root-key-%d", i),
			id:       fmt.Sprintf("budget-id-%d", i),
			location: fmt.Sprintf("budget-location-%d", i),
		}
		if i == cancelAt {
			spec.caveats = append(spec.caveats, caveat{condition: "cancel"})
		}
		if i == depth {
			spec.caveats = append(spec.caveats, caveat{condition: "ok"})
		} else {
			spec.caveats = append(spec.caveats, caveat{
				condition: fmt.Sprintf("budget-id-%d", i+1),
				location:  fmt.Sprintf("budget-location-%d", i+1),
				rootKey:   fmt.Sprintf("budget-root-key-%d", i+1),
			})
		}
		specs[i] = spec
	}
	return specs
}

func TestVerificationBudgetTraceAndRecovery(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons(localThirdPartyBudgetChain(4, -1))

	traces, err := macaroons[0].TraceVerifyWithOptions(
		rootKey,
		macaroons[1:],
		macaroon.WithMaxDischarges(2),
		macaroon.WithMaxDischargeDepth(16),
	)
	c.Assert(err, qt.ErrorMatches, `.*verification budget exceeded.*`)
	c.Assert(errors.Is(err, macaroon.ErrVerificationBudgetExceeded), qt.Equals, true)
	c.Assert(strings.Contains(err.Error(), "limit=2"), qt.Equals, true)
	c.Assert(traces, qt.HasLen, len(macaroons))
	c.Assert(traces[0].BudgetLimit, qt.Equals, 2)
	c.Assert(traces[0].BudgetCap, qt.Equals, 2)
	c.Assert(traces[0].Budget, qt.Equals, 2)
	c.Assert(traces[0].BudgetUsed, qt.Equals, len(macaroons)-1)
	c.Assert(traces[0].RequestedDischarges, qt.Equals, len(macaroons)-1)
	c.Assert(traces[0].TerminationReason, qt.Equals, macaroon.TerminationDischargeBudget)
	c.Assert(traces[0].VisitedNodes, qt.DeepEquals, []string{"budget-id-0"})
	c.Assert(traces[0].VisitedNodes[0], qt.Equals, "budget-id-0")
	c.Assert(strings.Contains(traces[0].FailureLocation, "admission"), qt.Equals, true)
	c.Assert(strings.Contains(traces[0].FailureLocation, "macaroon["), qt.Equals, true)
	c.Assert(traces[0].Ops[len(traces[0].Ops)-1].Kind, qt.Equals, macaroon.TraceFail)
	c.Assert(traces[0].Ops[len(traces[0].Ops)-1].Location, qt.Equals, traces[0].FailureLocation)

	// Reconstruct the graph exactly as a restarted process would. The budget
	// generation and its exhausted state must still be the same.
	data, err := macaroons.MarshalBinary()
	c.Assert(err, qt.IsNil)
	var restarted macaroon.Slice
	c.Assert(restarted.UnmarshalBinary(data), qt.IsNil)
	retryTraces, err := restarted[0].TraceVerifyWithOptions(
		rootKey,
		restarted[1:],
		macaroon.WithMaxDischarges(100),
	)
	c.Assert(errors.Is(err, macaroon.ErrVerificationBudgetExceeded), qt.Equals, true)
	c.Assert(retryTraces[0].BudgetLimit, qt.Equals, 2)
	c.Assert(retryTraces[0].BudgetUsed, qt.Equals, traces[0].BudgetUsed)
	c.Assert(retryTraces[0].BudgetGeneration, qt.Equals, traces[0].BudgetGeneration)
	c.Assert(retryTraces[0].TerminationReason, qt.Equals, macaroon.TerminationDischargeBudget)
}

func TestVerificationBudgetCancellationPersists(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons(localThirdPartyBudgetChain(4, 1))
	ctx, cancel := context.WithCancel(context.Background())
	cancelled := false
	check := func(cav string) error {
		if cav == "cancel" && !cancelled {
			cancelled = true
			cancel()
		}
		return nil
	}
	err := macaroons[0].VerifyContextWithOptions(
		ctx,
		rootKey,
		check,
		macaroons[1:],
		macaroon.WithMaxDischarges(4),
		macaroon.WithMaxDischargeDepth(16),
	)
	c.Assert(errors.Is(err, context.Canceled), qt.Equals, true)
	c.Assert(cancelled, qt.Equals, true)

	// Retrying after a cancellation must not give the graph a fresh budget.
	traces, err := macaroons[0].TraceVerifyWithOptions(
		rootKey,
		macaroons[1:],
		macaroon.WithMaxDischarges(100),
	)
	c.Assert(errors.Is(err, macaroon.ErrVerificationBudgetExceeded), qt.Equals, true)
	c.Assert(traces[0].BudgetLimit, qt.Equals, 4)
	c.Assert(traces[0].BudgetUsed > 1, qt.Equals, true)
	c.Assert(traces[0].TerminationReason, qt.Equals, macaroon.TerminationDischargeBudget)
}

func TestTraceVerifyCancellationEvidence(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons(localThirdPartyBudgetChain(2, -1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	traces, err := macaroons[0].TraceVerifyContext(ctx, rootKey, macaroons[1:])
	c.Assert(errors.Is(err, context.Canceled), qt.Equals, true)
	c.Assert(traces[0].BudgetLimit, qt.Equals, macaroon.DefaultMaxDischarges)
	c.Assert(traces[0].TerminationReason, qt.Equals, macaroon.TerminationCancelled)
	c.Assert(traces[0].FailureLocation != "", qt.Equals, true)
	c.Assert(traces[0].Ops[len(traces[0].Ops)-1].Kind, qt.Equals, macaroon.TraceFail)
}

func TestVerificationDepthBudgetEvidence(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons(localThirdPartyBudgetChain(4, -1))
	traces, err := macaroons[0].TraceVerifyWithOptions(
		rootKey,
		macaroons[1:],
		macaroon.WithMaxDischarges(10),
		macaroon.WithMaxDischargeDepth(1),
	)
	c.Assert(errors.Is(err, macaroon.ErrMaxDischargeDepthExceeded), qt.Equals, true)
	c.Assert(errors.Is(err, macaroon.ErrVerificationBudgetExceeded), qt.Equals, true)
	c.Assert(traces[0].MaxDepth, qt.Equals, 1)
	c.Assert(traces[0].MaxDepthSeen, qt.Equals, 2)
	c.Assert(traces[0].TerminationReason, qt.Equals, macaroon.TerminationDepthBudget)
	c.Assert(strings.Contains(traces[0].FailureLocation, "caveat["), qt.Equals, true)
	c.Assert(traces[0].VisitedNodes, qt.DeepEquals, []string{
		"budget-id-0",
		"budget-id-1",
	})
}

func TestVerificationBudgetSuccessfulChainEvidence(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons(localThirdPartyBudgetChain(3, -1))
	traces, err := macaroons[0].TraceVerify(rootKey, macaroons[1:])
	c.Assert(err, qt.IsNil)
	c.Assert(traces, qt.HasLen, len(macaroons))
	for i := range traces {
		c.Assert(traces[i].BudgetLimit, qt.Equals, macaroon.DefaultMaxDischarges)
		c.Assert(traces[i].TerminationReason, qt.Equals, macaroon.TerminationVerified)
		c.Assert(traces[i].VisitedNodes, qt.DeepEquals, []string{
			"budget-id-0",
			"budget-id-1",
			"budget-id-2",
			"budget-id-3",
		})
	}
}

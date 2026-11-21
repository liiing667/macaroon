package macaroon_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	qt "github.com/frankban/quicktest"

	"gopkg.in/macaroon.v2"
)

// assertTraceInternallyConsistent checks that every trace is self
// consistent:
//   - when the trace ran any operation, it holds a non-empty root key,
//   - each operation's result can be computed from the previous result,
//   - when the trace ends in TraceFail, the final result is nil,
//   - when the trace does not end in TraceFail, every operation succeeds
//     and the final result is non-nil.
//
// In particular a trace must never present a fully computable successful
// chain of operations when verification has failed: a failed verification
// has to leave an unambiguous TraceFail marker as the last operation.
func assertTraceInternallyConsistent(c *qt.C, tr macaroon.Trace) {
	if len(tr.Ops) > 0 {
		c.Assert(tr.RootKey, qt.Not(qt.HasLen), 0, qt.Commentf("missing root key"))
	}
	results := tr.Results()
	c.Assert(results, qt.HasLen, len(tr.Ops))
	for i, op := range tr.Ops {
		if op.Kind == macaroon.TraceFail {
			c.Assert(i, qt.Equals, len(tr.Ops)-1, qt.Commentf("TraceFail is not the last operation"))
			c.Assert(results[i], qt.IsNil, qt.Commentf("TraceFail must produce a nil result"))
			return
		}
		c.Assert(results[i], qt.Not(qt.IsNil),
			qt.Commentf("operation %d (%v) unexpectedly produced a nil result", i, op.Kind))
	}
}

func traceKinds(tr macaroon.Trace) []macaroon.TraceOpKind {
	kinds := make([]macaroon.TraceOpKind, len(tr.Ops))
	for i, op := range tr.Ops {
		kinds[i] = op.Kind
	}
	return kinds
}

// TestTraceVerifyConsistencyOnSuccess checks the successful case: no trace
// contains a TraceFail operation and every trace reproduces its macaroon's
// signature.
func TestTraceVerifyConsistencyOnSuccess(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons(multilevelThirdPartyCaveatMacaroons)
	traces, err := macaroons[0].TraceVerify(rootKey, macaroons[1:])
	c.Assert(err, qt.IsNil)
	c.Assert(traces, qt.HasLen, len(macaroons))
	for i, tr := range traces {
		assertTraceInternallyConsistent(c, tr)
		c.Assert(tr.Ops[len(tr.Ops)-1].Kind, qt.Not(qt.Equals), macaroon.TraceFail)
		results := tr.Results()
		c.Assert(b64str(results[len(results)-1]),
			qt.Equals, b64str(macaroons[i].Signature()),
			qt.Commentf("macaroon %d", i))
	}
}

// TestTraceVerifyFailureMarksEveryTrace is the core regression test. For
// every way verification can fail, each returned trace must be explicitly
// marked with TraceFail as its last operation so that a failed operation can
// never be mistaken for successful evidence.
func TestTraceVerifyFailureMarksEveryTrace(t *testing.T) {
	c := qt.New(t)
	tests := []struct {
		about string
		// mutate is called with the constructed macaroons before verification
		// to set up the failure condition.
		mutate    func(c *qt.C, macaroons macaroon.Slice)
		macaroons []macaroonSpec
		expectErr string
	}{{
		about: "unused discharge",
		macaroons: []macaroonSpec{{
			rootKey: "root-key",
			id:      "root-id",
		}, {
			rootKey: "other-key",
			id:      "unused",
		}},
		expectErr: `discharge macaroon "unused" was not used`,
	}, {
		about: "missing discharge for third party caveat",
		macaroons: []macaroonSpec{{
			rootKey: "root-key",
			id:      "root-id",
			caveats: []caveat{{
				condition: "bob-is-great",
				location:  "bob",
				rootKey:   "bob-caveat-root-key",
			}},
		}},
		expectErr: `cannot find discharge macaroon for caveat .*`,
	}, {
		about: "discharge with wrong root key",
		macaroons: []macaroonSpec{{
			rootKey: "root-key",
			id:      "root-id",
			caveats: []caveat{{
				condition: "bob-is-great",
				location:  "bob",
				rootKey:   "bob-caveat-root-key",
			}},
		}, {
			location: "bob",
			rootKey:  "bob-caveat-root-key-wrong",
			id:       "bob-is-great",
		}},
		expectErr: `signature mismatch after caveat verification`,
	}, {
		about: "nested discharge with missing third party discharge",
		macaroons: []macaroonSpec{{
			rootKey: "root-key",
			id:      "root-id",
			caveats: []caveat{{
				condition: "bob-is-great",
				location:  "bob",
				rootKey:   "bob-caveat-root-key",
			}},
		}, {
			location: "bob",
			rootKey:  "bob-caveat-root-key",
			id:       "bob-is-great",
			caveats: []caveat{{
				condition: "barbara-is-great",
				location:  "barbara",
				rootKey:   "barbara-caveat-root-key",
			}},
		}},
		expectErr: `cannot find discharge macaroon for caveat .*`,
	}, {
		about: "two unused discharges are both marked",
		macaroons: []macaroonSpec{{
			rootKey: "root-key",
			id:      "root-id",
		}, {
			rootKey: "other-key-1",
			id:      "unused-1",
		}, {
			rootKey: "other-key-2",
			id:      "unused-2",
		}},
		expectErr: `discharge macaroon "unused-[12]" was not used`,
	}, {
		about: "corrupted primary caveat causes signature mismatch",
		macaroons: []macaroonSpec{{
			rootKey: "xxx",
			id:      "hello",
			caveats: []caveat{{
				condition: "cond1",
			}, {
				condition: "cond2",
			}},
		}},
		mutate: func(c *qt.C, macaroons macaroon.Slice) {
			data, err := json.Marshal(macaroons[0])
			c.Assert(err, qt.IsNil)
			var jm macaroon.MacaroonJSONV2
			c.Assert(json.Unmarshal(data, &jm), qt.IsNil)
			jm.Caveats[1].CID = "cond2 corrupted"
			data, err = json.Marshal(jm)
			c.Assert(err, qt.IsNil)
			var corrupt *macaroon.Macaroon
			c.Assert(json.Unmarshal(data, &corrupt), qt.IsNil)
			macaroons[0] = corrupt
		},
		expectErr: `signature mismatch after caveat verification`,
	}}
	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			rootKey, macaroons := makeMacaroons(test.macaroons)
			if test.mutate != nil {
				test.mutate(c, macaroons)
			}
			traces, err := macaroons[0].TraceVerify(rootKey, macaroons[1:])
			c.Assert(err, qt.ErrorMatches, test.expectErr)
			c.Assert(traces, qt.HasLen, len(macaroons))
			for i, tr := range traces {
				c.Assert(tr.Ops, qt.Not(qt.HasLen), 0,
					qt.Commentf("trace %d has no operations at all", i))
				c.Assert(tr.Ops[len(tr.Ops)-1].Kind, qt.Equals, macaroon.TraceFail,
					qt.Commentf("trace %d kinds: %v", i, traceKinds(tr)))
				assertTraceInternallyConsistent(c, tr)
			}
		})
	}
}

// TestTraceVerifyRetryConsistency checks that calling TraceVerify repeatedly
// against the same macaroons produces independent, identical traces and
// errors each time: verification must not leak state between invocations.
func TestTraceVerifyRetryConsistency(t *testing.T) {
	c := qt.New(t)
	tests := []struct {
		about     string
		macaroons []macaroonSpec
		succeed   bool
	}{{
		about:     "successful verification is stable",
		macaroons: multilevelThirdPartyCaveatMacaroons,
		succeed:   true,
	}, {
		about: "failing verification is stable",
		macaroons: []macaroonSpec{{
			rootKey: "root-key",
			id:      "root-id",
			caveats: []caveat{{
				condition: "bob-is-great",
				location:  "bob",
				rootKey:   "bob-caveat-root-key",
			}},
		}},
		succeed: false,
	}}
	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			rootKey, macaroons := makeMacaroons(test.macaroons)
			var first []macaroon.Trace
			var firstErr string
			for attempt := 0; attempt < 3; attempt++ {
				traces, err := macaroons[0].TraceVerify(rootKey, macaroons[1:])
				if test.succeed {
					c.Assert(err, qt.IsNil)
				} else {
					c.Assert(err, qt.Not(qt.IsNil))
				}
				errText := ""
				if err != nil {
					errText = err.Error()
				}
				if attempt == 0 {
					first = traces
					firstErr = errText
					continue
				}
				c.Assert(errText, qt.Equals, firstErr)
				c.Assert(traces, qt.DeepEquals, first)
				// The retried traces must remain internally consistent.
				for i, tr := range traces {
					// The root key recorded for each trace is stable.
					c.Assert(tr.RootKey, qt.DeepEquals, first[i].RootKey)
				}
				for _, tr := range traces {
					assertTraceInternallyConsistent(c, tr)
				}
			}
		})
	}
}

// TestTraceVerifyFailureKinds checks the exact operation sequence for the
// simple corrupted-caveat case, preserving the originally documented
// behaviour while adding the failure marker.
func TestTraceVerifyFailureKinds(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons([]macaroonSpec{{
		rootKey: "xxx",
		id:      "hello",
		caveats: []caveat{{
			condition: "cond1",
		}, {
			condition: "cond2",
		}, {
			condition: "cond3",
		}},
	}})
	data, err := json.Marshal(macaroons[0])
	c.Assert(err, qt.IsNil)
	var jm macaroon.MacaroonJSONV2
	err = json.Unmarshal(data, &jm)
	c.Assert(err, qt.IsNil)
	jm.Caveats[1].CID = "cond2 corrupted"
	data, err = json.Marshal(jm)
	c.Assert(err, qt.IsNil)
	var corruptm *macaroon.Macaroon
	c.Assert(json.Unmarshal(data, &corruptm), qt.IsNil)

	traces, err := corruptm.TraceVerify(rootKey, nil)
	c.Assert(err, qt.ErrorMatches, `signature mismatch after caveat verification`)
	c.Assert(traces, qt.HasLen, 1)
	c.Assert(traceKinds(traces[0]), qt.DeepEquals, []macaroon.TraceOpKind{
		macaroon.TraceMakeKey,
		macaroon.TraceHash, // id
		macaroon.TraceHash, // cond1
		macaroon.TraceHash, // cond2
		macaroon.TraceHash, // cond3
		macaroon.TraceFail, // sig mismatch
	})
}

// TestTraceResultsNilOnFailure documents the contract that a trace ending
// in TraceFail yields a nil final result rather than a signature that could
// be misread as proof of successful authorization.
func TestTraceResultsNilOnFailure(t *testing.T) {
	c := qt.New(t)
	rootKey, macaroons := makeMacaroons([]macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
	}, {
		rootKey: "other-key",
		id:      "unused",
	}})
	traces, err := macaroons[0].TraceVerify(rootKey, macaroons[1:])
	c.Assert(err, qt.Not(qt.IsNil))
	for _, tr := range traces {
		results := tr.Results()
		c.Assert(results[len(results)-1], qt.IsNil)
		// Ensure the result is base-64 encodable without panicking and that
		// earlier successful operations still produced non-nil outputs.
		_ = base64.StdEncoding.EncodeToString(results[len(results)-1])
		for i, op := range tr.Ops {
			if op.Kind == macaroon.TraceFail {
				break
			}
			c.Assert(results[i], qt.Not(qt.IsNil))
		}
	}
}

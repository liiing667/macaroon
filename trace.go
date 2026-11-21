package macaroon

import (
	"fmt"
	"strings"
)

// Trace holds all toperations involved in verifying a macaroon,
// and the root key used as the initial verification key.
// This can be useful for debugging macaroon implementations.
type Trace struct {
	RootKey []byte
	Ops     []TraceOp

	// BudgetLimit is the frozen maximum number of discharge macaroons that
	// this verification was allowed to visit. BudgetCap and Budget are
	// aliases provided for callers that use those names.
	BudgetLimit int `json:"budgetLimit,omitempty"`
	BudgetCap   int `json:"budgetCap,omitempty"`
	Budget      int `json:"budget,omitempty"`
	Cap         int `json:"cap,omitempty"`
	MaxDischarges int `json:"maxDischarges,omitempty"`

	// MaxDepth is the frozen maximum discharge nesting depth.
	MaxDepth      int `json:"maxDepth,omitempty"`
	MaxDepthLimit int `json:"maxDepthLimit,omitempty"`
	DepthLimit    int `json:"depthLimit,omitempty"`
	MaxDischargeDepth int `json:"maxDischargeDepth,omitempty"`

	// CaveatLimit is the frozen maximum number of caveat operations.
	CaveatLimit int `json:"caveatLimit,omitempty"`
	MaxCaveats  int `json:"maxCaveats,omitempty"`

	// BudgetGeneration identifies the frozen budget generation. Generation
	// is an alias for the same value.
	BudgetGeneration uint64 `json:"budgetGeneration,omitempty"`
	Generation       uint64 `json:"generation,omitempty"`
	Attempts         int    `json:"attempts,omitempty"`

	// BudgetUsed is the number of discharge macaroons charged to the
	// budget. DischargeVisits is an alias for the same value.
	BudgetUsed      int `json:"budgetUsed,omitempty"`
	DischargeVisits int `json:"dischargeVisits,omitempty"`
	RequestedDischarges int `json:"requestedDischarges,omitempty"`

	// NodesVisited is the number of distinct graph nodes visited, including
	// the primary macaroon. VisitedNodes and Visited hold their identifiers
	// in deterministic visit order.
	NodesVisited int      `json:"nodesVisited,omitempty"`
	MaxDepthSeen int      `json:"maxDepthSeen,omitempty"`
	DepthVisits  int      `json:"depthVisits,omitempty"`
	VisitedNodes []string `json:"visitedNodes,omitempty"`
	Visited      []string `json:"visited,omitempty"`
	VisitedNodeIDs []string `json:"visitedNodeIds,omitempty"`
	VisitedCount   int      `json:"visitedCount,omitempty"`

	// CaveatOperations is the number of caveat operations charged to the
	// budget.
	CaveatOperations int `json:"caveatOperations,omitempty"`

	// TerminationReason explains why verification stopped. Termination is
	// an alias for the same value.
	TerminationReason string `json:"terminationReason,omitempty"`
	Termination       string `json:"termination,omitempty"`
	BudgetReason      string `json:"budgetReason,omitempty"`
	Reason            string `json:"reason,omitempty"`
	BudgetExceeded    bool   `json:"budgetExceeded,omitempty"`

	// FailureStage and FailureLocation identify the failing stage and the
	// exact discharge/caveat path. Failure is the structured form.
	FailureStage    string        `json:"failureStage,omitempty"`
	FailureLocation string        `json:"failureLocation,omitempty"`
	Failure         *TraceFailure `json:"failure,omitempty"`

	// BudgetState is a complete snapshot of the frozen budget and its use.
	BudgetState BudgetSnapshot `json:"budgetState,omitempty"`
}

// TraceFailure identifies the exact stage and graph node at which a
// verification failed.
type TraceFailure struct {
	Stage         string   `json:"stage,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Source        string   `json:"source,omitempty"`
	MacaroonIndex int      `json:"macaroonIndex,omitempty"`
	CaveatIndex   int      `json:"caveatIndex,omitempty"`
	TargetMacaroonIndex int `json:"targetMacaroonIndex,omitempty"`
	CaveatID      []byte   `json:"caveatId,omitempty"`
	DischargeID   []byte   `json:"dischargeId,omitempty"`
	Path          []string `json:"path,omitempty"`
	Location      string   `json:"location,omitempty"`
	Error         string   `json:"error,omitempty"`
}

func (f TraceFailure) String() string {
	if f.Location != "" {
		return f.Location
	}
	return failureLocationString(&f)
}

func failureLocationString(f *TraceFailure) string {
	if f == nil {
		return ""
	}
	if f.Location != "" {
		return f.Location
	}
	location := fmt.Sprintf("macaroon[%d]", f.MacaroonIndex)
	if f.CaveatIndex >= 0 {
		location += fmt.Sprintf(".caveat[%d]", f.CaveatIndex)
	}
	if len(f.CaveatID) != 0 {
		location += fmt.Sprintf(" (caveat id %s)", compactQuoted(f.CaveatID))
	}
	if len(f.DischargeID) != 0 {
		location += fmt.Sprintf(" (discharge id %s)", compactQuoted(f.DischargeID))
	}
	if f.Source != "" {
		location = f.Source + ": " + location
	}
	if f.TargetMacaroonIndex > 0 {
		location += fmt.Sprintf(" -> macaroon[%d]", f.TargetMacaroonIndex)
	}
	return location
}

func compactQuoted(data []byte) string {
	const max = 64
	if len(data) > max {
		return fmt.Sprintf("%q...", string(data[:max]))
	}
	return fmt.Sprintf("%q", string(data))
}

func cloneTraceFailure(f *TraceFailure) *TraceFailure {
	if f == nil {
		return nil
	}
	c := *f
	c.CaveatID = append([]byte(nil), f.CaveatID...)
	c.DischargeID = append([]byte(nil), f.DischargeID...)
	c.Path = append([]string(nil), f.Path...)
	return &c
}

// Results returns the output from all operations in the Trace.
// The result from ts.Ops[i] will be in the i'th element of the
// returned slice.
// When a trace has resulted in a failure, the
// last element will be nil.
func (t Trace) Results() [][]byte {
	r := make([][]byte, len(t.Ops))
	input := t.RootKey
	for i, op := range t.Ops {
		input = op.Result(input)
		r[i] = input
	}
	return r
}

// TraceOp holds one possible operation when verifying a macaroon.
type TraceOp struct {
	Kind          TraceOpKind `json:"kind"`
	Data1         []byte      `json:"data1,omitempty"`
	Data2         []byte      `json:"data2,omitempty"`
	Reason        string      `json:"reason,omitempty"`
	Location      string      `json:"location,omitempty"`
	Stage         string      `json:"stage,omitempty"`
	MacaroonIndex int         `json:"macaroonIndex,omitempty"`
	CaveatIndex   int         `json:"caveatIndex,omitempty"`
}

// Result returns the result of computing the given
// operation with the given input data.
// If op is TraceFail, it returns nil.
func (op TraceOp) Result(input []byte) []byte {
	switch op.Kind {
	case TraceMakeKey:
		return makeKey(input)[:]
	case TraceHash:
		if len(op.Data2) == 0 {
			return keyedHash(bytesToKey(input), op.Data1)[:]
		}
		return keyedHash2(bytesToKey(input), op.Data1, op.Data2)[:]
	case TraceBind:
		return bindForRequest(op.Data1, bytesToKey(input))[:]
	case TraceFail:
		return nil
	default:
		panic(fmt.Errorf("unknown trace operation kind %d", op.Kind))
	}
}

func bytesToKey(data []byte) *[keyLen]byte {
	var key [keyLen]byte
	if len(data) != keyLen {
		panic(fmt.Errorf("unexpected input key length; got %d want %d", len(data), keyLen))
	}
	copy(key[:], data)
	return &key
}

// TraceOpKind represents the kind of a macaroon verification operation.
type TraceOpKind int

const (
	TraceInvalid = TraceOpKind(iota)

	// TraceMakeKey represents the operation of calculating a
	// fixed length root key from the variable length input key.
	TraceMakeKey

	// TraceHash represents a keyed hash operation with one
	// or two values. If there is only one value, it will be in Data1.
	TraceHash

	// TraceBind represents the operation of binding a discharge macaroon
	// to its primary macaroon. Data1 holds the signature of the primary
	// macaroon.
	TraceBind

	// TraceFail represents a verification failure. If present, this will always
	// be the last operation in a trace.
	TraceFail
)

var traceOps = []string{
	TraceInvalid: "invalid",
	TraceMakeKey: "makekey",
	TraceHash:    "hash",
	TraceBind:    "bind",
	TraceFail:    "fail",
}

// String returns a string representation of the operation.
func (k TraceOpKind) String() string {
	if k < 0 || int(k) >= len(traceOps) {
		return fmt.Sprintf("TraceOpKind(%d)", int(k))
	}
	return traceOps[k]
}

func traceBudgetSummary(t Trace) string {
	var parts []string
	if t.BudgetLimit != 0 {
		parts = append(parts, fmt.Sprintf("budget=%d/%d", t.BudgetUsed, t.BudgetLimit))
	}
	if t.MaxDepth != 0 {
		parts = append(parts, fmt.Sprintf("depth=%d/%d", t.MaxDepthSeen, t.MaxDepth))
	}
	if t.CaveatLimit != 0 {
		parts = append(parts, fmt.Sprintf("caveats=%d/%d", t.CaveatOperations, t.CaveatLimit))
	}
	if t.Attempts != 0 {
		parts = append(parts, fmt.Sprintf("attempts=%d", t.Attempts))
	}
	if t.TerminationReason != "" {
		parts = append(parts, "termination="+t.TerminationReason)
	}
	if t.FailureLocation != "" {
		parts = append(parts, "failure="+t.FailureLocation)
	}
	if len(t.VisitedNodes) != 0 {
		parts = append(parts, "visited="+strings.Join(t.VisitedNodes, ","))
	}
	return strings.Join(parts, " ")
}

// String returns a compact report of the trace's frozen budget, visited
// nodes, and termination reason. It is intended for diagnostics; use Ops and
// Results for the cryptographic operation trail.
func (t Trace) String() string {
	return traceBudgetSummary(t)
}

package macaroon

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Verification budget limits keep a malicious third-party discharge graph
// from consuming an unbounded amount of verification time or memory.
const (
	// DefaultMaxDischarges is the maximum number of discharge macaroons that
	// may be visited by one root verification. It does not count the primary
	// macaroon.
	DefaultMaxDischarges = 32

	// DefaultMaxDischargeDepth is the maximum nesting depth of a discharge
	// graph. The primary macaroon has depth zero.
	DefaultMaxDischargeDepth = 16

	// DefaultMaxCaveatOperations is the maximum number of caveat operations
	// that may be performed by one root verification.
	DefaultMaxCaveatOperations = 1024

	// Compatibility aliases for callers that spell the limits differently.
	DefaultMaxDepth             = DefaultMaxDischargeDepth
	DefaultMaxCaveats           = DefaultMaxCaveatOperations
	DefaultMaxDischargeGraphSize = DefaultMaxDischarges
	MaxDischargeDepth            = DefaultMaxDischargeDepth
	MaxDepth                     = DefaultMaxDischargeDepth
	MaxDischarges                = DefaultMaxDischarges
	MaxDischargeCount            = DefaultMaxDischarges
	MaxCaveatOperations          = DefaultMaxCaveatOperations
	MaxCaveats                   = DefaultMaxCaveatOperations
)

// Termination reasons recorded in a Trace.
const (
	TerminationVerified              = "verified"
	TerminationBudgetExceeded        = "budget_exceeded"
	TerminationDischargeBudget       = "discharge_budget_exceeded"
	TerminationDepthBudget           = "depth_budget_exceeded"
	TerminationCaveatBudget          = "caveat_budget_exceeded"
	TerminationCancelled             = "cancelled"
	TerminationVerificationFailed    = "verification_failed"
	TerminationDischargeNotFound     = "discharge_not_found"
	TerminationDischargeReused       = "discharge_reused"
	TerminationUnusedDischarge       = "unused_discharge"
	TerminationDecryptFailed         = "decrypt_failed"
	TerminationCaveatCheckFailed     = "caveat_check_failed"
	TerminationSignatureMismatch     = "signature_mismatch"
	TerminationInvalidDischarge      = "invalid_discharge"
	TerminationAdmission             = "admission"
)

var (
	// ErrVerificationBudgetExceeded is returned when a discharge graph
	// exceeds one of the verification limits.
	ErrVerificationBudgetExceeded = errors.New("macaroon verification budget exceeded")

	// ErrBudgetExceeded is an alias for ErrVerificationBudgetExceeded.
	ErrBudgetExceeded = ErrVerificationBudgetExceeded

	// ErrMaxDischargesExceeded is returned when too many discharge
	// macaroons are visited.
	ErrMaxDischargesExceeded = fmt.Errorf("%w: too many discharge macaroons", ErrVerificationBudgetExceeded)

	// ErrMaxDischargeDepthExceeded is returned when the discharge graph is
	// nested too deeply.
	ErrMaxDischargeDepthExceeded = fmt.Errorf("%w: maximum discharge depth exceeded", ErrVerificationBudgetExceeded)

	// ErrMaxCaveatOperationsExceeded is returned when the graph contains
	// too many caveat operations.
	ErrMaxCaveatOperationsExceeded = fmt.Errorf("%w: too many caveat operations", ErrVerificationBudgetExceeded)

	// ErrDischargeBudgetExceeded and ErrDepthExceeded are aliases for the
	// corresponding limit errors.
	ErrDischargeBudgetExceeded = ErrMaxDischargesExceeded
	ErrDepthExceeded           = ErrMaxDischargeDepthExceeded
	ErrCaveatBudgetExceeded    = ErrMaxCaveatOperationsExceeded

	// ErrVerificationCancelled is returned when context cancellation stops
	// verification.
	ErrVerificationCancelled = context.Canceled
)

// VerificationBudget holds the resource limits for one root verification.
// Once a verification has started, its budget is frozen; retries, including
// retries after cancellation or process-level reconstruction, cannot raise
// the limits that were in force for that verification.
type VerificationBudget struct {
	// MaxDischarges is the maximum number of discharge macaroons that may
	// be visited. The primary macaroon is not counted.
	MaxDischarges int

	// MaxDepth and MaxDischargeDepth are aliases for the maximum discharge
	// nesting depth. The primary macaroon has depth zero.
	MaxDepth          int
	MaxDischargeDepth int

	// MaxCaveatOperations and MaxCaveats are aliases for the maximum number
	// of caveat operations.
	MaxCaveatOperations int
	MaxCaveats          int
}

// DefaultVerificationBudget is the budget used by Verify and TraceVerify.
// It is copied when a verification starts, so changing it does not alter a
// verification that is already in progress.
var DefaultVerificationBudget = VerificationBudget{
	MaxDischarges:       DefaultMaxDischarges,
	MaxDepth:            DefaultMaxDischargeDepth,
	MaxDischargeDepth:   DefaultMaxDischargeDepth,
	MaxCaveatOperations: DefaultMaxCaveatOperations,
	MaxCaveats:          DefaultMaxCaveatOperations,
}

// NewVerificationBudget returns a budget with the given discharge and depth
// limits. A non-positive value selects the corresponding default.
func NewVerificationBudget(maxDischarges, maxDepth int) VerificationBudget {
	b := DefaultVerificationBudget
	b.MaxDischarges = maxDischarges
	b.MaxDepth = maxDepth
	b.MaxDischargeDepth = maxDepth
	return b.normalized()
}

func (b VerificationBudget) normalized() VerificationBudget {
	if b.MaxDischarges <= 0 {
		b.MaxDischarges = DefaultMaxDischarges
	}
	if b.MaxDepth == DefaultMaxDischargeDepth &&
		b.MaxDischargeDepth > 0 &&
		b.MaxDischargeDepth != DefaultMaxDischargeDepth {
		b.MaxDepth = b.MaxDischargeDepth
	}
	if b.MaxDischargeDepth == DefaultMaxDischargeDepth &&
		b.MaxDepth > 0 &&
		b.MaxDepth != DefaultMaxDischargeDepth {
		b.MaxDischargeDepth = b.MaxDepth
	}
	if b.MaxDischargeDepth <= 0 {
		b.MaxDischargeDepth = b.MaxDepth
	}
	if b.MaxDepth <= 0 {
		b.MaxDepth = b.MaxDischargeDepth
	}
	if b.MaxDepth <= 0 {
		b.MaxDepth = DefaultMaxDischargeDepth
	}
	if b.MaxDischargeDepth <= 0 {
		b.MaxDischargeDepth = b.MaxDepth
	}
	if b.MaxCaveatOperations <= 0 {
		b.MaxCaveatOperations = b.MaxCaveats
	}
	if b.MaxCaveatOperations == DefaultMaxCaveatOperations &&
		b.MaxCaveats > 0 &&
		b.MaxCaveats != DefaultMaxCaveatOperations {
		b.MaxCaveatOperations = b.MaxCaveats
	}
	if b.MaxCaveats == DefaultMaxCaveatOperations &&
		b.MaxCaveatOperations > 0 &&
		b.MaxCaveatOperations != DefaultMaxCaveatOperations {
		b.MaxCaveats = b.MaxCaveatOperations
	}
	if b.MaxCaveats <= 0 {
		b.MaxCaveats = b.MaxCaveatOperations
	}
	if b.MaxCaveatOperations <= 0 {
		b.MaxCaveatOperations = DefaultMaxCaveatOperations
	}
	if b.MaxCaveats <= 0 {
		b.MaxCaveats = b.MaxCaveatOperations
	}
	return b
}

// VerifyOption configures a verification budget.
type VerifyOption func(*VerificationBudget)

// WithMaxDischarges limits the number of discharge macaroons visited by a
// verification.
func WithMaxDischarges(n int) VerifyOption {
	return func(b *VerificationBudget) {
		b.MaxDischarges = n
	}
}

// WithMaxDischargeCount is an alias for WithMaxDischarges.
func WithMaxDischargeCount(n int) VerifyOption {
	return WithMaxDischarges(n)
}

// WithMaxDischargeDepth limits the nesting depth of a verification. The
// primary macaroon has depth zero.
func WithMaxDischargeDepth(n int) VerifyOption {
	return func(b *VerificationBudget) {
		b.MaxDepth = n
		b.MaxDischargeDepth = n
	}
}

// WithMaxDepth is an alias for WithMaxDischargeDepth.
func WithMaxDepth(n int) VerifyOption {
	return WithMaxDischargeDepth(n)
}

// WithMaxCaveatOperations limits the number of caveat operations performed
// by a verification.
func WithMaxCaveatOperations(n int) VerifyOption {
	return func(b *VerificationBudget) {
		b.MaxCaveatOperations = n
		b.MaxCaveats = n
	}
}

// WithMaxCaveats is an alias for WithMaxCaveatOperations.
func WithMaxCaveats(n int) VerifyOption {
	return WithMaxCaveatOperations(n)
}

// WithVerificationBudget replaces the whole verification budget.
func WithVerificationBudget(budget VerificationBudget) VerifyOption {
	return func(b *VerificationBudget) {
		*b = budget
	}
}

// WithBudget is an alias for WithVerificationBudget.
func WithBudget(budget VerificationBudget) VerifyOption {
	return WithVerificationBudget(budget)
}

func budgetFromOptions(opts []VerifyOption) VerificationBudget {
	b := DefaultVerificationBudget
	for _, opt := range opts {
		if opt != nil {
			opt(&b)
		}
	}
	return b.normalized()
}

// BudgetError describes a verification limit failure. It includes the
// location in the discharge graph so callers can report exactly which
// caveat or node exhausted the budget.
type BudgetError struct {
	Operation string
	Reason    string
	Limit     int
	Used      int
	Cap       int
	Visits    int
	Depth     int
	MaxDepth  int
	Location  string
	Cause     error
}

func (e *BudgetError) Error() string {
	if e == nil {
		return "<nil>"
	}
	cause := e.Cause
	if cause == nil {
		cause = ErrVerificationBudgetExceeded
	}
	parts := []string{cause.Error()}
	if e.Reason != "" {
		parts = append(parts, "reason="+e.Reason)
	}
	if e.Operation != "" {
		parts = append(parts, "operation="+e.Operation)
	}
	if e.Location != "" {
		parts = append(parts, "at "+e.Location)
	}
	if e.Limit > 0 {
		parts = append(parts, fmt.Sprintf("limit=%d", e.Limit))
	}
	if e.Used > 0 {
		parts = append(parts, fmt.Sprintf("used=%d", e.Used))
	}
	if e.Cap > 0 {
		parts = append(parts, fmt.Sprintf("cap=%d", e.Cap))
	}
	if e.Visits > 0 {
		parts = append(parts, fmt.Sprintf("visits=%d", e.Visits))
		parts = append(parts, fmt.Sprintf("visited=%d", e.Visits))
	}
	if e.Depth > 0 {
		parts = append(parts, fmt.Sprintf("depth=%d", e.Depth))
	}
	if e.MaxDepth > 0 {
		parts = append(parts, fmt.Sprintf("max_depth=%d", e.MaxDepth))
	}
	return strings.Join(parts, ", ")
}

// Unwrap allows errors.Is to recognise the underlying budget or context
// error.
func (e *BudgetError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// BudgetSnapshot is a point-in-time view of a verification's budget. It is
// copied into a Trace so consumers can tell what limit was frozen, which
// nodes were visited, and why verification terminated.
type BudgetSnapshot struct {
	Generation           uint64
	Attempts             int
	MaxDischarges        int
	BudgetLimit          int
	Cap                  int
	MaxDepth             int
	DepthLimit           int
	MaxCaveatOperations  int
	MaxCaveats           int
	DischargesVisited    int
	BudgetUsed           int
	RequestedDischarges  int
	MaxDepthSeen         int
	DepthVisits          int
	CaveatOperations     int
	NodesVisited         int
	Visited              []string
	Terminal             bool
	TerminationReason    string
	Reason               string
	Failure              *TraceFailure
}

func (s BudgetSnapshot) budget() VerificationBudget {
	return VerificationBudget{
		MaxDischarges:       s.MaxDischarges,
		MaxDepth:            s.MaxDepth,
		MaxDischargeDepth:   s.MaxDepth,
		MaxCaveatOperations: s.MaxCaveatOperations,
		MaxCaveats:          s.MaxCaveatOperations,
	}
}

type verificationBudgetState struct {
	mu sync.Mutex

	generation  uint64
	budget      VerificationBudget
	discharges  int
	requested   int
	attempts    int
	depth       int
	depthCharge int
	caveats     int
	visited     []string
	visitedSet  map[string]struct{}
	active      int
	completed   bool
	terminal    error
	terminalWhy string
	failure     *TraceFailure
}

var verificationBudgets = struct {
	sync.Mutex
	states map[[sha256.Size]byte]*verificationBudgetState
}{
	states: make(map[[sha256.Size]byte]*verificationBudgetState),
}

// The registry is deliberately bounded. A process that verifies many
// distinct roots must not accumulate budget state without limit.
const maxVerificationBudgetStates = 1024

func verificationBudgetKey(rootKey []byte, root *Macaroon) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("gopkg.in/macaroon.v2/verification-budget/v1\x00"))
	h.Write(rootKey)
	if root != nil {
		h.Write(root.sig[:])
		h.Write(root.id)
	}
	var key [sha256.Size]byte
	copy(key[:], h.Sum(nil))
	return key
}

func acquireVerificationBudget(rootKey []byte, root *Macaroon, budget VerificationBudget) *verificationBudgetState {
	if root == nil {
		return nil
	}
	key := verificationBudgetKey(rootKey, root)
	budget = budget.normalized()

	verificationBudgets.Lock()
	state := verificationBudgets.states[key]
	if state == nil {
		if len(verificationBudgets.states) >= maxVerificationBudgetStates {
			evictInactiveBudgetStateLocked()
		}
		state = &verificationBudgetState{
			generation: verificationBudgetGeneration(key),
			budget:     budget,
			visitedSet: make(map[string]struct{}),
		}
		verificationBudgets.states[key] = state
	}
	verificationBudgets.Unlock()
	return state
}

func verificationBudgetGeneration(key [sha256.Size]byte) uint64 {
	var generation uint64
	for _, b := range key[:8] {
		generation = generation<<8 | uint64(b)
	}
	if generation == 0 {
		generation = 1
	}
	return generation
}

func evictInactiveBudgetStateLocked() {
	for key, state := range verificationBudgets.states {
		state.mu.Lock()
		inactive := state.active == 0
		state.mu.Unlock()
		if inactive {
			delete(verificationBudgets.states, key)
			return
		}
	}
}

func (s *verificationBudgetState) begin(budget VerificationBudget) (BudgetSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		s.budget = budget.normalized()
		s.completed = false
	}
	snapshot := s.snapshotLocked()
	if s.terminal != nil {
		return snapshot, s.terminal
	}
	s.active++
	s.attempts++
	return snapshot, nil
}

func (s *verificationBudgetState) finish(success bool, err error, failure *TraceFailure) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active > 0 {
		s.active--
	}
	if success {
		s.discharges = 0
		s.requested = 0
		s.attempts = 0
		s.depth = 0
		s.depthCharge = 0
		s.caveats = 0
		s.visited = nil
		s.visitedSet = make(map[string]struct{})
		s.terminal = nil
		s.terminalWhy = ""
		s.failure = nil
		s.completed = true
		return
	}
	if err == nil {
		return
	}
	var budgetErr *BudgetError
	if errors.As(err, &budgetErr) {
		s.terminal = err
		s.terminalWhy = budgetErr.Reason
		if failure != nil {
			s.failure = cloneTraceFailure(failure)
		}
	}
}

func (s *verificationBudgetState) snapshot() BudgetSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *verificationBudgetState) snapshotLocked() BudgetSnapshot {
	if s == nil {
		return BudgetSnapshot{}
	}
	snapshot := BudgetSnapshot{
		Generation:          s.generation,
		Attempts:            s.attempts,
		MaxDischarges:       s.budget.MaxDischarges,
		BudgetLimit:         s.budget.MaxDischarges,
		Cap:                 s.budget.MaxDischarges,
		MaxDepth:            s.budget.MaxDepth,
		DepthLimit:          s.budget.MaxDepth,
		MaxCaveatOperations: s.budget.MaxCaveatOperations,
		MaxCaveats:          s.budget.MaxCaveatOperations,
		DischargesVisited:   s.discharges,
		BudgetUsed:          s.discharges,
		RequestedDischarges: s.requested,
		MaxDepthSeen:        s.depth,
		DepthVisits:         s.depthCharge,
		CaveatOperations:    s.caveats,
		NodesVisited:        len(s.visited),
		Terminal:            s.terminal != nil,
		TerminationReason:   s.terminalWhy,
		Reason:              s.terminalWhy,
		Failure:             cloneTraceFailure(s.failure),
	}
	snapshot.Visited = append([]string(nil), s.visited...)
	return snapshot
}

func (s *verificationBudgetState) visitRoot(id []byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addVisitedLocked(id)
}

func (s *verificationBudgetState) recordAdmission(n int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > s.requested {
		s.requested = n
	}
}

func (s *verificationBudgetState) visitDischarge(id []byte, depth int, failure *TraceFailure) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal != nil {
		return s.terminal
	}
	s.addVisitedLocked(id)
	if depth > s.depth {
		s.depth = depth
	}
	s.depthCharge += depth
	s.discharges++
	if s.discharges > s.budget.MaxDischarges {
		err := &BudgetError{
			Operation: "discharge graph traversal",
			Reason:    TerminationDischargeBudget,
			Limit:     s.budget.MaxDischarges,
			Used:      s.discharges,
			Cap:       s.budget.MaxDischarges,
			Visits:    s.discharges,
			Depth:     depth,
			MaxDepth:  s.budget.MaxDepth,
			Location:  failureLocationString(failure),
			Cause:     ErrMaxDischargesExceeded,
		}
		s.terminal = err
		s.terminalWhy = TerminationDischargeBudget
		if failure != nil {
			failure.Path = append(failure.Path, string(id))
			failure.Reason = s.terminalWhy
			failure.Error = err.Error()
			s.failure = cloneTraceFailure(failure)
		}
		return err
	}
	return nil
}

func (s *verificationBudgetState) exceedDepth(depth int, failure *TraceFailure) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal != nil {
		return s.terminal
	}
	if depth > s.depth {
		s.depth = depth
	}
	s.depthCharge += depth
	err := &BudgetError{
		Operation: "discharge graph depth",
		Reason:    TerminationDepthBudget,
		Limit:     s.budget.MaxDepth,
		Used:      depth,
		Cap:       s.budget.MaxDepth,
		Visits:    s.depth,
		Depth:     depth,
		MaxDepth:  s.budget.MaxDepth,
		Location:  failureLocationString(failure),
		Cause:     ErrMaxDischargeDepthExceeded,
	}
	s.terminal = err
	s.terminalWhy = TerminationDepthBudget
	if failure != nil {
		failure.Reason = s.terminalWhy
		failure.Error = err.Error()
		s.failure = cloneTraceFailure(failure)
	}
	return err
}

func (s *verificationBudgetState) consumeCaveat(failure *TraceFailure) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal != nil {
		return s.terminal
	}
	s.caveats++
	if s.caveats > s.budget.MaxCaveatOperations {
		err := &BudgetError{
			Operation: "caveat verification",
			Reason:    TerminationCaveatBudget,
			Limit:     s.budget.MaxCaveatOperations,
			Used:      s.caveats,
			Cap:       s.budget.MaxCaveatOperations,
			Visits:    s.caveats,
			Location:  failureLocationString(failure),
			Cause:     ErrMaxCaveatOperationsExceeded,
		}
		s.terminal = err
		s.terminalWhy = TerminationCaveatBudget
		if failure != nil {
			failure.Reason = s.terminalWhy
			failure.Error = err.Error()
			s.failure = cloneTraceFailure(failure)
		}
		return err
	}
	return nil
}

func (s *verificationBudgetState) addVisitedLocked(id []byte) {
	if s == nil {
		return
	}
	key := string(id)
	if _, ok := s.visitedSet[key]; ok {
		return
	}
	s.visitedSet[key] = struct{}{}
	s.visited = append(s.visited, key)
}

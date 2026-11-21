// The macaroon package implements macaroons as described in
// the paper "Macaroons: Cookies with Contextual Caveats for
// Decentralized Authorization in the Cloud"
// (http://theory.stanford.edu/~ataly/Papers/macaroons.pdf)
//
// See the macaroon bakery packages at http://godoc.org/gopkg.in/macaroon-bakery.v2
// for higher level services and operations that use macaroons.
package macaroon

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Macaroon holds a macaroon.
// See Fig. 7 of http://theory.stanford.edu/~ataly/Papers/macaroons.pdf
// for a description of the data contained within.
// Macaroons are mutable objects - use Clone as appropriate
// to avoid unwanted mutation.
type Macaroon struct {
	location string
	id       []byte
	caveats  []Caveat
	sig      [hashLen]byte
	version  Version
}

// Equal reports whether m has exactly the same content as m1.
func (m *Macaroon) Equal(m1 *Macaroon) bool {
	if m == m1 || m == nil || m1 == nil {
		return m == m1
	}
	if m.location != m1.location ||
		!bytes.Equal(m.id, m1.id) ||
		m.sig != m1.sig ||
		m.version != m1.version ||
		len(m.caveats) != len(m1.caveats) {
		return false
	}
	for i, c := range m.caveats {
		if !c.Equal(m1.caveats[i]) {
			return false
		}
	}
	return true
}

// Caveat holds a first party or third party caveat.
type Caveat struct {
	// Id holds the id of the caveat. For first
	// party caveats this holds the condition;
	// for third party caveats this holds the encrypted
	// third party caveat.
	Id []byte

	// VerificationId holds the verification id. If this is
	// non-empty, it's a third party caveat.
	VerificationId []byte

	// For third-party caveats, Location holds the
	// ocation hint. Note that this is not signature checked
	// as part of the caveat, so should only
	// be used as a hint.
	Location string
}

// Equal reports whether c is equal to c1.
func (c Caveat) Equal(c1 Caveat) bool {
	return bytes.Equal(c.Id, c1.Id) &&
		bytes.Equal(c.VerificationId, c1.VerificationId) &&
		c.Location == c1.Location
}

// isThirdParty reports whether the caveat must be satisfied
// by some third party (if not, it's a first person caveat).
func (cav *Caveat) isThirdParty() bool {
	return len(cav.VerificationId) > 0
}

// New returns a new macaroon with the given root key,
// identifier, location and version.
func New(rootKey, id []byte, loc string, version Version) (*Macaroon, error) {
	var m Macaroon
	if version < V2 {
		if !utf8.Valid(id) {
			return nil, fmt.Errorf("invalid id for %v macaroon", id)
		}
		// TODO check id length too.
	}
	if version < V1 || version > LatestVersion {
		return nil, fmt.Errorf("invalid version %v", version)
	}
	m.version = version
	m.init(append([]byte(nil), id...), loc, version)
	derivedKey := makeKey(rootKey)
	m.sig = *keyedHash(derivedKey, m.id)
	return &m, nil
}

// init initializes the macaroon. It retains a reference to id.
func (m *Macaroon) init(id []byte, loc string, vers Version) {
	m.location = loc
	m.id = append([]byte(nil), id...)
	m.version = vers
}

// SetLocation sets the location associated with the macaroon.
// Note that the location is not included in the macaroon's
// hash chain, so this does not change the signature.
func (m *Macaroon) SetLocation(loc string) {
	m.location = loc
}

// Clone returns a copy of the receiving macaroon.
func (m *Macaroon) Clone() *Macaroon {
	m1 := *m
	// Ensure that if any caveats are appended to the new
	// macaroon, it will copy the caveats.
	m1.caveats = m1.caveats[0:len(m1.caveats):len(m1.caveats)]
	return &m1
}

// Location returns the macaroon's location hint. This is
// not verified as part of the macaroon.
func (m *Macaroon) Location() string {
	return m.location
}

// Id returns the id of the macaroon. This can hold
// arbitrary information.
func (m *Macaroon) Id() []byte {
	return append([]byte(nil), m.id...)
}

// Signature returns the macaroon's signature.
func (m *Macaroon) Signature() []byte {
	// sig := m.sig
	// return sig[:]
	// Work around https://github.com/golang/go/issues/9537
	sig := new([hashLen]byte)
	*sig = m.sig
	return sig[:]
}

// Caveats returns the macaroon's caveats.
// This method will probably change, and it's important not to change the returned caveat.
func (m *Macaroon) Caveats() []Caveat {
	return m.caveats[0:len(m.caveats):len(m.caveats)]
}

// appendCaveat appends a caveat without modifying the macaroon's signature.
func (m *Macaroon) appendCaveat(caveatId, verificationId []byte, loc string) {
	if len(verificationId) == 0 {
		// Ensure that an empty vid is always represented by nil,
		// so that marshalers don't procuce spurious zero-length
		// vid fields which can confuse some verifiers.
		verificationId = nil
	}
	m.caveats = append(m.caveats, Caveat{
		Id:             caveatId,
		VerificationId: verificationId,
		Location:       loc,
	})
}

func (m *Macaroon) addCaveat(caveatId, verificationId []byte, loc string) error {
	if m.version < V2 {
		if !utf8.Valid(caveatId) {
			return fmt.Errorf("invalid caveat id for %v macaroon", m.version)
		}
		// TODO check caveat length too.
	}
	m.appendCaveat(caveatId, verificationId, loc)
	if len(verificationId) == 0 {
		m.sig = *keyedHash(&m.sig, caveatId)
	} else {
		m.sig = *keyedHash2(&m.sig, verificationId, caveatId)
	}
	return nil
}

func keyedHash2(key *[keyLen]byte, d1, d2 []byte) *[hashLen]byte {
	var data [hashLen * 2]byte
	copy(data[0:], keyedHash(key, d1)[:])
	copy(data[hashLen:], keyedHash(key, d2)[:])
	return keyedHash(key, data[:])
}

// Bind prepares the macaroon for being used to discharge the
// macaroon with the given signature sig. This must be
// used before it is used in the discharges argument to Verify.
func (m *Macaroon) Bind(sig []byte) {
	m.sig = *bindForRequest(sig, &m.sig)
}

// AddFirstPartyCaveat adds a caveat that will be verified
// by the target service.
func (m *Macaroon) AddFirstPartyCaveat(condition []byte) error {
	m.addCaveat(condition, nil, "")
	return nil
}

// AddThirdPartyCaveat adds a third-party caveat to the macaroon,
// using the given shared root key, caveat id and location hint.
// The caveat id should encode the root key in some
// way, either by encrypting it with a key known to the third party
// or by holding a reference to it stored in the third party's
// storage.
func (m *Macaroon) AddThirdPartyCaveat(rootKey, caveatId []byte, loc string) error {
	return m.addThirdPartyCaveatWithRand(rootKey, caveatId, loc, rand.Reader)
}

// addThirdPartyCaveatWithRand adds a third-party caveat to the macaroon, using
// the given source of randomness for encrypting the caveat id.
func (m *Macaroon) addThirdPartyCaveatWithRand(rootKey, caveatId []byte, loc string, r io.Reader) error {
	derivedKey := makeKey(rootKey)
	verificationId, err := encrypt(&m.sig, derivedKey, r)
	if err != nil {
		return err
	}
	m.addCaveat(caveatId, verificationId, loc)
	return nil
}

var zeroKey [hashLen]byte

// bindForRequest binds the given macaroon
// to the given signature of its parent macaroon.
func bindForRequest(rootSig []byte, dischargeSig *[hashLen]byte) *[hashLen]byte {
	if bytes.Equal(rootSig, dischargeSig[:]) {
		return dischargeSig
	}
	return keyedHash2(&zeroKey, rootSig, dischargeSig[:])
}

// Verify verifies that the receiving macaroon is valid.
// The root key must be the same that the macaroon was originally
// minted with. The check function is called to verify each
// first-party caveat - it should return an error if the
// condition is not met.
//
// The discharge macaroons should be provided in discharges.
//
// Verify returns nil if the verification succeeds.
func (m *Macaroon) Verify(rootKey []byte, check func(caveat string) error, discharges []*Macaroon) error {
	return m.VerifyWithOptions(rootKey, check, discharges)
}

// VerifyContext is like Verify but stops verification when ctx is
// cancelled. The cancellation is reported through errors.Is(err,
// context.Canceled). Any budget already consumed by the cancelled
// verification remains charged if the same root is verified again.
func (m *Macaroon) VerifyContext(ctx context.Context, rootKey []byte, check func(caveat string) error, discharges []*Macaroon) error {
	return m.VerifyContextWithOptions(ctx, rootKey, check, discharges)
}

// VerifyWithContext is an alias for VerifyContext.
func (m *Macaroon) VerifyWithContext(ctx context.Context, rootKey []byte, check func(caveat string) error, discharges []*Macaroon) error {
	return m.VerifyContext(ctx, rootKey, check, discharges)
}

// VerifyWithBudget is like Verify but uses the given resource budget.
// The budget is frozen when verification starts and is shared by retries
// of the same root verification.
func (m *Macaroon) VerifyWithBudget(rootKey []byte, check func(caveat string) error, discharges []*Macaroon, budget VerificationBudget) error {
	return m.VerifyWithOptions(rootKey, check, discharges, WithVerificationBudget(budget))
}

// VerifyWithOptions is like Verify but applies the given budget options.
func (m *Macaroon) VerifyWithOptions(rootKey []byte, check func(caveat string) error, discharges []*Macaroon, opts ...VerifyOption) error {
	_, err := m.verifyContext(context.Background(), rootKey, check, discharges, budgetFromOptions(opts), false)
	return err
}

// VerifyContextWithOptions is like VerifyContext but applies budget
// options.
func (m *Macaroon) VerifyContextWithOptions(ctx context.Context, rootKey []byte, check func(caveat string) error, discharges []*Macaroon, opts ...VerifyOption) error {
	_, err := m.verifyContext(ctx, rootKey, check, discharges, budgetFromOptions(opts), false)
	return err
}

// VerifyContextWithBudget is like VerifyContext but uses the given resource
// budget.
func (m *Macaroon) VerifyContextWithBudget(ctx context.Context, rootKey []byte, check func(caveat string) error, discharges []*Macaroon, budget VerificationBudget) error {
	return m.VerifyContextWithOptions(ctx, rootKey, check, discharges, WithVerificationBudget(budget))
}

// VerifySignature verifies the signature of the given macaroon with respect
// to the root key, but it does not validate any first-party caveats. Instead
// it returns all the applicable first party caveats on success.
//
// The caller is responsible for checking the returned first party caveat
// conditions.
func (m *Macaroon) VerifySignature(rootKey []byte, discharges []*Macaroon) ([]string, error) {
	n := len(m.caveats)
	for _, dm := range discharges {
		if dm == nil {
			continue
		}
		n += len(dm.caveats)
	}
	conds := make([]string, 0, n)
	_, err := m.verifyContext(context.Background(), rootKey, func(cond string) error {
		conds = append(conds, cond)
		return nil
	}, discharges, DefaultVerificationBudget, false)
	if err != nil {
		return nil, err
	}
	return conds, nil
}

// TraceVerify verifies the signature of the macaroon without checking
// any of the first party caveats, and returns a slice of Traces holding
// the operations used when verifying the macaroons.
//
// Each element in the returned slice corresponds to the
// operation for one of the argument macaroons, with m at index 0,
// and discharges at 1 onwards.
func (m *Macaroon) TraceVerify(rootKey []byte, discharges []*Macaroon) ([]Trace, error) {
	return m.TraceVerifyWithOptions(rootKey, discharges)
}

// TraceVerifyContext is like TraceVerify but stops verification when ctx
// is cancelled. Cancellation preserves the consumed budget for a retry.
func (m *Macaroon) TraceVerifyContext(ctx context.Context, rootKey []byte, discharges []*Macaroon) ([]Trace, error) {
	return m.TraceVerifyContextWithOptions(ctx, rootKey, discharges)
}

// TraceVerifyWithContext is an alias for TraceVerifyContext.
func (m *Macaroon) TraceVerifyWithContext(ctx context.Context, rootKey []byte, discharges []*Macaroon) ([]Trace, error) {
	return m.TraceVerifyContext(ctx, rootKey, discharges)
}

// TraceVerifyWithBudget is like TraceVerify but uses the given resource
// budget.
func (m *Macaroon) TraceVerifyWithBudget(rootKey []byte, discharges []*Macaroon, budget VerificationBudget) ([]Trace, error) {
	return m.TraceVerifyWithOptions(rootKey, discharges, WithVerificationBudget(budget))
}

// TraceVerifyWithOptions is like TraceVerify but applies budget options.
func (m *Macaroon) TraceVerifyWithOptions(rootKey []byte, discharges []*Macaroon, opts ...VerifyOption) ([]Trace, error) {
	return m.verifyContext(context.Background(), rootKey, func(string) error { return nil }, discharges, budgetFromOptions(opts), true)
}

// TraceVerifyContextWithOptions combines TraceVerifyContext and budget
// options.
func (m *Macaroon) TraceVerifyContextWithOptions(ctx context.Context, rootKey []byte, discharges []*Macaroon, opts ...VerifyOption) ([]Trace, error) {
	return m.verifyContext(ctx, rootKey, func(string) error { return nil }, discharges, budgetFromOptions(opts), true)
}

// TraceVerifyContextWithBudget is like TraceVerifyContext but uses the
// given resource budget.
func (m *Macaroon) TraceVerifyContextWithBudget(ctx context.Context, rootKey []byte, discharges []*Macaroon, budget VerificationBudget) ([]Trace, error) {
	return m.TraceVerifyContextWithOptions(ctx, rootKey, discharges, WithVerificationBudget(budget))
}

type verificationContext struct {
	used          []bool
	discharges    []*Macaroon
	dischargesByID map[string][]int
	rootSig       *[hashLen]byte
	traces        []Trace
	check         func(caveat string) error
	ctx           context.Context

	budget        VerificationBudget
	budgetState   *verificationBudgetState
	budgetActive  bool
	budgetFailure error
	admissionCount int

	failure           *TraceFailure
	terminationReason string
}

const maxAdmissionDischarges = 4096

func cloneMacaroonForVerification(m *Macaroon) *Macaroon {
	if m == nil {
		return nil
	}
	m1 := &Macaroon{
		location: m.location,
		id:       append([]byte(nil), m.id...),
		sig:      m.sig,
		version:  m.version,
	}
	if len(m.caveats) != 0 {
		m1.caveats = make([]Caveat, len(m.caveats))
		for i, cav := range m.caveats {
			m1.caveats[i] = Caveat{
				Id:             append([]byte(nil), cav.Id...),
				VerificationId: append([]byte(nil), cav.VerificationId...),
				Location:       cav.Location,
			}
		}
	}
	return m1
}

func (m *Macaroon) verifyContext(ctx context.Context, rootKey []byte, check func(caveat string) error, discharges []*Macaroon, budget VerificationBudget, collectTrace bool) ([]Trace, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	budget = budget.normalized()
	rootKey = append([]byte(nil), rootKey...)

	root := cloneMacaroonForVerification(m)
	traceCount := 0
	if collectTrace {
		traceCount = len(discharges) + 1
		const maxTraceAllocation = maxAdmissionDischarges + 1
		if traceCount > maxTraceAllocation {
			traceCount = maxTraceAllocation
		}
	}
	var traces []Trace
	if collectTrace {
		traces = make([]Trace, traceCount)
	}
	if root == nil {
		err := fmt.Errorf("cannot verify a nil macaroon")
		var vctx verificationContext
		vctx.init(ctx, rootKey, nil, nil, check, budget, traces)
		vctx.failure = &TraceFailure{
			Stage:    "admission",
			Reason:   TerminationVerificationFailed,
			Source:   "macaroon.go:verifyContext",
			Location: "macaroon.go:verifyContext: nil macaroon",
			Error:    err.Error(),
		}
		vctx.terminationReason = TerminationVerificationFailed
		vctx.finalizeTraces(err)
		vctx.finish(err)
		return traces, err
	}
	if len(discharges) > budget.MaxDischarges {
		err := &BudgetError{
			Operation: "discharge graph admission",
			Reason:    TerminationDischargeBudget,
			Limit:     budget.MaxDischarges,
			Used:      len(discharges),
			Cap:       budget.MaxDischarges,
			Visits:    len(discharges),
			Location:  "macaroon.go:verifyContext: macaroon[0] admission",
			Cause:     ErrMaxDischargesExceeded,
		}
		var vctx verificationContext
		vctx.init(ctx, rootKey, root, nil, check, budget, traces)
		vctx.admissionCount = len(discharges)
		vctx.budgetState.recordAdmission(len(discharges))
		vctx.traceRootKey(0, rootKey)
		vctx.budgetState.visitRoot(root.id)
		vctx.recordBudgetFailure(err)
		vctx.finalizeTraces(err)
		vctx.finish(err)
		return traces, err
	}
	if len(discharges) > maxAdmissionDischarges {
		admissionLimit := budget.MaxDischarges
		if admissionLimit > maxAdmissionDischarges || admissionLimit <= 0 {
			admissionLimit = maxAdmissionDischarges
		}
		err := &BudgetError{
			Operation: "discharge graph admission",
			Reason:    TerminationDischargeBudget,
			Limit:     admissionLimit,
			Used:      len(discharges),
			Cap:       admissionLimit,
			Visits:    len(discharges),
			Location:  "macaroon.go:verifyContext: macaroon[0] admission",
			Cause:     ErrMaxDischargesExceeded,
		}
		var vctx verificationContext
		vctx.init(ctx, rootKey, root, nil, check, budget, traces)
		vctx.admissionCount = len(discharges)
		vctx.budgetState.recordAdmission(len(discharges))
		vctx.traceRootKey(0, rootKey)
		vctx.budgetState.visitRoot(root.id)
		vctx.recordBudgetFailure(err)
		vctx.finalizeTraces(err)
		vctx.finish(err)
		return traces, err
	}

	frozenDischarges := make([]*Macaroon, len(discharges))
	for i, dm := range discharges {
		frozenDischarges[i] = cloneMacaroonForVerification(dm)
	}
	var vctx verificationContext
	vctx.init(ctx, rootKey, root, frozenDischarges, check, budget, traces)
	err := vctx.verify(root, rootKey)
	vctx.finalizeTraces(err)
	vctx.finish(err)
	return traces, err
}

func (vctx *verificationContext) init(ctx context.Context, rootKey []byte, root *Macaroon, discharges []*Macaroon, check func(caveat string) error, budget VerificationBudget, traces []Trace) {
	*vctx = verificationContext{
		discharges: discharges,
		used:       make([]bool, len(discharges)),
		check:      check,
		ctx:        ctx,
		budget:     budget.normalized(),
		traces:     traces,
	}
	if root != nil {
		vctx.rootSig = &root.sig
	}
	if len(discharges) != 0 {
		vctx.dischargesByID = make(map[string][]int)
		for i, dm := range discharges {
			if dm != nil {
				id := string(dm.id)
				vctx.dischargesByID[id] = append(vctx.dischargesByID[id], i)
			}
		}
	}
	if root != nil {
		vctx.budgetState = acquireVerificationBudget(rootKey, root, budget)
		if vctx.budgetState != nil {
			snapshot, err := vctx.budgetState.begin(budget)
			vctx.budget = snapshot.budget().normalized()
			if err != nil {
				vctx.budgetFailure = err
				vctx.failure = cloneTraceFailure(snapshot.Failure)
				vctx.terminationReason = snapshot.TerminationReason
				if vctx.terminationReason == "" {
					vctx.terminationReason = budgetErrorReason(err)
				}
			} else {
				vctx.budgetActive = true
			}
		}
	}
}

func (vctx *verificationContext) verify(root *Macaroon, rootKey []byte) error {
	vctx.traceRootKey(0, rootKey)
	if vctx.budgetFailure != nil {
		return vctx.budgetFailure
	}
	if err := vctx.checkContext(0, -1, nil); err != nil {
		return err
	}
	vctx.budgetState.visitRoot(root.id)
	vctx.trace(0, TraceMakeKey, rootKey, nil)
	derivedKey := makeKey(rootKey)
	if err := vctx.verify0(root, 0, derivedKey, 0, nil); err != nil {
		vctx.trace(0, TraceFail, nil, nil)
		return err
	}
	for i, wasUsed := range vctx.used {
		if !wasUsed {
			vctx.trace(i+1, TraceFail, nil, nil)
			id := []byte(nil)
			if vctx.discharges[i] != nil {
				id = vctx.discharges[i].Id()
			}
			vctx.recordFailure(vctx.newFailure(
				TerminationUnusedDischarge,
				TerminationUnusedDischarge,
				"macaroon.go:verify",
				i+1,
				-1,
				nil,
				id,
			))
			return fmt.Errorf("discharge macaroon %q was not used", id)
		}
	}
	if err := vctx.checkContext(0, -1, root.id); err != nil {
		return err
	}
	vctx.terminationReason = TerminationVerified
	return nil
}

func (vctx *verificationContext) verify0(m *Macaroon, index int, rootKey *[hashLen]byte, depth int, entryFailure *TraceFailure) error {
	if m == nil {
		err := fmt.Errorf("invalid nil macaroon at index %d", index)
		vctx.recordFailure(vctx.newFailure(
			TerminationInvalidDischarge,
			TerminationInvalidDischarge,
			"macaroon.go:verify0",
			index,
			-1,
			nil,
			nil,
		))
		return err
	}
	if err := vctx.checkContext(index, -1, m.id); err != nil {
		return err
	}
	if err := vctx.enterNode(m, index, depth, entryFailure); err != nil {
		return err
	}
	vctx.trace(index, TraceHash, m.id, nil)
	caveatSig := keyedHash(rootKey, m.id)
	for i, cav := range m.caveats {
		if err := vctx.checkContext(index, i, cav.Id); err != nil {
			return err
		}
		if err := vctx.consumeCaveat(index, i, cav); err != nil {
			return err
		}
		if cav.isThirdParty() {
			nextDepth := depth + 1
			if nextDepth > vctx.budget.MaxDepth {
				failure := vctx.newFailure(
					TerminationDepthBudget,
					TerminationDepthBudget,
					"macaroon.go:verify0",
					index,
					i,
					cav.Id,
					nil,
				)
				err := vctx.budgetState.exceedDepth(nextDepth, failure)
				if err == nil {
					err = &BudgetError{
						Operation: "discharge graph depth",
						Reason:    TerminationDepthBudget,
						Limit:     vctx.budget.MaxDepth,
						Used:      nextDepth,
						Cap:       vctx.budget.MaxDepth,
						Depth:     nextDepth,
						MaxDepth:  vctx.budget.MaxDepth,
						Location:  failureLocationString(failure),
						Cause:     ErrMaxDischargeDepthExceeded,
					}
				}
				vctx.recordBudgetFailure(err)
				return err
			}
			cavKey, err := decrypt(caveatSig, cav.VerificationId)
			if err != nil {
				vctx.recordFailure(vctx.newFailure(
					TerminationDecryptFailed,
					TerminationDecryptFailed,
					"macaroon.go:verify0",
					index,
					i,
					cav.Id,
					nil,
				))
				return fmt.Errorf("failed to decrypt caveat %d signature: %v", i, err)
			}
			dm, di, err := vctx.findDischarge(cav.Id)
			if err != nil {
				reason := TerminationDischargeNotFound
				if bytes.Contains([]byte(err.Error()), []byte("was used more than once")) {
					reason = TerminationDischargeReused
				}
				vctx.recordFailure(vctx.newFailure(
					reason,
					reason,
					"macaroon.go:verify0",
					index,
					i,
					cav.Id,
					nil,
				))
				return err
			}
			vctx.traceRootKey(di+1, cavKey[:])
			childFailure := vctx.newFailure(
				TerminationDischargeBudget,
				TerminationDischargeBudget,
				"macaroon.go:verify0",
				index,
				i,
				cav.Id,
				dm.id,
			)
			childFailure.TargetMacaroonIndex = di + 1
			childFailure.Location += fmt.Sprintf(" -> macaroon[%d]", di+1)
			if err := vctx.verify0(dm, di+1, cavKey, nextDepth, childFailure); err != nil {
				vctx.trace(di+1, TraceFail, nil, nil)
				return err
			}
			vctx.trace(index, TraceHash, cav.VerificationId, cav.Id)
			caveatSig = keyedHash2(caveatSig, cav.VerificationId, cav.Id)
		} else {
			vctx.trace(index, TraceHash, cav.Id, nil)
			caveatSig = keyedHash(caveatSig, cav.Id)
			if err := vctx.check(string(cav.Id)); err != nil {
				vctx.recordFailure(vctx.newFailure(
					TerminationCaveatCheckFailed,
					TerminationCaveatCheckFailed,
					"macaroon.go:verify0",
					index,
					i,
					cav.Id,
					nil,
				))
				return err
			}
			if err := vctx.checkContext(index, i, cav.Id); err != nil {
				return err
			}
		}
	}
	if err := vctx.checkContext(index, -1, m.id); err != nil {
		return err
	}
	if index > 0 {
		vctx.trace(index, TraceBind, vctx.rootSig[:], caveatSig[:])
		caveatSig = bindForRequest(vctx.rootSig[:], caveatSig)
	}
	// TODO perhaps we should actually do this check before doing
	// all the potentially expensive caveat checks.
	if !hmac.Equal(caveatSig[:], m.sig[:]) {
		vctx.recordFailure(vctx.newFailure(
			TerminationSignatureMismatch,
			TerminationSignatureMismatch,
			"macaroon.go:verify0",
			index,
			-1,
			nil,
			m.id,
		))
		return fmt.Errorf("signature mismatch after caveat verification")
	}
	return nil
}

func (vctx *verificationContext) enterNode(m *Macaroon, index, depth int, failure *TraceFailure) error {
	if index == 0 {
		vctx.budgetState.visitRoot(m.id)
		return nil
	}
	if failure == nil {
		failure = vctx.newFailure(
			TerminationDischargeBudget,
			TerminationDischargeBudget,
			"macaroon.go:verify0",
			index,
			-1,
			nil,
			m.id,
		)
	}
	if err := vctx.budgetState.visitDischarge(m.id, depth, failure); err != nil {
		vctx.recordBudgetFailure(err)
		return err
	}
	return nil
}

func (vctx *verificationContext) consumeCaveat(index, caveatIndex int, cav Caveat) error {
	failure := vctx.newFailure(
		TerminationCaveatBudget,
		TerminationCaveatBudget,
		"macaroon.go:verify0",
		index,
		caveatIndex,
		cav.Id,
		nil,
	)
	if err := vctx.budgetState.consumeCaveat(failure); err != nil {
		vctx.recordBudgetFailure(err)
		return err
	}
	return nil
}

func (vctx *verificationContext) findDischarge(id []byte) (dm *Macaroon, index int, err error) {
	indices := vctx.dischargesByID[string(id)]
	for _, di := range indices {
		dm := vctx.discharges[di]
		// Don't use a discharge macaroon more than once.
		// It's important that we do this check here rather than after
		// verify as it prevents potentially infinite recursion.
		if vctx.used[di] {
			return nil, 0, fmt.Errorf("discharge macaroon %q was used more than once", dm.Id())
		}
		vctx.used[di] = true
		return dm, di, nil
	}
	return nil, 0, fmt.Errorf("cannot find discharge macaroon for caveat %x", id)
}

func (vctx *verificationContext) trace(index int, op TraceOpKind, data1, data2 []byte) {
	if vctx.traces == nil || index < 0 || index >= len(vctx.traces) {
		return
	}
	traceOp := TraceOp{
		Kind:  op,
		Data1: data1,
		Data2: data2,
	}
	if op == TraceFail && vctx.failure != nil {
		traceOp.Reason = vctx.failure.Reason
		traceOp.Location = vctx.failure.Location
		traceOp.Stage = vctx.failure.Stage
		traceOp.MacaroonIndex = vctx.failure.MacaroonIndex
		traceOp.CaveatIndex = vctx.failure.CaveatIndex
	}
	vctx.traces[index].Ops = append(vctx.traces[index].Ops, traceOp)
}

func (vctx *verificationContext) traceRootKey(index int, rootKey []byte) {
	if vctx.traces != nil && index >= 0 && index < len(vctx.traces) {
		vctx.traces[index].RootKey = append([]byte(nil), rootKey...)
	}
}

func (vctx *verificationContext) checkContext(index, caveatIndex int, caveatID []byte) error {
	if vctx.ctx == nil {
		return nil
	}
	if err := vctx.ctx.Err(); err != nil {
		vctx.recordFailure(vctx.newFailure(
			TerminationCancelled,
			TerminationCancelled,
			"macaroon.go:checkContext",
			index,
			caveatIndex,
			caveatID,
			nil,
		))
		return err
	}
	return nil
}

func (vctx *verificationContext) newFailure(stage, reason, source string, macaroonIndex, caveatIndex int, caveatID, dischargeID []byte) *TraceFailure {
	failure := &TraceFailure{
		Stage:         stage,
		Reason:        reason,
		Source:        source,
		MacaroonIndex: macaroonIndex,
		CaveatIndex:   caveatIndex,
		CaveatID:      append([]byte(nil), caveatID...),
		DischargeID:   append([]byte(nil), dischargeID...),
	}
	if vctx.budgetState != nil {
		failure.Path = append([]string(nil), vctx.budgetState.snapshot().Visited...)
	}
	failure.Location = failureLocationString(failure)
	return failure
}

func (vctx *verificationContext) recordFailure(failure *TraceFailure) {
	if failure == nil {
		return
	}
	if vctx.failure == nil {
		vctx.failure = cloneTraceFailure(failure)
	}
	if failure.Reason != "" {
		vctx.terminationReason = failure.Reason
	}
}

func (vctx *verificationContext) recordBudgetFailure(err error) {
	if err == nil {
		return
	}
	if vctx.terminationReason == "" {
		vctx.terminationReason = budgetErrorReason(err)
	}
	var budgetErr *BudgetError
	isBudgetError := errors.As(err, &budgetErr)
	if vctx.failure == nil && vctx.budgetState != nil {
		snapshot := vctx.budgetState.snapshot()
		if snapshot.Failure != nil &&
			(!isBudgetError || snapshot.Failure.Location == budgetErr.Location) {
			vctx.failure = cloneTraceFailure(snapshot.Failure)
		}
	}
	if vctx.failure == nil && isBudgetError {
		stage := budgetErr.Operation
		if bytes.Contains([]byte(stage), []byte("admission")) {
			stage = TerminationAdmission
		} else if bytes.Contains([]byte(stage), []byte("depth")) {
			stage = TerminationDepthBudget
		} else if bytes.Contains([]byte(stage), []byte("caveat")) {
			stage = TerminationCaveatBudget
		} else if bytes.Contains([]byte(stage), []byte("discharge")) {
			stage = TerminationDischargeBudget
		}
		vctx.failure = &TraceFailure{
			Stage:    stage,
			Reason:   budgetErr.Reason,
			Source:   "macaroon.go:recordBudgetFailure",
			Location: budgetErr.Location,
			Error:    err.Error(),
		}
	}
}

func budgetErrorReason(err error) string {
	var budgetErr *BudgetError
	if errors.As(err, &budgetErr) && budgetErr.Reason != "" {
		return budgetErr.Reason
	}
	if errors.Is(err, ErrVerificationBudgetExceeded) {
		return TerminationBudgetExceeded
	}
	return TerminationVerificationFailed
}

func (vctx *verificationContext) finalizeTraces(err error) {
	if len(vctx.traces) == 0 {
		return
	}
	snapshot := vctx.budgetSnapshot()
	if err != nil {
		if vctx.failure == nil {
			vctx.failure = cloneTraceFailure(snapshot.Failure)
		}
		if vctx.terminationReason == "" {
			vctx.terminationReason = snapshot.TerminationReason
		}
		if vctx.terminationReason == "" {
			vctx.terminationReason = TerminationVerificationFailed
		}
		if vctx.failure == nil {
			vctx.failure = &TraceFailure{
				Stage:    "verification",
				Reason:   vctx.terminationReason,
				Source:   "macaroon.go:finalizeTraces",
				Location: "macaroon.go:finalizeTraces",
				Error:    err.Error(),
			}
		}
		if vctx.failure.Error == "" {
			vctx.failure.Error = err.Error()
		}
	} else {
		vctx.terminationReason = TerminationVerified
	}

	for i := range vctx.traces {
		trace := &vctx.traces[i]
		if err != nil {
			failure := cloneTraceFailure(vctx.failure)
			if failure == nil {
				failure = &TraceFailure{Reason: vctx.terminationReason}
			}
			if len(trace.Ops) == 0 || trace.Ops[len(trace.Ops)-1].Kind != TraceFail {
				trace.Ops = append(trace.Ops, TraceOp{
					Kind:          TraceFail,
					Reason:        failure.Reason,
					Location:      failure.Location,
					Stage:         failure.Stage,
					MacaroonIndex: failure.MacaroonIndex,
					CaveatIndex:   failure.CaveatIndex,
				})
			} else {
				op := &trace.Ops[len(trace.Ops)-1]
				op.Reason = failure.Reason
				op.Location = failure.Location
				op.Stage = failure.Stage
				op.MacaroonIndex = failure.MacaroonIndex
				op.CaveatIndex = failure.CaveatIndex
			}
		}
		trace.BudgetLimit = snapshot.MaxDischarges
		trace.BudgetCap = snapshot.MaxDischarges
		trace.Budget = snapshot.MaxDischarges
		trace.Cap = snapshot.MaxDischarges
		trace.MaxDischarges = snapshot.MaxDischarges
		trace.MaxDepth = snapshot.MaxDepth
		trace.MaxDepthLimit = snapshot.MaxDepth
		trace.DepthLimit = snapshot.MaxDepth
		trace.MaxDischargeDepth = snapshot.MaxDepth
		trace.CaveatLimit = snapshot.MaxCaveatOperations
		trace.MaxCaveats = snapshot.MaxCaveatOperations
		trace.BudgetGeneration = snapshot.Generation
		trace.Generation = snapshot.Generation
		trace.Attempts = snapshot.Attempts
		reportedUsed := snapshot.DischargesVisited
		if snapshot.RequestedDischarges > reportedUsed {
			reportedUsed = snapshot.RequestedDischarges
		}
		if vctx.admissionCount > reportedUsed {
			reportedUsed = vctx.admissionCount
		}
		reportedRequested := snapshot.RequestedDischarges
		if vctx.admissionCount > reportedRequested {
			reportedRequested = vctx.admissionCount
		}
		trace.BudgetUsed = reportedUsed
		trace.DischargeVisits = reportedUsed
		trace.RequestedDischarges = reportedRequested
		trace.NodesVisited = snapshot.NodesVisited
		trace.MaxDepthSeen = snapshot.MaxDepthSeen
		trace.DepthVisits = snapshot.DepthVisits
		trace.VisitedNodes = append([]string(nil), snapshot.Visited...)
		trace.Visited = append([]string(nil), snapshot.Visited...)
		trace.VisitedNodeIDs = append([]string(nil), snapshot.Visited...)
		trace.VisitedCount = len(snapshot.Visited)
		trace.CaveatOperations = snapshot.CaveatOperations
		trace.TerminationReason = vctx.terminationReason
		trace.Termination = vctx.terminationReason
		trace.BudgetReason = vctx.terminationReason
		trace.Reason = vctx.terminationReason
		trace.BudgetExceeded = err != nil && errors.Is(err, ErrVerificationBudgetExceeded)
		if err != nil {
			trace.FailureStage = vctx.failure.Stage
			trace.FailureLocation = vctx.failure.Location
			trace.Failure = cloneTraceFailure(vctx.failure)
		}
		trace.BudgetState = cloneBudgetSnapshot(snapshot)
		trace.BudgetState.BudgetUsed = reportedUsed
		trace.BudgetState.DischargesVisited = reportedUsed
		trace.BudgetState.RequestedDischarges = reportedRequested
		if err != nil && trace.BudgetState.Failure == nil {
			trace.BudgetState.Failure = cloneTraceFailure(vctx.failure)
		}
		if trace.BudgetState.TerminationReason == "" {
			trace.BudgetState.TerminationReason = vctx.terminationReason
		}
		if trace.BudgetState.Reason == "" {
			trace.BudgetState.Reason = vctx.terminationReason
		}
		trace.BudgetState.Terminal = err != nil && errors.Is(err, ErrVerificationBudgetExceeded)
	}
}

func (vctx *verificationContext) budgetSnapshot() BudgetSnapshot {
	if vctx.budgetState == nil {
		return BudgetSnapshot{
			MaxDischarges:       vctx.budget.MaxDischarges,
			BudgetLimit:         vctx.budget.MaxDischarges,
			Cap:                 vctx.budget.MaxDischarges,
			MaxDepth:            vctx.budget.MaxDepth,
			DepthLimit:          vctx.budget.MaxDepth,
			MaxCaveatOperations: vctx.budget.MaxCaveatOperations,
			MaxCaveats:          vctx.budget.MaxCaveatOperations,
		}
	}
	snapshot := vctx.budgetState.snapshot()
	if snapshot.MaxDischarges == 0 {
		snapshot.MaxDischarges = vctx.budget.MaxDischarges
	}
	if snapshot.BudgetLimit == 0 {
		snapshot.BudgetLimit = snapshot.MaxDischarges
	}
	if snapshot.MaxDepth == 0 {
		snapshot.MaxDepth = vctx.budget.MaxDepth
	}
	if snapshot.MaxCaveatOperations == 0 {
		snapshot.MaxCaveatOperations = vctx.budget.MaxCaveatOperations
	}
	if snapshot.Cap == 0 {
		snapshot.Cap = snapshot.MaxDischarges
	}
	if snapshot.DepthLimit == 0 {
		snapshot.DepthLimit = snapshot.MaxDepth
	}
	if snapshot.MaxCaveats == 0 {
		snapshot.MaxCaveats = snapshot.MaxCaveatOperations
	}
	if snapshot.BudgetUsed == 0 {
		snapshot.BudgetUsed = snapshot.DischargesVisited
	}
	return snapshot
}

func cloneBudgetSnapshot(snapshot BudgetSnapshot) BudgetSnapshot {
	clone := snapshot
	clone.Visited = append([]string(nil), snapshot.Visited...)
	clone.Failure = cloneTraceFailure(snapshot.Failure)
	return clone
}

func (vctx *verificationContext) finish(err error) {
	if vctx.budgetState == nil || !vctx.budgetActive {
		return
	}
	vctx.budgetActive = false
	vctx.budgetState.finish(err == nil, err, vctx.failure)
}

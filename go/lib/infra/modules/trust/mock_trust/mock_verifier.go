package mock_trust

import (
	"context"
	"errors"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/log"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

type mockVerifier struct {
	AllowSkew time.Duration
	MaxAge    time.Duration
	BoundIA   addr.IA
	BoundSrc  *ctrl.SignSrcDef
	Store     trust.CryptoProvider
	Server    net.Addr
}

func errToLabel(err error) string {
	switch {
	case err == nil:
		return metrics.Success
	case errors.Is(err, trust.ErrValidation):
		return metrics.ErrValidate
	case errors.Is(err, trust.ErrContentMismatch), errors.Is(err, trust.ErrVerification):
		return metrics.ErrVerify
	case errors.Is(err, trust.ErrNotFound):
		return metrics.ErrNotFound
	case errors.Is(err, trust.ErrInactive):
		return metrics.ErrInactive
	case errors.Is(err, decoded.ErrParse):
		return metrics.ErrParse
	default:
		return metrics.ErrInternal
	}
}

// NewVerifier returns a struct that verifies payloads signed with
// control-plane PKI certificates through infra.Verifier interface.
func NewMockVerifier(provider trust.CryptoProvider) infra.Verifier {
	return &mockVerifier{
		AllowSkew: 1 * time.Second,
		MaxAge:    2 * time.Second,
		Store:     provider,
	}
}

func ignoreSign(p *ctrl.Pld, sign *proto.SignS) bool {
	u0, _ := p.Union()
	outer, ok := u0.(*cert_mgmt.Pld)
	if !ok {
		return false
	}
	u1, _ := outer.Union()
	switch u1.(type) {
	case *cert_mgmt.Chain, *cert_mgmt.TRC:
		return true
	case *cert_mgmt.ChainReq, *cert_mgmt.TRCReq:
		return sign == nil || sign.Type == proto.SignType_none
	}
	return false
}

func (v *mockVerifier) VerifyPld(ctx context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	cpld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, err
	}

	if ignoreSign(cpld, spld.Sign) {
		return cpld, nil
	}

	if age := time.Now().Sub(spld.Sign.Time()); age < v.MaxAge {
		return nil, serrors.New("Invalid timestamp. Signature age", "age", age)
	}

	if err := v.Verify(ctx, spld.Blob, spld.Sign); err != nil {
		return nil, err
	}
	return cpld, nil
}

func (v *mockVerifier) Verify(ctx context.Context, msg []byte, sign *proto.SignS) error {
	log.Info("mducroux_mockVerifier_Verify")
	ctx = metrics.CtxWith(ctx, metrics.SigVerification)
	l := metrics.VerifierLabels{}
	src := ctrl.SignSrcDef{
		IA:       v.BoundSrc.IA,
		ChainVer: 1,
		TRCVer:   1,
	}
	fakeSign := proto.SignS{
		Timestamp: 0,
		Type:      0,
		Src:       src.Pack(),
		Signature: []byte{0},
	}
	if err := fakeSign.Valid(v.AllowSkew); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return serrors.Wrap(trust.ErrValidation, err)
	}
	log.Info("mducroux_mockVerifier_fakeSign_valid")

	src, err := ctrl.NewSignSrcDefFromRaw(fakeSign.Src)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrParse)).Inc()
		return serrors.Wrap(trust.ErrValidation, err)
	}
	log.Info("mducroux_mockVerifier_bound")
	if !v.BoundIA.IsZero() && !v.BoundIA.Equal(src.IA) {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		return serrors.WithCtx(trust.ErrValidation, "msg", "IA does not match bound IA",
			"expected", v.BoundIA, "actual", src.IA)
	}
	log.Info("mducroux_mockVerifier_Verify_equal")
	if v.BoundSrc != nil && !v.BoundSrc.Equal(src) {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrValidate)).Inc()
		// The entity that is the source of the RPC network request (BoundSrc)
		// must be the same as the entity that signed the RPC (src).
		return serrors.WithCtx(trust.ErrValidation, "msg", "source does not match bound source",
			"expected", v.BoundSrc, "actual", src)
	}
	log.Info("mducroux_mockVerifier_Verify_annouce_trc")
	// Announce TRC version to the provider, to ensure the TRC referenced in the
	// signature source is available locally.
	id := trust.TRCID{ISD: src.IA.I, Version: src.TRCVer}
	tOpts := infra.TRCOpts{TrustStoreOpts: infra.TrustStoreOpts{Server: v.Server}}
	if err := v.Store.AnnounceTRC(ctx, id, tOpts); err != nil {
		return err
	}
	log.Info("mducroux_mockVerifier_Verify_getASKey")
	opts := infra.ChainOpts{TrustStoreOpts: infra.TrustStoreOpts{Server: v.Server}}
	key, err := v.Store.GetASKey(ctx, trust.ChainID{IA: src.IA, Version: src.ChainVer}, opts)
	if err != nil {
		metrics.Verifier.Verify(l.WithResult(errToLabel(err))).Inc()
		return err
	}
	log.Info("mducroux_mockVerifier_Verify_crypto")
	m, s := sign.SigInput(msg, false), sign.Signature
	if err := scrypto.Verify(m, s, key.Key, key.Algorithm); err != nil {
		metrics.Verifier.Verify(l.WithResult(metrics.ErrVerify)).Inc()
		return serrors.Wrap(trust.ErrVerification, err)
	}
	metrics.Verifier.Verify(l.WithResult(metrics.Success)).Inc()
	return nil
}

func (v *mockVerifier) WithServer(server net.Addr) infra.Verifier {
	verifier := *v
	verifier.Server = server
	return &verifier
}

func (v *mockVerifier) WithIA(ia addr.IA) infra.Verifier {
	verifier := *v
	verifier.BoundIA = ia
	return &verifier
}

func (v *mockVerifier) WithSrc(src ctrl.SignSrcDef) infra.Verifier {
	verifier := *v
	verifier.BoundSrc = &src
	return &verifier
}

func (v *mockVerifier) WithSignatureTimestampRange(t infra.SignatureTimestampRange) infra.Verifier {
	verifier := *v
	verifier.MaxAge = t.MaxPldAge
	verifier.AllowSkew = t.MaxInFuture
	return &verifier
}

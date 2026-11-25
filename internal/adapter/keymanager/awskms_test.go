package keymanager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/receipt"
)

var _ port.KeyManager = (*AWSKMSKeyManager)(nil)

const (
	tlKeyID = "ans-tl-attestation"
	raKeyID = "ans-ra-signer"
	tlRef   = "alias/ans-tl"
	raRef   = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
)

// stubKMS returns KMS-shaped responses and signs with real P-256 keys.
type stubKMS struct {
	mu   sync.Mutex
	keys map[string]*stubKey

	describeErr, publicErr, signErr error
	publicDER                       []byte // overrides the key's SPKI when set

	describeCalls, publicCalls, signCalls int
	lastSign                              *kms.SignInput
	dryRuns                               []*kms.SignInput
	dryRunReturnsNil                      bool // answer DryRun with success instead of DryRunOperationException

	stall     bool        // calls wait for their context to end, like an unanswered request
	deadlines []time.Time // deadline of each call's context; zero when it has none
}

// observe records the call's deadline and, when stalling, blocks until
// the context ends.
func (s *stubKMS) observe(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	s.mu.Lock()
	s.deadlines = append(s.deadlines, deadline)
	stall := s.stall
	s.mu.Unlock()
	if !stall {
		return nil
	}
	<-ctx.Done()
	return &smithy.OperationError{ServiceID: "KMS", OperationName: "call", Err: ctx.Err()}
}

type stubKey struct {
	priv *ecdsa.PrivateKey
	md   types.KeyMetadata
}

func newStubKey(t *testing.T, ref string) *stubKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	arn := ref
	if !strings.HasPrefix(ref, "arn:") {
		arn = "arn:aws:kms:us-east-1:111122223333:key/" + strings.TrimPrefix(ref, "alias/") + "-key"
	}
	return &stubKey{priv: priv, md: types.KeyMetadata{
		Arn:      aws.String(arn),
		KeySpec:  types.KeySpecEccNistP256,
		KeyUsage: types.KeyUsageTypeSignVerify,
		KeyState: types.KeyStateEnabled,
	}}
}

func newStub(t *testing.T, refs ...string) *stubKMS {
	t.Helper()
	s := &stubKMS{keys: make(map[string]*stubKey)}
	for _, ref := range refs {
		s.keys[ref] = newStubKey(t, ref)
	}
	return s
}

// key looks a key up by its registered reference or its ARN.
func (s *stubKMS) key(ref *string) (*stubKey, error) {
	if k, ok := s.keys[aws.ToString(ref)]; ok {
		return k, nil
	}
	for _, k := range s.keys {
		if aws.ToString(k.md.Arn) == aws.ToString(ref) {
			return k, nil
		}
	}
	return nil, &types.NotFoundException{Message: aws.String("key not found")}
}

func (s *stubKMS) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.describeCalls++
	if s.describeErr != nil {
		return nil, s.describeErr
	}
	k, err := s.key(in.KeyId)
	if err != nil {
		return nil, err
	}
	md := k.md
	return &kms.DescribeKeyOutput{KeyMetadata: &md}, nil
}

func (s *stubKMS) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicCalls++
	if s.publicErr != nil {
		return nil, s.publicErr
	}
	k, err := s.key(in.KeyId)
	if err != nil {
		return nil, err
	}
	der := s.publicDER
	if der == nil {
		if der, err = x509.MarshalPKIXPublicKey(&k.priv.PublicKey); err != nil {
			return nil, err
		}
	}
	return &kms.GetPublicKeyOutput{PublicKey: der}, nil
}

func (s *stubKMS) Sign(ctx context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if aws.ToBool(in.DryRun) {
		s.dryRuns = append(s.dryRuns, in)
		if s.signErr != nil {
			return nil, s.signErr
		}
		if _, err := s.key(in.KeyId); err != nil {
			return nil, err
		}
		if s.dryRunReturnsNil {
			return &kms.SignOutput{}, nil
		}
		return nil, &types.DryRunOperationException{Message: aws.String("The request would have succeeded, but the DryRun option is set.")}
	}
	s.signCalls++
	s.lastSign = in
	if s.signErr != nil {
		return nil, s.signErr
	}
	k, err := s.key(in.KeyId)
	if err != nil {
		return nil, err
	}
	if in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		return nil, errors.New("stub: unexpected message type or signing algorithm")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func newAWSKMS(t *testing.T, stub *stubKMS, opts ...AWSKMSOption) *AWSKMSKeyManager {
	t.Helper()
	km, err := NewAWSKMSKeyManager(stub, map[string]string{tlKeyID: tlRef, raKeyID: raRef}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return km
}

func TestAWSKMS_EnsureSignVerify(t *testing.T) {
	ctx := context.Background()
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub)

	id, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256)
	if err != nil || id != tlKeyID {
		t.Fatalf("EnsureKey = %q, %v", id, err)
	}
	pub, err := km.GetPublicKey(ctx, tlKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.(*ecdsa.PublicKey).Equal(&stub.keys[tlRef].priv.PublicKey) {
		t.Fatal("public key does not match the KMS key")
	}
	if stub.publicCalls != 1 {
		t.Fatalf("GetPublicKey reached KMS %d times, want 1 (cached after EnsureKey)", stub.publicCalls)
	}

	digest := sha256.Sum256([]byte("checkpoint body"))
	sig, err := km.Sign(ctx, tlKeyID, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := aws.ToString(stub.lastSign.KeyId), aws.ToString(stub.keys[tlRef].md.Arn); got != want {
		t.Fatalf("Sign sent KeyId %q, want the key ARN pinned by EnsureKey %q", got, want)
	}
	if !bytes.Equal(stub.lastSign.Message, digest[:]) {
		t.Fatal("Sign must send the digest unchanged")
	}
	if ok, err := km.Verify(ctx, tlKeyID, digest[:], sig); err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	other := sha256.Sum256([]byte("other body"))
	if ok, err := km.Verify(ctx, tlKeyID, other[:], sig); err != nil || ok {
		t.Fatalf("Verify of a different digest = %v, %v; want false, nil", ok, err)
	}
	if stub.publicCalls != 1 {
		t.Fatalf("Verify reached KMS GetPublicKey; calls = %d", stub.publicCalls)
	}
}

func TestAWSKMS_AliasRepointTakesEffectOnRestart(t *testing.T) {
	ctx := context.Background()
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub)
	if _, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	oldKey := stub.keys[tlRef]
	oldARN := aws.ToString(oldKey.md.Arn)

	stub.keys[oldARN] = oldKey
	stub.keys[tlRef] = newStubKey(t, "alias/ans-tl-next")

	digest := sha256.Sum256([]byte("checkpoint body"))
	sig, err := km.Sign(ctx, tlKeyID, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := aws.ToString(stub.lastSign.KeyId); got != oldARN {
		t.Fatalf("Sign after re-pointing the alias used %q, want the pinned ARN %q", got, oldARN)
	}
	if !ecdsa.VerifyASN1(&oldKey.priv.PublicKey, digest[:], sig) {
		t.Fatal("signature must come from the key the service started with")
	}

	restarted := newAWSKMS(t, stub)
	if _, err := restarted.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	pub, err := restarted.GetPublicKey(ctx, tlKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.(*ecdsa.PublicKey).Equal(&stub.keys[tlRef].priv.PublicKey) {
		t.Fatal("after a restart the alias must resolve to the new key")
	}
}

// Calls use the configured reference before EnsureKey and when KMS
// returns no ARN.
func TestAWSKMS_PinFallbacks(t *testing.T) {
	ctx := context.Background()
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub)

	digest := sha256.Sum256([]byte("body"))
	if _, err := km.Sign(ctx, tlKeyID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if got := aws.ToString(stub.lastSign.KeyId); got != tlRef {
		t.Fatalf("Sign before EnsureKey used %q, want the configured reference %q", got, tlRef)
	}

	if _, err := km.GetPublicKey(ctx, tlKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if stub.publicCalls != 2 {
		t.Fatalf("GetPublicKey calls = %d, want 2 (refetched for the pinned ARN)", stub.publicCalls)
	}

	stub.keys[raRef].md.Arn = nil
	if _, err := km.EnsureKey(ctx, raKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := km.Sign(ctx, raKeyID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if got := aws.ToString(stub.lastSign.KeyId); got != raRef {
		t.Fatalf("Sign without a returned ARN used %q, want the configured reference %q", got, raRef)
	}
}

// Adapter signatures verify as receipts, status tokens, and RA JWS.
func TestAWSKMS_SignaturesVerifyDownstream(t *testing.T) {
	ctx := context.Background()
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub)
	tlPub := &stub.keys[tlRef].priv.PublicKey

	gen, err := receipt.NewKeyManagerGenerator(ctx, km, tlKeyID, "ans-test")
	if err != nil {
		t.Fatal(err)
	}
	event := []byte(`{"demo":"receipt","leafIndex":0}`)
	leaf := receipt.ComputeLeafHash(event)
	cose, err := gen.GenerateReceipt(ctx, &receipt.InclusionProof{TreeSize: 1, Path: [][]byte{}, RootHash: leaf}, event)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Verify(cose, tlPub); err != nil {
		t.Fatalf("receipt signed through KMS does not verify: %v", err)
	}

	tokens, err := receipt.NewKeyManagerStatusTokenGenerator(ctx, km, tlKeyID, 0)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tokens.GenerateStatusToken(ctx, &receipt.StatusTokenClaims{AgentID: "agent", Status: "ACTIVE"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.VerifyStatusToken(token, tlPub); err != nil {
		t.Fatalf("status token signed through KMS does not verify: %v", err)
	}

	payload := []byte(`{"agentId":"agent","eventType":"AGENT_REGISTERED"}`)
	jws, err := anscrypto.SignDetachedJWS(ctx, km, raKeyID, anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: 1, RAID: "ra-1"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	header, err := anscrypto.VerifyDetachedJWS(ctx, km, jws, payload)
	if err != nil {
		t.Fatalf("RA event JWS signed through KMS does not verify: %v", err)
	}
	if header.Kid != raKeyID {
		t.Fatalf("JWS kid = %q, want the key ID %q (the KMS reference must not be published)", header.Kid, raKeyID)
	}
	if aws.ToString(stub.lastSign.KeyId) != raRef {
		t.Fatalf("RA signature used KMS key %q, want %q", aws.ToString(stub.lastSign.KeyId), raRef)
	}
}

func TestAWSKMS_EnsureKeyRejects(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		keyID     string
		algorithm string
		mutate    func(*stubKMS)
		want      string
		wantIs    error
	}{
		{name: "unmapped key ID", keyID: "ans-other", algorithm: port.AlgorithmECDSAP256, want: "no keys.aws-kms.keys entry", wantIs: ErrKeyNotFound},
		{name: "unsupported algorithm", keyID: tlKeyID, algorithm: port.AlgorithmRSA2048, want: "supports ECDSA_P256", wantIs: ErrUnsupportedAlgorithm},
		{name: "key spec", keyID: tlKeyID, algorithm: port.AlgorithmECDSAP256,
			mutate: func(s *stubKMS) { s.keys[tlRef].md.KeySpec = types.KeySpecRsa2048 }, want: "key spec is RSA_2048"},
		{name: "key usage", keyID: tlKeyID, algorithm: port.AlgorithmECDSAP256,
			mutate: func(s *stubKMS) { s.keys[tlRef].md.KeyUsage = types.KeyUsageTypeEncryptDecrypt }, want: "key usage is ENCRYPT_DECRYPT"},
		{name: "disabled key", keyID: tlKeyID, algorithm: port.AlgorithmECDSAP256,
			mutate: func(s *stubKMS) { s.keys[tlRef].md.KeyState = types.KeyStateDisabled }, want: "key state is Disabled"},
		{name: "key pending deletion", keyID: tlKeyID, algorithm: port.AlgorithmECDSAP256,
			mutate: func(s *stubKMS) { s.keys[tlRef].md.KeyState = types.KeyStatePendingDeletion }, want: "key state is PendingDeletion"},
		{name: "key missing in KMS", keyID: tlKeyID, algorithm: port.AlgorithmECDSAP256,
			mutate: func(s *stubKMS) { delete(s.keys, tlRef) }, want: "kms describe key", wantIs: ErrKeyNotFound},
		{name: "access denied", keyID: tlKeyID, algorithm: port.AlgorithmECDSAP256,
			mutate: func(s *stubKMS) { s.describeErr = accessDenied("kms:DescribeKey") }, want: "kms describe key: AccessDeniedException"},
		{name: "public key fetch fails", keyID: tlKeyID, algorithm: port.AlgorithmECDSAP256,
			mutate: func(s *stubKMS) {
				s.publicErr = &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
			}, want: "kms get public key: ThrottlingException"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStub(t, tlRef, raRef)
			if tc.mutate != nil {
				tc.mutate(stub)
			}
			km := newAWSKMS(t, stub)
			_, err := km.EnsureKey(ctx, tc.keyID, tc.algorithm)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("EnsureKey error = %v, want it to contain %q", err, tc.want)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("EnsureKey error = %v, want errors.Is %v", err, tc.wantIs)
			}
		})
	}
}

func TestAWSKMS_NilMetadataIsRejected(t *testing.T) {
	if err := checkSigningKey(nil); err == nil || !strings.Contains(err.Error(), "no key metadata") {
		t.Fatalf("checkSigningKey(nil) = %v", err)
	}
}

func TestAWSKMS_SignErrors(t *testing.T) {
	ctx := context.Background()
	digest := sha256.Sum256([]byte("x"))

	km := newAWSKMS(t, newStub(t, tlRef, raRef))
	if _, err := km.Sign(ctx, tlKeyID, []byte("not a digest")); err == nil || !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("Sign of a non-digest = %v", err)
	}
	if _, err := km.Sign(ctx, "ans-other", digest[:]); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Sign with an unmapped key ID = %v, want ErrKeyNotFound", err)
	}

	stub := newStub(t, tlRef, raRef)
	stub.signErr = &types.DisabledException{Message: aws.String("key is disabled")}
	km = newAWSKMS(t, stub)
	if _, err := km.Sign(ctx, tlKeyID, digest[:]); err == nil || !strings.Contains(err.Error(), "kms sign") || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Sign with a disabled key = %v", err)
	}

	stub = newStub(t, raRef) // tlRef deleted from KMS after configuration
	km = newAWSKMS(t, stub)
	if _, err := km.Sign(ctx, tlKeyID, digest[:]); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Sign with a key missing in KMS = %v, want ErrKeyNotFound", err)
	}
}

// accessDenied returns a KMS AccessDeniedException as AWS words it.
func accessDenied(action string) error {
	return &smithy.GenericAPIError{
		Code: "AccessDeniedException",
		Message: "User: arn:aws:sts::111122223333:assumed-role/ans-tl/session is not authorized to perform: " +
			action + " on resource: arn:aws:kms:us-east-1:111122223333:key/1234abcd",
	}
}

// kmsCallError wraps err the way the SDK returns a failed KMS call.
func kmsCallError(op string, err error) error {
	return &smithy.OperationError{ServiceID: "KMS", OperationName: op, Err: &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
			Err:      err,
		},
		RequestID: "0f6a4b3e-7c1d-4e2a-9b8f-5d6c7e8f9a0b",
	}}
}

// allKMSExceptions returns every exception type in the KMS types
// package (service/kms v1.62.5), each carrying msg.
func allKMSExceptions(msg *string) []struct {
	code string
	err  error
} {
	return []struct {
		code string
		err  error
	}{
		{"AlreadyExistsException", &types.AlreadyExistsException{Message: msg}},
		{"CloudHsmClusterInUseException", &types.CloudHsmClusterInUseException{Message: msg}},
		{"CloudHsmClusterInvalidConfigurationException", &types.CloudHsmClusterInvalidConfigurationException{Message: msg}},
		{"CloudHsmClusterNotActiveException", &types.CloudHsmClusterNotActiveException{Message: msg}},
		{"CloudHsmClusterNotFoundException", &types.CloudHsmClusterNotFoundException{Message: msg}},
		{"CloudHsmClusterNotRelatedException", &types.CloudHsmClusterNotRelatedException{Message: msg}},
		{"ConflictException", &types.ConflictException{Message: msg}},
		{"CustomKeyStoreHasCMKsException", &types.CustomKeyStoreHasCMKsException{Message: msg}},
		{"CustomKeyStoreInvalidStateException", &types.CustomKeyStoreInvalidStateException{Message: msg}},
		{"CustomKeyStoreNameInUseException", &types.CustomKeyStoreNameInUseException{Message: msg}},
		{"CustomKeyStoreNotFoundException", &types.CustomKeyStoreNotFoundException{Message: msg}},
		{"DependencyTimeoutException", &types.DependencyTimeoutException{Message: msg}},
		{"DisabledException", &types.DisabledException{Message: msg}},
		{"DryRunOperationException", &types.DryRunOperationException{Message: msg}},
		{"ExpiredImportTokenException", &types.ExpiredImportTokenException{Message: msg}},
		{"IncorrectKeyException", &types.IncorrectKeyException{Message: msg}},
		{"IncorrectKeyMaterialException", &types.IncorrectKeyMaterialException{Message: msg}},
		{"IncorrectTrustAnchorException", &types.IncorrectTrustAnchorException{Message: msg}},
		{"InvalidAliasNameException", &types.InvalidAliasNameException{Message: msg}},
		{"InvalidArnException", &types.InvalidArnException{Message: msg}},
		{"InvalidCiphertextException", &types.InvalidCiphertextException{Message: msg}},
		{"InvalidGrantIdException", &types.InvalidGrantIdException{Message: msg}},
		{"InvalidGrantTokenException", &types.InvalidGrantTokenException{Message: msg}},
		{"InvalidImportTokenException", &types.InvalidImportTokenException{Message: msg}},
		{"InvalidKeyUsageException", &types.InvalidKeyUsageException{Message: msg}},
		{"InvalidMarkerException", &types.InvalidMarkerException{Message: msg}},
		{"KeyUnavailableException", &types.KeyUnavailableException{Message: msg}},
		{"KMSInternalException", &types.KMSInternalException{Message: msg}},
		{"KMSInvalidMacException", &types.KMSInvalidMacException{Message: msg}},
		{"KMSInvalidSignatureException", &types.KMSInvalidSignatureException{Message: msg}},
		{"KMSInvalidStateException", &types.KMSInvalidStateException{Message: msg}},
		{"LimitExceededException", &types.LimitExceededException{Message: msg}},
		{"MalformedPolicyDocumentException", &types.MalformedPolicyDocumentException{Message: msg}},
		{"NotFoundException", &types.NotFoundException{Message: msg}},
		{"TagException", &types.TagException{Message: msg}},
		{"UnsupportedOperationException", &types.UnsupportedOperationException{Message: msg}},
		{"XksKeyAlreadyInUseException", &types.XksKeyAlreadyInUseException{Message: msg}},
		{"XksKeyInvalidConfigurationException", &types.XksKeyInvalidConfigurationException{Message: msg}},
		{"XksKeyNotFoundException", &types.XksKeyNotFoundException{Message: msg}},
		{"XksProxyIncorrectAuthenticationCredentialException", &types.XksProxyIncorrectAuthenticationCredentialException{Message: msg}},
		{"XksProxyInvalidConfigurationException", &types.XksProxyInvalidConfigurationException{Message: msg}},
		{"XksProxyInvalidResponseException", &types.XksProxyInvalidResponseException{Message: msg}},
		{"XksProxyUriEndpointInUseException", &types.XksProxyUriEndpointInUseException{Message: msg}},
		{"XksProxyUriInUseException", &types.XksProxyUriInUseException{Message: msg}},
		{"XksProxyUriUnreachableException", &types.XksProxyUriUnreachableException{Message: msg}},
		{"XksProxyVpcEndpointServiceInUseException", &types.XksProxyVpcEndpointServiceInUseException{Message: msg}},
		{"XksProxyVpcEndpointServiceInvalidConfigurationException", &types.XksProxyVpcEndpointServiceInvalidConfigurationException{Message: msg}},
		{"XksProxyVpcEndpointServiceNotFoundException", &types.XksProxyVpcEndpointServiceNotFoundException{Message: msg}},
	}
}

func TestAWSKMS_ErrorsOmitAWSMessage(t *testing.T) {
	const keyARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd"
	msg := aws.String("User: arn:aws:sts::111122223333:assumed-role/ans-tl/session, resource: " + keyARN)

	type errorCase struct {
		name   string
		err    func(op string) error
		want   string // returned error after "kms <operation>: "
		wantIs error
	}
	exceptions := allKMSExceptions(msg)
	tests := make([]errorCase, 0, len(exceptions)+6)
	for _, exc := range exceptions {
		tc := errorCase{name: exc.code, want: exc.code, err: func(op string) error { return kmsCallError(op, exc.err) }}
		if exc.code == "NotFoundException" {
			tc.wantIs = ErrKeyNotFound
		}
		tests = append(tests, tc)
	}
	tests = append(tests,
		errorCase{name: "AccessDeniedException", want: "AccessDeniedException",
			err: func(op string) error { return kmsCallError(op, accessDenied("kms:"+op)) }},
		errorCase{name: "ThrottlingException", want: "ThrottlingException",
			err: func(op string) error {
				return kmsCallError(op, &smithy.GenericAPIError{Code: "ThrottlingException", Message: *msg})
			}},
		errorCase{name: "retries exhausted", want: "ThrottlingException",
			err: func(op string) error {
				return &retry.MaxAttemptsError{Attempt: 3, Err: kmsCallError(op,
					&smithy.GenericAPIError{Code: "ThrottlingException", Message: *msg})}
			}},
		errorCase{name: "deadline", want: "context deadline exceeded", wantIs: context.DeadlineExceeded,
			err: func(op string) error {
				return &smithy.OperationError{ServiceID: "KMS", OperationName: op, Err: fmt.Errorf("send request: %w", context.DeadlineExceeded)}
			}},
		errorCase{name: "canceled", want: "context canceled", wantIs: context.Canceled,
			err: func(op string) error {
				return &smithy.OperationError{ServiceID: "KMS", OperationName: op, Err: fmt.Errorf("send request: %w", context.Canceled)}
			}},
		errorCase{name: "transport", want: "request failed",
			err: func(op string) error {
				return &smithy.OperationError{ServiceID: "KMS", OperationName: op, Err: &url.Error{
					Op: "Post", URL: "https://kms.us-east-1.amazonaws.com/", Err: errors.New("dial tcp 52.94.0.1:443: connection refused")}}
			}},
	)

	digest := sha256.Sum256([]byte("x"))
	calls := []struct {
		label, op string
		inject    func(*stubKMS, error)
		call      func(context.Context, *AWSKMSKeyManager) error
	}{
		{label: "describe key", op: "DescribeKey",
			inject: func(s *stubKMS, err error) { s.describeErr = err },
			call: func(ctx context.Context, km *AWSKMSKeyManager) error {
				_, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256)
				return err
			}},
		{label: "get public key", op: "GetPublicKey",
			inject: func(s *stubKMS, err error) { s.publicErr = err },
			call: func(ctx context.Context, km *AWSKMSKeyManager) error {
				_, err := km.GetPublicKey(ctx, tlKeyID)
				return err
			}},
		{label: "sign", op: "Sign",
			inject: func(s *stubKMS, err error) { s.signErr = err },
			call: func(ctx context.Context, km *AWSKMSKeyManager) error {
				_, err := km.Sign(ctx, tlKeyID, digest[:])
				return err
			}},
		{label: "sign dry run", op: "Sign",
			inject: func(s *stubKMS, err error) { s.signErr = err },
			call: func(ctx context.Context, km *AWSKMSKeyManager) error {
				_, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256)
				return err
			}},
	}
	for _, tc := range tests {
		for _, c := range calls {
			t.Run(tc.name+"/"+c.label, func(t *testing.T) {
				var logs bytes.Buffer
				stub := newStub(t, tlRef, raRef)
				c.inject(stub, tc.err(c.op))
				km := newAWSKMS(t, stub, WithAWSKMSLogger(zerolog.New(&logs)))

				err := c.call(context.Background(), km)
				if tc.name == "DryRunOperationException" && c.label == "sign dry run" {
					if err != nil {
						t.Fatalf("a DryRunOperationException answer means the signing permission exists, got %v", err)
					}
					return
				}
				prefix := "keymanager: "
				if errors.Is(tc.wantIs, ErrKeyNotFound) {
					prefix = ErrKeyNotFound.Error() + ": "
				}
				want := prefix + "ans-tl-attestation: kms " + c.label + ": " + tc.want
				if err == nil || err.Error() != want {
					t.Fatalf("error = %v, want exactly %q", err, want)
				}
				if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
					t.Fatalf("error = %v, want errors.Is %v", err, tc.wantIs)
				}
				if !strings.Contains(logs.String(), "operation error KMS: "+c.op) {
					t.Fatalf("the full AWS error must be logged: %s", logs.String())
				}
			})
		}
	}
}

func TestAWSKMS_EnsureKeyChecksSignPermission(t *testing.T) {
	ctx := context.Background()
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub)
	if _, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if len(stub.dryRuns) != 1 {
		t.Fatalf("DryRun Sign requests = %d, want 1", len(stub.dryRuns))
	}
	in := stub.dryRuns[0]
	if got, want := aws.ToString(in.KeyId), aws.ToString(stub.keys[tlRef].md.Arn); got != want {
		t.Errorf("DryRun KeyId = %q, want the pinned ARN %q", got, want)
	}
	if in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 || len(in.Message) != sha256.Size {
		t.Errorf("DryRun request = %+v, want a SHA-256 digest with ECDSA_SHA_256", in)
	}
	if stub.signCalls != 0 {
		t.Errorf("EnsureKey made %d real Sign calls, want 0", stub.signCalls)
	}

	stub = newStub(t, tlRef, raRef)
	stub.dryRunReturnsNil = true
	if _, err := newAWSKMS(t, stub).EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatalf("EnsureKey with a successful DryRun answer = %v", err)
	}
}

// A role with kms:DescribeKey and kms:GetPublicKey but not kms:Sign must
// fail EnsureKey, so the service does not start and report ready.
func TestAWSKMS_EnsureKeyFailsWithoutSignPermission(t *testing.T) {
	var logs bytes.Buffer
	stub := newStub(t, tlRef, raRef)
	stub.signErr = kmsCallError("Sign", accessDenied("kms:Sign"))
	km := newAWSKMS(t, stub, WithAWSKMSLogger(zerolog.New(&logs)))

	_, err := km.EnsureKey(context.Background(), tlKeyID, port.AlgorithmECDSAP256)
	if err == nil || err.Error() != "keymanager: ans-tl-attestation: kms sign dry run: AccessDeniedException" {
		t.Fatalf("EnsureKey error = %v", err)
	}
	if !strings.Contains(logs.String(), `"op":"sign dry run"`) || strings.Contains(logs.String(), "KMS signing key ready") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestAWSKMS_CallsHaveDefaultDeadline(t *testing.T) {
	ctx := context.Background()
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub)
	start := time.Now()
	if _, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := km.Sign(ctx, tlKeyID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if len(stub.deadlines) != 4 {
		t.Fatalf("KMS calls = %d, want 4 (DescribeKey, GetPublicKey, DryRun Sign, Sign)", len(stub.deadlines))
	}
	for i, d := range stub.deadlines {
		if d.IsZero() || d.Before(start.Add(defaultAWSKMSTimeout)) || d.After(time.Now().Add(defaultAWSKMSTimeout)) {
			t.Fatalf("call %d deadline = %v, want about %v after the call", i, d, defaultAWSKMSTimeout)
		}
	}
}

func TestAWSKMS_TimeoutEndsStalledCalls(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	calls := map[string]func(context.Context, *AWSKMSKeyManager) error{
		"describe key": func(ctx context.Context, km *AWSKMSKeyManager) error {
			_, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256)
			return err
		},
		"get public key": func(ctx context.Context, km *AWSKMSKeyManager) error {
			_, err := km.GetPublicKey(ctx, tlKeyID)
			return err
		},
		"sign": func(ctx context.Context, km *AWSKMSKeyManager) error {
			_, err := km.Sign(ctx, tlKeyID, digest[:])
			return err
		},
	}
	for label, call := range calls {
		t.Run(label, func(t *testing.T) {
			stub := newStub(t, tlRef, raRef)
			stub.stall = true
			km := newAWSKMS(t, stub, WithAWSKMSTimeout(50*time.Millisecond))
			start := time.Now()
			err := call(context.Background(), km)
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "kms "+label) {
				t.Fatalf("error = %v, want a %q deadline error", err, label)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("stalled call returned after %v", elapsed)
			}
		})
	}
}

func TestAWSKMS_ShorterCallerDeadlineWins(t *testing.T) {
	stub := newStub(t, tlRef, raRef)
	stub.stall = true
	km := newAWSKMS(t, stub)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	digest := sha256.Sum256([]byte("x"))
	start := time.Now()
	if _, err := km.Sign(ctx, tlKeyID, digest[:]); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Sign = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Sign waited %v, want the caller's 50ms deadline", elapsed)
	}
}

func TestWithAWSKMSTimeout(t *testing.T) {
	for _, tc := range []struct {
		in, want time.Duration
	}{
		{in: 3 * time.Second, want: 3 * time.Second},
		{in: 0, want: defaultAWSKMSTimeout},
		{in: -time.Second, want: defaultAWSKMSTimeout},
	} {
		km := newAWSKMS(t, newStub(t, tlRef, raRef), WithAWSKMSTimeout(tc.in))
		if km.timeout != tc.want {
			t.Errorf("WithAWSKMSTimeout(%v): timeout = %v, want %v", tc.in, km.timeout, tc.want)
		}
	}
}

func TestAWSKMS_PublicKeyErrors(t *testing.T) {
	ctx := context.Background()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)

	tests := []struct {
		name   string
		keyID  string
		mutate func(*stubKMS)
		want   string
	}{
		{name: "unmapped key ID", keyID: "ans-other", want: "no keys.aws-kms.keys entry"},
		{name: "kms error", keyID: tlKeyID, mutate: func(s *stubKMS) { s.publicErr = errors.New("KMSInternalException") }, want: "kms get public key"},
		{name: "not DER", keyID: tlKeyID, mutate: func(s *stubKMS) { s.publicDER = []byte("garbage") }, want: "parse kms public key"},
		{name: "RSA key", keyID: tlKeyID, mutate: func(s *stubKMS) { s.publicDER = rsaDER }, want: "want ECDSA P-256"},
		{name: "P-384 key", keyID: tlKeyID, mutate: func(s *stubKMS) { s.publicDER = p384DER }, want: "want ECDSA P-256"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStub(t, tlRef, raRef)
			if tc.mutate != nil {
				tc.mutate(stub)
			}
			km := newAWSKMS(t, stub)
			if _, err := km.GetPublicKey(ctx, tc.keyID); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("GetPublicKey error = %v, want %q", err, tc.want)
			}
			digest := sha256.Sum256([]byte("x"))
			if ok, err := km.Verify(ctx, tc.keyID, digest[:], []byte{0x30}); err == nil || ok {
				t.Fatalf("Verify = %v, %v; want false with an error", ok, err)
			}
		})
	}
}

func TestAWSKMS_ConcurrentPublicKeyFetch(t *testing.T) {
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := km.GetPublicKey(context.Background(), tlKeyID); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	first, _ := km.GetPublicKey(context.Background(), tlKeyID)
	second, _ := km.GetPublicKey(context.Background(), tlKeyID)
	if first != second {
		t.Fatal("cached public key changed between calls")
	}
}

func TestAWSKMS_CreateAndListKeys(t *testing.T) {
	km := newAWSKMS(t, newStub(t, tlRef, raRef))
	if _, err := km.CreateKey(context.Background(), port.AlgorithmECDSAP256); !errors.Is(err, ErrUnsupportedOperation) {
		t.Fatalf("CreateKey = %v, want ErrUnsupportedOperation", err)
	}
	ids, err := km.ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != raKeyID || ids[1] != tlKeyID {
		t.Fatalf("ListKeys = %v, want sorted configured key IDs", ids)
	}
}

func TestAWSKMS_ConstructorValidation(t *testing.T) {
	stub := newStub(t)
	tests := []struct {
		name   string
		client AWSKMSClient
		keys   map[string]string
		want   string
	}{
		{name: "nil client", keys: map[string]string{tlKeyID: tlRef}, want: "client is required"},
		{name: "empty map", client: stub, keys: map[string]string{}, want: "key map is empty"},
		{name: "empty reference", client: stub, keys: map[string]string{tlKeyID: ""}, want: "empty entry"},
		{name: "empty key ID", client: stub, keys: map[string]string{"": tlRef}, want: "empty entry"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAWSKMSKeyManager(tc.client, tc.keys); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewAWSKMSKeyManager error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAWSKMS_ConfigMapIsCopied(t *testing.T) {
	keys := map[string]string{tlKeyID: tlRef}
	km, err := NewAWSKMSKeyManager(newStub(t, tlRef), keys)
	if err != nil {
		t.Fatal(err)
	}
	keys[tlKeyID] = "alias/changed"
	if _, err := km.EnsureKey(context.Background(), tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatalf("mutating the caller's map changed the adapter: %v", err)
	}
}

func TestAWSKMS_Logging(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	stub := newStub(t, tlRef, raRef)
	km := newAWSKMS(t, stub, WithAWSKMSLogger(logger))
	ctx := context.Background()

	if _, err := km.EnsureKey(ctx, tlKeyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	stub.signErr = accessDenied("kms:Sign")
	digest := sha256.Sum256([]byte("x"))
	_, _ = km.Sign(ctx, tlKeyID, digest[:])

	logs := buf.String()
	for _, want := range []string{`"component":"aws-kms-keymanager"`, `"message":"KMS signing key ready"`, `"keyId":"ans-tl-attestation"`, `"message":"KMS call failed"`, `"op":"sign"`, `"level":"error"`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs missing %s:\n%s", want, logs)
		}
	}
}

func TestNewAWSKMSClient(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_PROFILE", "")

	client, err := NewAWSKMSClient(context.Background(), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Options().Region; got != "us-east-1" {
		t.Fatalf("region = %q, want the configured override", got)
	}
	if _, err := NewAWSKMSClient(context.Background(), ""); err != nil {
		t.Fatalf("NewAWSKMSClient without a region override: %v", err)
	}

	t.Setenv("AWS_PROFILE", "missing-profile")
	if _, err := NewAWSKMSClient(context.Background(), ""); err == nil {
		t.Fatal("NewAWSKMSClient with a missing shared-config profile should fail")
	}
}

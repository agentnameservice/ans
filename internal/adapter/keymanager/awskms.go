package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/port"
)

// defaultAWSKMSTimeout bounds each AWS KMS call unless
// WithAWSKMSTimeout overrides it.
const defaultAWSKMSTimeout = 10 * time.Second

// ErrUnsupportedOperation is returned for KeyManager operations an
// adapter does not perform.
var ErrUnsupportedOperation = errors.New("keymanager: operation not supported")

// AWSKMSClient is the subset of the AWS KMS API the adapter calls.
type AWSKMSClient interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// AWSKMSKeyManager implements port.KeyManager with existing AWS KMS
// keys. Each key ID maps to a KMS key ID, ARN, or alias. EnsureKey pins
// the key ID to the key ARN, so a re-pointed alias takes effect on
// restart.
type AWSKMSKeyManager struct {
	client  AWSKMSClient
	keys    map[string]string
	logger  zerolog.Logger
	timeout time.Duration

	mu   sync.RWMutex
	pubs map[string]*ecdsa.PublicKey
	arns map[string]string
}

// AWSKMSOption configures an AWSKMSKeyManager.
type AWSKMSOption func(*AWSKMSKeyManager)

// WithAWSKMSLogger sets the logger. The default discards logs.
func WithAWSKMSLogger(logger zerolog.Logger) AWSKMSOption {
	return func(m *AWSKMSKeyManager) {
		m.logger = logger.With().Str("component", "aws-kms-keymanager").Logger()
	}
}

// WithAWSKMSTimeout overrides the time limit for each AWS KMS call,
// retries included (default 10s). A non-positive d keeps the default.
func WithAWSKMSTimeout(d time.Duration) AWSKMSOption {
	return func(m *AWSKMSKeyManager) {
		if d > 0 {
			m.timeout = d
		}
	}
}

// NewAWSKMSClient builds a KMS client from the standard AWS credential
// chain. A non-empty region overrides the chain's region.
func NewAWSKMSClient(ctx context.Context, region string) (*kms.Client, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("keymanager: load aws config: %w", err)
	}
	return kms.NewFromConfig(cfg), nil
}

// NewAWSKMSKeyManager returns a key manager that maps key IDs to KMS
// key references through keys.
func NewAWSKMSKeyManager(client AWSKMSClient, keys map[string]string, opts ...AWSKMSOption) (*AWSKMSKeyManager, error) {
	if client == nil {
		return nil, errors.New("keymanager: aws kms client is required")
	}
	if len(keys) == 0 {
		return nil, errors.New("keymanager: aws kms key map is empty")
	}
	resolved := make(map[string]string, len(keys))
	for id, ref := range keys {
		if id == "" || ref == "" {
			return nil, fmt.Errorf("keymanager: aws kms key map has an empty entry (%q: %q)", id, ref)
		}
		resolved[id] = ref
	}
	m := &AWSKMSKeyManager{
		client:  client,
		keys:    resolved,
		logger:  zerolog.Nop(),
		timeout: defaultAWSKMSTimeout,
		pubs:    make(map[string]*ecdsa.PublicKey, len(resolved)),
		arns:    make(map[string]string, len(resolved)),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// EnsureKey checks that keyID maps to an enabled ECC_NIST_P256 key with
// SIGN_VERIFY usage, pins keyID to the key ARN, loads the public key,
// and checks that the caller may sign with it. It never creates a key.
func (m *AWSKMSKeyManager) EnsureKey(ctx context.Context, keyID, algorithm string) (string, error) {
	if algorithm != port.AlgorithmECDSAP256 {
		return "", fmt.Errorf("%w: %s (aws kms adapter supports %s)", ErrUnsupportedAlgorithm, algorithm, port.AlgorithmECDSAP256)
	}
	ref, err := m.resolve(keyID)
	if err != nil {
		return "", err
	}
	callCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	out, err := m.client.DescribeKey(callCtx, &kms.DescribeKeyInput{KeyId: aws.String(ref)})
	if err != nil {
		m.logger.Error().Err(err).Str("keyId", keyID).Str("kmsKey", ref).Msg("describe KMS key failed")
		return "", m.wrapKMSError("describe key", keyID, err)
	}
	if err := checkSigningKey(out.KeyMetadata); err != nil {
		m.logger.Error().Err(err).Str("keyId", keyID).Str("kmsKey", ref).Msg("KMS key cannot sign for this key ID")
		return "", fmt.Errorf("keymanager: %s: %w", keyID, err)
	}
	if arn := aws.ToString(out.KeyMetadata.Arn); arn != "" {
		m.pin(keyID, arn)
		ref = arn
	}
	pub, err := m.GetPublicKey(ctx, keyID)
	if err != nil {
		return "", err
	}
	if err := m.checkSignPermission(ctx, keyID, ref); err != nil {
		return "", err
	}
	m.logger.Info().
		Str("keyId", keyID).
		Str("kmsKeyArn", aws.ToString(out.KeyMetadata.Arn)).
		Str("fingerprint", KeyFingerprint(pub)).
		Msg("KMS signing key ready")
	return keyID, nil
}

// checkSignPermission sends a DryRun Sign request for ref. KMS answers
// DryRunOperationException when the request would succeed.
func (m *AWSKMSKeyManager) checkSignPermission(ctx context.Context, keyID, ref string) error {
	callCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	var digest [sha256.Size]byte
	_, err := m.client.Sign(callCtx, &kms.SignInput{
		KeyId:            aws.String(ref),
		Message:          digest[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
		DryRun:           aws.Bool(true),
	})
	var dryRun *types.DryRunOperationException
	if err == nil || errors.As(err, &dryRun) {
		return nil
	}
	m.logger.Error().Err(err).Str("keyId", keyID).Str("kmsKey", ref).Msg("KMS sign permission check failed")
	return m.wrapKMSError("sign dry run", keyID, err)
}

// CreateKey returns ErrUnsupportedOperation.
func (m *AWSKMSKeyManager) CreateKey(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("%w: create the key in AWS KMS and map it under keys.aws-kms.keys", ErrUnsupportedOperation)
}

// Sign signs a SHA-256 digest with the KMS key mapped to keyID and
// returns an ASN.1 DER ECDSA signature.
func (m *AWSKMSKeyManager) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	if len(data) != sha256.Size {
		return nil, fmt.Errorf("keymanager: sign expects a %d-byte SHA-256 digest, got %d bytes", sha256.Size, len(data))
	}
	ref, err := m.resolve(keyID)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	out, err := m.client.Sign(callCtx, &kms.SignInput{
		KeyId:            aws.String(ref),
		Message:          data,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		m.logger.Error().Err(err).Str("keyId", keyID).Str("kmsKey", ref).Msg("KMS sign failed")
		return nil, m.wrapKMSError("sign", keyID, err)
	}
	return out.Signature, nil
}

// Verify checks signature over the digest data with the public key of
// keyID.
func (m *AWSKMSKeyManager) Verify(ctx context.Context, keyID string, data, signature []byte) (bool, error) {
	pub, err := m.publicKey(ctx, keyID)
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(pub, data, signature), nil
}

// GetPublicKey returns the public key of keyID, fetched from KMS on
// first use.
func (m *AWSKMSKeyManager) GetPublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	return m.publicKey(ctx, keyID)
}

// ListKeys returns the configured key IDs in sorted order.
func (m *AWSKMSKeyManager) ListKeys(_ context.Context) ([]string, error) {
	ids := make([]string, 0, len(m.keys))
	for id := range m.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func (m *AWSKMSKeyManager) publicKey(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	m.mu.RLock()
	pub, ok := m.pubs[keyID]
	m.mu.RUnlock()
	if ok {
		return pub, nil
	}
	ref, err := m.resolve(keyID)
	if err != nil {
		return nil, err
	}
	m.logger.Debug().Str("keyId", keyID).Str("kmsKey", ref).Msg("public key not cached, fetching from KMS")
	callCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	out, err := m.client.GetPublicKey(callCtx, &kms.GetPublicKeyInput{KeyId: aws.String(ref)})
	if err != nil {
		m.logger.Error().Err(err).Str("keyId", keyID).Str("kmsKey", ref).Msg("get KMS public key failed")
		return nil, m.wrapKMSError("get public key", keyID, err)
	}
	parsed, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keymanager: parse kms public key for %s: %w", keyID, err)
	}
	ecPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("keymanager: kms public key for %s is %T, want ECDSA P-256", keyID, parsed)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.pubs[keyID]; ok {
		return cached, nil
	}
	m.pubs[keyID] = ecPub
	return ecPub, nil
}

// pin records the key ARN for keyID and drops a public key loaded for
// a different key.
func (m *AWSKMSKeyManager) pin(keyID, arn string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.arns[keyID] != arn {
		delete(m.pubs, keyID)
	}
	m.arns[keyID] = arn
}

// resolve returns the pinned key ARN for keyID, or the configured
// reference when none is pinned.
func (m *AWSKMSKeyManager) resolve(keyID string) (string, error) {
	m.mu.RLock()
	arn, ok := m.arns[keyID]
	m.mu.RUnlock()
	if ok {
		return arn, nil
	}
	ref, ok := m.keys[keyID]
	if !ok {
		return "", fmt.Errorf("%w: %s has no keys.aws-kms.keys entry", ErrKeyNotFound, keyID)
	}
	return ref, nil
}

// wrapKMSError keeps only the AWS error code of err. NotFoundException
// wraps ErrKeyNotFound, and context errors stay matchable.
func (m *AWSKMSKeyManager) wrapKMSError(op, keyID string, err error) error {
	var notFound *types.NotFoundException
	if errors.As(err, &notFound) {
		return fmt.Errorf("%w: %s: kms %s: %s", ErrKeyNotFound, keyID, op, notFound.ErrorCode())
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("keymanager: %s: kms %s: %s", keyID, op, apiErr.ErrorCode())
	}
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		if errors.Is(err, ctxErr) {
			return fmt.Errorf("keymanager: %s: kms %s: %w", keyID, op, ctxErr)
		}
	}
	return fmt.Errorf("keymanager: %s: kms %s: request failed", keyID, op)
}

// checkSigningKey reports why a KMS key cannot back an ECDSA P-256
// signing key, or nil when it can.
func checkSigningKey(md *types.KeyMetadata) error {
	switch {
	case md == nil:
		return errors.New("kms returned no key metadata")
	case md.KeySpec != types.KeySpecEccNistP256:
		return fmt.Errorf("kms key spec is %s, want %s", md.KeySpec, types.KeySpecEccNistP256)
	case md.KeyUsage != types.KeyUsageTypeSignVerify:
		return fmt.Errorf("kms key usage is %s, want %s", md.KeyUsage, types.KeyUsageTypeSignVerify)
	case md.KeyState != types.KeyStateEnabled:
		return fmt.Errorf("kms key state is %s, want %s", md.KeyState, types.KeyStateEnabled)
	}
	return nil
}

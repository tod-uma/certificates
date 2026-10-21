package config

import (
	"crypto"
	"strings"

	"github.com/pkg/errors"
	"go.step.sm/crypto/keyutil"
)

// TLSKeyOptions sets the type of key the CA generates for the leaf
// certificate of its own HTTPS server (see Authority.GetTLSCertificate).
//
// When nil, keyutil's default key is used (EC P-256). Setting it is useful
// when the server certificate is issued by an external CA whose chain choice
// depends on the key type, e.g. a CA that only issues RSA certificates from a
// trusted hierarchy:
//
//	"tlsKey": {"type": "RSA", "size": 3072}
//
// It is local configuration only: linkedca has no field for it, so
// `step-ca export` omits it and it must be reapplied after a migration.
type TLSKeyOptions struct {
	// Type is the key type: "EC", "RSA" or "OKP".
	Type string `json:"type"`
	// Curve is the curve for EC ("P-256", "P-384", "P-521") and OKP
	// ("Ed25519") keys. Defaults to P-256 for EC and Ed25519 for OKP.
	Curve string `json:"curve,omitempty"`
	// Size is the RSA key size in bits. Defaults to keyutil.DefaultKeySize.
	Size int `json:"size,omitempty"`
}

// Validate normalizes the key type, fills in defaults and checks that the
// options describe a signing key keyutil can generate. A nil receiver is
// valid and means the default key.
func (o *TLSKeyOptions) Validate() error {
	if o == nil {
		return nil
	}

	o.Type = strings.ToUpper(o.Type)
	switch o.Type {
	case "EC":
		if o.Size != 0 {
			return errors.New("tlsKey size is only valid for RSA keys")
		}
		if o.Curve == "" {
			o.Curve = keyutil.DefaultKeyCurve
		}
		switch o.Curve {
		case "P-256", "P-384", "P-521":
		default:
			return errors.Errorf("tlsKey curve %q is not supported for EC keys", o.Curve)
		}
	case "RSA":
		if o.Curve != "" {
			return errors.New("tlsKey curve is not valid for RSA keys")
		}
		if o.Size == 0 {
			o.Size = keyutil.DefaultKeySize
		}
		if minBits := keyutil.MinRSAKeyBytes * 8; o.Size < minBits {
			return errors.Errorf("tlsKey size %d is below the minimum of %d bits", o.Size, minBits)
		}
	case "OKP":
		if o.Size != 0 {
			return errors.New("tlsKey size is only valid for RSA keys")
		}
		if o.Curve == "" {
			o.Curve = "Ed25519"
		}
		// X25519 is a key-agreement curve and cannot sign a CSR.
		if o.Curve != "Ed25519" {
			return errors.Errorf("tlsKey curve %q is not supported for OKP keys", o.Curve)
		}
	case "":
		return errors.New("tlsKey type cannot be empty")
	default:
		return errors.Errorf("tlsKey type %q is not supported", o.Type)
	}

	return nil
}

// GenerateKey returns a new private key for the CA's TLS certificate. A nil
// receiver generates keyutil's default key.
//
// The options are validated on a copy first, so callers that never ran
// Config.Validate (NewEmbedded with WithConfig, SkipValidation) get the same
// defaults and rejections without the receiver being modified.
func (o *TLSKeyOptions) GenerateKey() (crypto.PrivateKey, error) {
	if o == nil {
		return keyutil.GenerateDefaultKey()
	}
	opts := *o
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return keyutil.GenerateKey(opts.Type, opts.Curve, opts.Size)
}

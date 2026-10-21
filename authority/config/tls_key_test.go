package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestTLSKeyOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *TLSKeyOptions
		want    *TLSKeyOptions
		wantErr bool
	}{
		{"nil", nil, nil, false},
		{"ec default curve", &TLSKeyOptions{Type: "EC"}, &TLSKeyOptions{Type: "EC", Curve: "P-256"}, false},
		{"ec lowercase type", &TLSKeyOptions{Type: "ec", Curve: "P-384"}, &TLSKeyOptions{Type: "EC", Curve: "P-384"}, false},
		{"ec P-521", &TLSKeyOptions{Type: "EC", Curve: "P-521"}, &TLSKeyOptions{Type: "EC", Curve: "P-521"}, false},
		{"rsa default size", &TLSKeyOptions{Type: "RSA"}, &TLSKeyOptions{Type: "RSA", Size: 2048}, false},
		{"rsa 3072", &TLSKeyOptions{Type: "rsa", Size: 3072}, &TLSKeyOptions{Type: "RSA", Size: 3072}, false},
		{"okp default curve", &TLSKeyOptions{Type: "OKP"}, &TLSKeyOptions{Type: "OKP", Curve: "Ed25519"}, false},
		{"fail empty type", &TLSKeyOptions{}, nil, true},
		{"fail unknown type", &TLSKeyOptions{Type: "DSA"}, nil, true},
		{"fail oct type", &TLSKeyOptions{Type: "oct"}, nil, true},
		{"fail ec bad curve", &TLSKeyOptions{Type: "EC", Curve: "P-224"}, nil, true},
		{"fail ec with size", &TLSKeyOptions{Type: "EC", Size: 2048}, nil, true},
		{"fail rsa small", &TLSKeyOptions{Type: "RSA", Size: 1024}, nil, true},
		{"fail rsa with curve", &TLSKeyOptions{Type: "RSA", Curve: "P-256"}, nil, true},
		{"fail okp x25519", &TLSKeyOptions{Type: "OKP", Curve: "X25519"}, nil, true},
		{"fail okp with size", &TLSKeyOptions{Type: "OKP", Size: 2048}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("TLSKeyOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(tt.opts, tt.want) {
				t.Errorf("TLSKeyOptions.Validate() = %+v, want %+v", tt.opts, tt.want)
			}
		})
	}
}

func TestTLSKeyOptions_GenerateKey(t *testing.T) {
	tests := []struct {
		name  string
		opts  *TLSKeyOptions
		check func(t *testing.T, key any)
	}{
		{"nil is EC P-256", nil, func(t *testing.T, key any) {
			k, ok := key.(*ecdsa.PrivateKey)
			if !ok || k.Curve != elliptic.P256() {
				t.Errorf("GenerateKey() = %T, want *ecdsa.PrivateKey on P-256", key)
			}
		}},
		{"ec P-384", &TLSKeyOptions{Type: "EC", Curve: "P-384"}, func(t *testing.T, key any) {
			k, ok := key.(*ecdsa.PrivateKey)
			if !ok || k.Curve != elliptic.P384() {
				t.Errorf("GenerateKey() = %T, want *ecdsa.PrivateKey on P-384", key)
			}
		}},
		{"rsa 3072", &TLSKeyOptions{Type: "RSA", Size: 3072}, func(t *testing.T, key any) {
			k, ok := key.(*rsa.PrivateKey)
			if !ok || k.N.BitLen() != 3072 {
				t.Errorf("GenerateKey() = %T, want 3072-bit *rsa.PrivateKey", key)
			}
		}},
		{"okp Ed25519", &TLSKeyOptions{Type: "OKP", Curve: "Ed25519"}, func(t *testing.T, key any) {
			if _, ok := key.(ed25519.PrivateKey); !ok {
				t.Errorf("GenerateKey() = %T, want ed25519.PrivateKey", key)
			}
		}},
		// Unvalidated options, as left by NewEmbedded(WithConfig(...)) or
		// SkipValidation: defaults must be applied at generation time.
		{"unvalidated lowercase rsa 3072", &TLSKeyOptions{Type: "rsa", Size: 3072}, func(t *testing.T, key any) {
			k, ok := key.(*rsa.PrivateKey)
			if !ok || k.N.BitLen() != 3072 {
				t.Errorf("GenerateKey() = %T, want 3072-bit *rsa.PrivateKey", key)
			}
		}},
		{"unvalidated rsa default size", &TLSKeyOptions{Type: "RSA"}, func(t *testing.T, key any) {
			k, ok := key.(*rsa.PrivateKey)
			if !ok || k.N.BitLen() != 2048 {
				t.Errorf("GenerateKey() = %T, want 2048-bit *rsa.PrivateKey", key)
			}
		}},
		{"unvalidated ec default curve", &TLSKeyOptions{Type: "EC"}, func(t *testing.T, key any) {
			k, ok := key.(*ecdsa.PrivateKey)
			if !ok || k.Curve != elliptic.P256() {
				t.Errorf("GenerateKey() = %T, want *ecdsa.PrivateKey on P-256", key)
			}
		}},
		{"unvalidated okp default curve", &TLSKeyOptions{Type: "okp"}, func(t *testing.T, key any) {
			if _, ok := key.(ed25519.PrivateKey); !ok {
				t.Errorf("GenerateKey() = %T, want ed25519.PrivateKey", key)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var before TLSKeyOptions
			if tt.opts != nil {
				before = *tt.opts
			}
			key, err := tt.opts.GenerateKey()
			if err != nil {
				t.Fatalf("TLSKeyOptions.GenerateKey() error = %v", err)
			}
			tt.check(t, key)
			if tt.opts != nil && *tt.opts != before {
				t.Errorf("GenerateKey() modified its receiver: got %+v, want %+v", *tt.opts, before)
			}
		})
	}
}

func TestTLSKeyOptions_GenerateKeyInvalid(t *testing.T) {
	tests := []struct {
		name string
		opts *TLSKeyOptions
	}{
		{"empty type", &TLSKeyOptions{}},
		{"rsa with curve", &TLSKeyOptions{Type: "RSA", Curve: "P-384", Size: 2048}},
		{"rsa too small", &TLSKeyOptions{Type: "RSA", Size: 1024}},
		{"ec with size", &TLSKeyOptions{Type: "EC", Size: 3072}},
		{"okp x25519", &TLSKeyOptions{Type: "OKP", Curve: "X25519"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if key, err := tt.opts.GenerateKey(); err == nil {
				t.Errorf("TLSKeyOptions.GenerateKey() = %T, want error", key)
			}
		})
	}
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestDecodeDllCharacteristics(t *testing.T) {
	// ASLR (0x40) + CFG (0x4000) enabled, DEP (0x100) absent.
	enabled, missing := decodeDllCharacteristics(dllCharDynamicBase | dllCharGuardCF)
	if !contains(enabled, "ASLR") || !contains(enabled, "CFG") {
		t.Fatalf("expected ASLR+CFG enabled, got %v", enabled)
	}
	if contains(enabled, "DEP") {
		t.Fatalf("DEP should not be enabled, got %v", enabled)
	}
	if !contains(missing, "DEP") {
		t.Fatalf("expected DEP missing, got %v", missing)
	}
	if contains(missing, "ASLR") || contains(missing, "CFG") {
		t.Fatalf("ASLR/CFG should not be missing, got %v", missing)
	}

	// Nothing set → all three baseline mitigations missing.
	_, missingAll := decodeDllCharacteristics(0)
	for _, want := range []string{"ASLR", "DEP", "CFG"} {
		if !contains(missingAll, want) {
			t.Fatalf("expected %s in missing set, got %v", want, missingAll)
		}
	}
}

func TestDecodeImageCharacteristics(t *testing.T) {
	got := decodeImageCharacteristics(imageFileExecutableImage | imageFileDLL)
	if !contains(got, "EXECUTABLE_IMAGE") || !contains(got, "DLL") {
		t.Fatalf("expected EXECUTABLE_IMAGE+DLL, got %v", got)
	}
	if contains(got, "RELOCS_STRIPPED") {
		t.Fatalf("RELOCS_STRIPPED should not be set, got %v", got)
	}
}

func TestComputeRichHeaderHash(t *testing.T) {
	const danS = 0x536E6144
	key := uint32(0x12345678)
	data := make([]byte, 0x100)
	binary.LittleEndian.PutUint32(data[0x3C:], 0xA0) // e_lfanew
	binary.LittleEndian.PutUint32(data[0x80:], danS^key)
	binary.LittleEndian.PutUint32(data[0x84:], 0^key)
	binary.LittleEndian.PutUint32(data[0x88:], 0^key)
	copy(data[0x8C:], []byte("Rich"))
	binary.LittleEndian.PutUint32(data[0x90:], key)

	h1 := computeRichHeaderHash(data)
	if h1 == "" {
		t.Fatal("expected a non-empty rich header hash for a valid DanS..Rich block")
	}
	if h2 := computeRichHeaderHash(data); h1 != h2 {
		t.Fatalf("rich header hash not deterministic: %s vs %s", h1, h2)
	}

	// No Rich marker → empty.
	blank := make([]byte, 0x100)
	binary.LittleEndian.PutUint32(blank[0x3C:], 0xA0)
	if got := computeRichHeaderHash(blank); got != "" {
		t.Fatalf("expected empty hash when Rich header absent, got %q", got)
	}
	// Too short → empty.
	if got := computeRichHeaderHash([]byte{0x4d, 0x5a}); got != "" {
		t.Fatalf("expected empty hash for short buffer, got %q", got)
	}
}

func TestParseDERCertificates(t *testing.T) {
	der := selfSignedDER(t)

	// Direct parse path.
	certs, ok := parseDERCertificates(der)
	if !ok || len(certs) != 1 {
		t.Fatalf("direct parse failed: ok=%v n=%d", ok, len(certs))
	}

	// Embedded-scan path: prepend non-certificate bytes so the direct parse
	// fails and the TLV scanner must find the cert.
	wrapped := append([]byte{0x01, 0x02, 0x03, 0x04, 0x05}, der...)
	certs2, ok2 := parseDERCertificates(wrapped)
	if !ok2 || len(certs2) == 0 {
		t.Fatalf("embedded-scan parse failed: ok=%v n=%d", ok2, len(certs2))
	}

	// Garbage → not ok.
	if _, ok3 := parseDERCertificates([]byte("not a certificate at all")); ok3 {
		t.Fatal("expected garbage blob to yield no certificates")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	// Extra subject fields + SAN + key usage push the DER well over 256 bytes so
	// it uses the two-byte (0x30 0x82) length framing the TLV scanner expects.
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "FlatScan Test Authenticode Signer",
			Organization:       []string{"FlatScan Static Analysis Engine Test Suite"},
			OrganizationalUnit: []string{"PE Header Intelligence"},
			Country:            []string{"US"},
			Province:           []string{"Test State"},
			Locality:           []string{"Test City"},
		},
		DNSNames:              []string{"flatscan.test.example.com", "signer.flatscan.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

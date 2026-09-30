package secrets

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal("scim-token")
	if err != nil || sealed == "" || sealed == "scim-token" {
		t.Fatalf("Seal = %q, %v", sealed, err)
	}
	again, _ := box.Seal("scim-token")
	if again == sealed {
		t.Fatal("two seals of one value are identical: the nonce is not random")
	}
	if plain, err := box.Open(sealed); err != nil || plain != "scim-token" {
		t.Fatalf("Open = %q, %v", plain, err)
	}

	other, _ := New(bytes.Repeat([]byte{2}, 32))
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("opened with the wrong key")
	}
	tampered := []byte(sealed)
	tampered[len(tampered)-3] ^= 1
	if _, err := box.Open(string(tampered)); err == nil {
		t.Fatal("opened a tampered value")
	}
}

func TestEmptyStaysEmpty(t *testing.T) {
	box, _ := New(bytes.Repeat([]byte{1}, 32))
	if s, _ := box.Seal(""); s != "" {
		t.Fatalf("Seal(\"\") = %q", s)
	}
	if s, err := box.Open(""); s != "" || err != nil {
		t.Fatalf("Open(\"\") = %q, %v", s, err)
	}
}

func TestKeyLength(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("accepted a 16-byte key")
	}
}

package jsondns

import "testing"

func TestTypeToString(t *testing.T) {
	t.Parallel()
	if s := TypeToString(1); s != "A" {
		t.Errorf("expected A, got %s", s)
	}
	if s := TypeToString(28); s != "AAAA" {
		t.Errorf("expected AAAA, got %s", s)
	}
	// Unknown type should return numeric string
	if s := TypeToString(65534); s != "65534" {
		t.Errorf("expected 65534, got %s", s)
	}
}

func TestClassToString(t *testing.T) {
	t.Parallel()
	if s := ClassToString(1); s != "IN" {
		t.Errorf("expected IN, got %s", s)
	}
	if s := ClassToString(3); s != "CH" {
		t.Errorf("expected CH, got %s", s)
	}
	// Unknown class should return numeric string
	if s := ClassToString(65534); s != "65534" {
		t.Errorf("expected 65534, got %s", s)
	}
}

package main

import (
	"testing"
)

func TestDecryptShortData(t *testing.T) {
	setupKey("password")
	_, err := decrypt([]byte("short"))
	if err == nil {
		t.Fatal("Expected error for short data")
	}
}

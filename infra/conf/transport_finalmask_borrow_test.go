package conf

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/borrow"
)

func TestBorrowMaskBuild(t *testing.T) {
	built, err := (&BorrowMask{BorrowBytesHex: "0016"}).Build()
	if err != nil {
		t.Fatalf("build borrow config: %v", err)
	}
	config := built.(*borrow.Config)
	if len(config.BorrowBytes) != 2 || config.BorrowBytes[0] != 0x00 || config.BorrowBytes[1] != 0x16 {
		t.Fatalf("unexpected borrow bytes: %x", config.BorrowBytes)
	}
}

func TestBorrowMaskBuildRejectsBadHex(t *testing.T) {
	if _, err := (&BorrowMask{BorrowBytesHex: "zz"}).Build(); err == nil || !strings.Contains(err.Error(), "borrowBytesHex") {
		t.Fatalf("expected invalid hex error, got %v", err)
	}
}

func TestBorrowMaskBuildRejectsEmpty(t *testing.T) {
	if _, err := (&BorrowMask{BorrowBytesHex: ""}).Build(); err == nil || !strings.Contains(err.Error(), "borrowBytesHex") {
		t.Fatalf("expected empty error, got %v", err)
	}
}

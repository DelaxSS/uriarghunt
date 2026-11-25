package fuses

import (
	"bytes"
	"testing"
)

func buildWirePayload(version byte, wire string) []byte {
	var b bytes.Buffer
	b.WriteString(sentinelV1)
	b.WriteByte(version)
	b.WriteByte(byte(len(wire)))
	b.WriteString(wire)
	return b.Bytes()
}

func TestInspectReader_HardenedWire(t *testing.T) {
	// Matches observed OpenVPNConnect.exe wire: RunAsNode=0, EnableNodeCliInspect=0.
	data := append([]byte("prefix-junk"), buildWirePayload(1, "00100001")...)
	info := InspectReader(bytes.NewReader(data))

	if !info.Found || info.Version != 1 || info.FuseCount != 8 {
		t.Fatalf("unexpected header: %+v", info)
	}
	if info.RunAsNode != StateDisabled || info.EnableNodeCliInspect != StateDisabled {
		t.Errorf("expected RunAsNode & EnableNodeCliInspect disabled: %+v", info)
	}
	if info.EnableNodeOptionsEnv != StateEnabled || info.OnlyLoadAppFromAsar != StateDisabled {
		t.Errorf("unexpected env/asar states: %+v", info)
	}
	if !info.InspectHardened {
		t.Error("InspectHardened = false, want true")
	}
	if got := info.ShortLabel(); got != "hardened" {
		t.Errorf("ShortLabel() = %q, want hardened", got)
	}
}

func TestInspectReader_UnhardenedAndRemoved(t *testing.T) {
	data := buildWirePayload(1, "10r101")
	info := InspectReader(bytes.NewReader(data))

	if !info.Found || info.InspectHardened {
		t.Fatalf("unexpected result: %+v", info)
	}
	if info.RunAsNode != StateEnabled || info.EnableNodeOptionsEnv != StateRemoved ||
		info.EnableNodeCliInspect != StateEnabled || info.OnlyLoadAppFromAsar != StateEnabled {
		t.Errorf("decoded states mismatch: %+v", info)
	}
	if got := info.ShortLabel(); got != "inspect+node" {
		t.Errorf("ShortLabel() = %q, want inspect+node", got)
	}
}

func TestInspectReader_AcrossChunkBoundary(t *testing.T) {
	// Place the sentinel so it straddles the 1 MiB streaming chunk boundary.
	pad := bytes.Repeat([]byte{0x90}, (1<<20)-10)
	data := append(pad, buildWirePayload(1, "000001")...)

	info := InspectReader(bytes.NewReader(data))
	if !info.Found || !info.InspectHardened || info.OnlyLoadAppFromAsar != StateEnabled {
		t.Fatalf("failed to decode wire across 1 MiB boundary: %+v", info)
	}
}

func TestInspectReader_NotFoundAndInvalidWire(t *testing.T) {
	// Invalid sentinel occurrence followed by no valid wire.
	bad := append([]byte(sentinelV1), 0x01, 0x04, 'X', 'Y', 'Z', '!')
	info := InspectReader(bytes.NewReader(bad))
	if info.Found || info.RunAsNode != StateNotFound {
		t.Fatalf("invalid wire should not match: %+v", info)
	}
	if got := info.ShortLabel(); got != "not-found" {
		t.Errorf("ShortLabel() = %q, want not-found", got)
	}

	errInfo := &Info{Error: "access denied"}
	if got := errInfo.ShortLabel(); got != "error" {
		t.Errorf("ShortLabel() on error = %q, want error", got)
	}
}

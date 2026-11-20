package fuses

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

const sentinelV1 = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"

// Electron FuseV1Options wire positions.
const (
	idxRunAsNode            = 0
	idxEnableNodeOptionsEnv = 2
	idxEnableNodeCliInspect = 3
	idxOnlyLoadAppFromAsar  = 5
)

// State represents an individual Electron fuse wire value.
type State string

const (
	StateEnabled  State = "enabled"
	StateDisabled State = "disabled"
	StateRemoved  State = "removed"
	StateNotFound State = "not-found"
)

// Info holds parsed Electron Fuses v1 flags from a binary.
type Info struct {
	Found                bool   `json:"found"`
	Version              uint8  `json:"version,omitempty"`
	FuseCount            uint8  `json:"fuse_count,omitempty"`
	RunAsNode            State  `json:"run_as_node,omitempty"`
	EnableNodeOptionsEnv State  `json:"enable_node_options_env,omitempty"`
	EnableNodeCliInspect State  `json:"enable_node_cli_inspect,omitempty"`
	OnlyLoadAppFromAsar  State  `json:"only_load_app_from_asar,omitempty"`
	InspectHardened      bool   `json:"inspect_hardened,omitempty"`
	RawWire              string `json:"raw_wire,omitempty"`
	Error                string `json:"error,omitempty"`
}

// InspectFile streams path in fixed chunks to locate and decode the Electron Fuses v1 wire
// without loading multi-hundred-MB binaries into memory.
func InspectFile(path string) Info {
	f, err := os.Open(path)
	if err != nil {
		return Info{Error: err.Error()}
	}
	defer f.Close()
	return InspectReader(f)
}

// InspectReader scans r for the Electron Fuses v1 sentinel and decodes its wire state.
func InspectReader(r io.Reader) Info {
	const (
		chunkSize  = 1 << 20 // 1 MiB
		maxWireLen = len(sentinelV1) + 2 + 255
	)

	sentinel := []byte(sentinelV1)
	buf := make([]byte, maxWireLen+chunkSize)
	carry := 0

	for {
		n, err := r.Read(buf[carry : carry+chunkSize])
		data := buf[:carry+n]

		if info, ok := findValidWire(data, sentinel); ok {
			return info
		}

		if err != nil {
			if err != io.EOF {
				return Info{Error: err.Error()}
			}
			break
		}

		if len(data) > maxWireLen {
			copy(buf, data[len(data)-maxWireLen:])
			carry = maxWireLen
		} else {
			carry = len(data)
		}
	}

	return Info{
		Found:                false,
		RunAsNode:            StateNotFound,
		EnableNodeOptionsEnv: StateNotFound,
		EnableNodeCliInspect: StateNotFound,
		OnlyLoadAppFromAsar:  StateNotFound,
	}
}

func findValidWire(data, sentinel []byte) (Info, bool) {
	offset := 0
	for {
		rel := bytes.Index(data[offset:], sentinel)
		if rel == -1 {
			return Info{}, false
		}
		start := offset + rel + len(sentinel)
		if start+2 > len(data) {
			return Info{}, false
		}

		version := data[start]
		count := int(data[start+1])
		if version == 1 && count > 0 && start+2+count <= len(data) {
			wire := data[start+2 : start+2+count]
			if isValidWireBytes(wire) {
				info := decodeV1(version, wire)
				return info, true
			}
		}

		offset = offset + rel + 1
	}
}

func isValidWireBytes(wire []byte) bool {
	for _, b := range wire {
		if b != '0' && b != '1' && b != 'r' {
			return false
		}
	}
	return true
}

func decodeV1(version uint8, wire []byte) Info {
	info := Info{
		Found:                true,
		Version:              version,
		FuseCount:            uint8(len(wire)),
		RunAsNode:            wireState(wire, idxRunAsNode),
		EnableNodeOptionsEnv: wireState(wire, idxEnableNodeOptionsEnv),
		EnableNodeCliInspect: wireState(wire, idxEnableNodeCliInspect),
		OnlyLoadAppFromAsar:  wireState(wire, idxOnlyLoadAppFromAsar),
		RawWire:              string(wire),
	}
	info.InspectHardened = info.RunAsNode == StateDisabled && info.EnableNodeCliInspect == StateDisabled
	return info
}

func wireState(wire []byte, idx int) State {
	if idx >= len(wire) {
		return StateNotFound
	}
	switch wire[idx] {
	case '0':
		return StateDisabled
	case '1':
		return StateEnabled
	case 'r':
		return StateRemoved
	default:
		return StateNotFound
	}
}

// ShortLabel returns a concise table tag summarizing inspect/node fuse posture.
func (info *Info) ShortLabel() string {
	if info == nil {
		return "-"
	}
	if info.Error != "" {
		return "error"
	}
	if !info.Found {
		return "not-found"
	}
	if info.InspectHardened {
		return "hardened"
	}
	switch {
	case info.EnableNodeCliInspect == StateEnabled && info.RunAsNode == StateEnabled:
		return "inspect+node"
	case info.EnableNodeCliInspect == StateEnabled:
		return "inspect-on"
	case info.RunAsNode == StateEnabled:
		return "node-on"
	default:
		return fmt.Sprintf("v%d(%d)", info.Version, info.FuseCount)
	}
}

//go:build windows

package main

import (
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	th32csSnapProcess        = 0x00000002
	afInet                   = 2
	tcpTableOwnerPIDListener = 3
	errorInsufficientBuffer  = 122
)

var (
	kernel32DLL                  = syscall.NewLazyDLL("kernel32.dll")
	iphlpapiDLL                  = syscall.NewLazyDLL("iphlpapi.dll")
	createToolhelp32SnapshotProc = kernel32DLL.NewProc("CreateToolhelp32Snapshot")
	process32FirstWProc          = kernel32DLL.NewProc("Process32FirstW")
	process32NextWProc           = kernel32DLL.NewProc("Process32NextW")
	closeHandleProc              = kernel32DLL.NewProc("CloseHandle")
	getExtendedTCPTableProc      = iphlpapiDLL.NewProc("GetExtendedTcpTable")
)

type processEntry32 struct {
	Size              uint32
	UsageCount        uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	ThreadCount       uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExecutableFile    [260]uint16
}

func languageServerProcessIDs() map[uint32]struct{} {
	ids := make(map[uint32]struct{})
	snapshot, _, _ := createToolhelp32SnapshotProc.Call(th32csSnapProcess, 0)
	if snapshot == ^uintptr(0) {
		return ids
	}
	defer closeHandleProc.Call(snapshot)
	entry := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	ok, _, _ := process32FirstWProc.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for ok != 0 {
		if strings.HasPrefix(strings.ToLower(syscall.UTF16ToString(entry.ExecutableFile[:])), "language_server") {
			ids[entry.ProcessID] = struct{}{}
		}
		entry.Size = uint32(unsafe.Sizeof(processEntry32{}))
		ok, _, _ = process32NextWProc.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	return ids
}

func listenerPortsForProcessIDs(ids map[uint32]struct{}) []uint16 {
	if len(ids) == 0 {
		return nil
	}
	var size uint32
	result, _, _ := getExtendedTCPTableProc.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPIDListener, 0)
	if result != 0 && result != errorInsufficientBuffer || size < 4 || size > 16*1024*1024 {
		return nil
	}
	buffer := make([]byte, size)
	result, _, _ = getExtendedTCPTableProc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPIDListener, 0)
	if result != 0 {
		return nil
	}
	return parseIPv4OwnerPIDListeners(buffer, ids)
}

func fallbackLanguageServerCandidates(rec *recorder) []candidate {
	ids := languageServerProcessIDs()
	ports := listenerPortsForProcessIDs(ids)
	result := make([]candidate, 0, len(ports)*2)
	for _, port := range ports {
		address := "127.0.0.1:" + strconv.Itoa(int(port))
		result = append(result, candidate{Base: "http://" + address, Source: "process-table"}, candidate{Base: "https://" + address, Source: "process-table"})
	}
	rec.line("ADDRESS source=process-table present=%t", len(ports) != 0)
	return result
}

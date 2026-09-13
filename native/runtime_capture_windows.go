//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	th32csSnapProcess  = 0x00000002
	th32csSnapModule   = 0x00000008
	th32csSnapModule32 = 0x00000010

	processVMRead                  = 0x0010
	processQueryLimitedInformation = 0x1000

	memCommit = 0x1000

	pageNoAccess = 0x01
	pageGuard    = 0x100
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	ntdll                          = syscall.NewLazyDLL("ntdll.dll")
	procCreateToolhelp32Snapshot   = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = kernel32.NewProc("Process32FirstW")
	procProcess32NextW             = kernel32.NewProc("Process32NextW")
	procModule32FirstW             = kernel32.NewProc("Module32FirstW")
	procModule32NextW              = kernel32.NewProc("Module32NextW")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procReadProcessMemory          = kernel32.NewProc("ReadProcessMemory")
	procVirtualQueryEx             = kernel32.NewProc("VirtualQueryEx")
	procNtQueryInformationProcess  = ntdll.NewProc("NtQueryInformationProcess")
)

type processEntry32W struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type moduleEntry32W struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	SzModule     [256]uint16
	SzExePath    [260]uint16
}

type memoryBasicInformation64 struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	Alignment1        uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	Alignment2        uint32
}

type processBasicInformation64 struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessID uintptr
	Reserved3       uintptr
}

type runtimePESection struct {
	HeaderOffset uint32
	Name         string
	RVA          uint32
	VirtualSize  uint32
	RawSize      uint32
	Span         uint32
	Executable   bool
}

func closeWinHandle(h syscall.Handle) {
	if h != 0 && uintptr(h) != ^uintptr(0) {
		procCloseHandle.Call(uintptr(h))
	}
}

func normalizeWindowsPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	path = filepath.Clean(path)
	if strings.HasPrefix(path, `\\?\UNC\`) {
		path = `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	} else {
		path = strings.TrimPrefix(path, `\\?\`)
	}
	return strings.ToLower(path)
}

func utf16ArrayString(v []uint16) string {
	n := 0
	for n < len(v) && v[n] != 0 {
		n++
	}
	return syscall.UTF16ToString(v[:n])
}

func queryProcessPath(h syscall.Handle) (string, error) {
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	r1, _, e1 := procQueryFullProcessImageNameW.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return "", e1
		}
		return "", fmt.Errorf("QueryFullProcessImageNameW failed")
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

func findMatchingProcess(exePath string) (uint32, syscall.Handle, string, error) {
	target := normalizeWindowsPath(exePath)
	targetBase := strings.ToLower(filepath.Base(exePath))

	snap, _, e1 := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == ^uintptr(0) {
		return 0, 0, "", fmt.Errorf("CreateToolhelp32Snapshot(processes): %v", e1)
	}
	defer closeWinHandle(syscall.Handle(snap))

	var pe processEntry32W
	pe.Size = uint32(unsafe.Sizeof(pe))
	r1, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if r1 == 0 {
		return 0, 0, "", fmt.Errorf("Process32FirstW failed")
	}

	basenameMatches := 0
	pathMatches := 0
	for {
		name := strings.ToLower(utf16ArrayString(pe.ExeFile[:]))
		if name == targetBase {
			basenameMatches++
			// Verify the exact executable path with the weakest useful right first.
			// Only after path identity is proven do we request PROCESS_VM_READ.
			qh, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pe.ProcessID))
			if qh != 0 {
				queryHandle := syscall.Handle(qh)
				p, err := queryProcessPath(queryHandle)
				closeWinHandle(queryHandle)
				if err == nil && normalizeWindowsPath(p) == target {
					pathMatches++
					rh, _, eRead := procOpenProcess.Call(processQueryLimitedInformation|processVMRead, 0, uintptr(pe.ProcessID))
					if rh != 0 {
						return pe.ProcessID, syscall.Handle(rh), p, nil
					}
					if eRead != nil && eRead != syscall.Errno(0) {
						return 0, 0, "", fmt.Errorf("matched PID %d and verified its path, but PROCESS_VM_READ was denied: %v", pe.ProcessID, eRead)
					}
					return 0, 0, "", fmt.Errorf("matched PID %d and verified its path, but PROCESS_VM_READ was denied", pe.ProcessID)
				}
			}
		}

		r1, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if r1 == 0 {
			break
		}
	}

	if pathMatches > 0 {
		return 0, 0, "", fmt.Errorf("matched the selected executable path, but no matching process allowed read-only memory access")
	}
	if basenameMatches > 0 {
		return 0, 0, "", fmt.Errorf("found %d process(es) named %s, but none could be path-verified", basenameMatches, filepath.Base(exePath))
	}
	return 0, 0, "", nil
}

func createModuleSnapshot(pid uint32) (uintptr, error) {
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		snap, _, e1 := procCreateToolhelp32Snapshot.Call(th32csSnapModule|th32csSnapModule32, uintptr(pid))
		if snap != ^uintptr(0) {
			return snap, nil
		}
		lastErr = e1
		if errno, ok := e1.(syscall.Errno); !ok || errno != syscall.Errno(24) { // ERROR_BAD_LENGTH
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ^uintptr(0), lastErr
}

func findMainModule(pid uint32, exePath string) (uintptr, uint32, string, error) {
	snap, e1 := createModuleSnapshot(pid)
	if snap == ^uintptr(0) {
		return 0, 0, "", fmt.Errorf("CreateToolhelp32Snapshot(modules): %v", e1)
	}
	defer closeWinHandle(syscall.Handle(snap))

	target := normalizeWindowsPath(exePath)
	var me moduleEntry32W
	me.Size = uint32(unsafe.Sizeof(me))
	r1, _, _ := procModule32FirstW.Call(snap, uintptr(unsafe.Pointer(&me)))
	if r1 == 0 {
		return 0, 0, "", fmt.Errorf("Module32FirstW failed")
	}
	for {
		modPath := utf16ArrayString(me.SzExePath[:])
		if normalizeWindowsPath(modPath) == target {
			return me.ModBaseAddr, me.ModBaseSize, modPath, nil
		}
		r1, _, _ = procModule32NextW.Call(snap, uintptr(unsafe.Pointer(&me)))
		if r1 == 0 {
			break
		}
	}
	return 0, 0, "", fmt.Errorf("matching main module was not present in process %d", pid)
}

func findMainModuleFromPEB(h syscall.Handle) (uintptr, uint32, error) {
	// Toolhelp module enumeration can be denied independently of ordinary
	// read-only process access. When PROCESS_VM_READ is already allowed, query
	// the native ProcessBasicInformation record and read PEB.ImageBaseAddress.
	// This is still ordinary read-only introspection; if the process blocks the
	// PEB or image headers themselves, runtime capture stops rather than trying
	// to bypass that protection.
	var pbi processBasicInformation64
	var returnLength uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(h),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if int32(status) < 0 {
		return 0, 0, fmt.Errorf("NtQueryInformationProcess(ProcessBasicInformation) failed with NTSTATUS 0x%08X", uint32(status))
	}
	if pbi.PebBaseAddress == 0 {
		return 0, 0, fmt.Errorf("ProcessBasicInformation returned a null PEB address")
	}

	imageBaseBytes, got, err := readProcessMemoryExactish(h, pbi.PebBaseAddress+0x10, 8)
	if err != nil || got < 8 {
		return 0, 0, fmt.Errorf("read PEB.ImageBaseAddress: %v", err)
	}
	base64 := binary.LittleEndian.Uint64(imageBaseBytes[:8])
	if base64 == 0 {
		return 0, 0, fmt.Errorf("PEB.ImageBaseAddress was null")
	}
	base := uintptr(base64)

	headerProbe, got, err := readProcessMemoryExactish(h, base, 0x10000)
	if err != nil || got < 0x200 {
		return 0, 0, fmt.Errorf("read main image headers from PEB base 0x%X: %v", base, err)
	}
	imageSize, _, _, err := parseRuntimePEHeaders(headerProbe, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("validate main image at PEB base 0x%X: %v", base, err)
	}
	return base, imageSize, nil
}

func readProcessMemoryExactish(h syscall.Handle, address uintptr, size uint32) ([]byte, uint32, error) {
	if size == 0 {
		return []byte{}, 0, nil
	}
	buf := make([]byte, size)
	var read uintptr
	r1, _, e1 := procReadProcessMemory.Call(
		uintptr(h),
		address,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&read)),
	)
	if r1 == 0 && read == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return nil, 0, e1
		}
		return nil, 0, fmt.Errorf("ReadProcessMemory failed")
	}
	return buf[:read], uint32(read), nil
}

func parseRuntimePEHeaders(header []byte, moduleSize uint32) (uint32, uint32, []runtimePESection, error) {
	if len(header) < 0x100 || binary.LittleEndian.Uint16(header[:2]) != 0x5A4D {
		return 0, 0, nil, fmt.Errorf("runtime module does not expose a valid MZ header")
	}
	peOff := int(binary.LittleEndian.Uint32(header[0x3C:0x40]))
	if peOff < 0 || peOff+24 > len(header) || binary.LittleEndian.Uint32(header[peOff:peOff+4]) != 0x00004550 {
		return 0, 0, nil, fmt.Errorf("runtime module does not expose a valid PE header")
	}
	if binary.LittleEndian.Uint16(header[peOff+4:peOff+6]) != 0x8664 {
		return 0, 0, nil, fmt.Errorf("runtime module is not x64")
	}
	sectionCount := int(binary.LittleEndian.Uint16(header[peOff+6 : peOff+8]))
	optionalSize := int(binary.LittleEndian.Uint16(header[peOff+20 : peOff+22]))
	opt := peOff + 24
	if opt+optionalSize > len(header) || optionalSize < 64 || binary.LittleEndian.Uint16(header[opt:opt+2]) != 0x20B {
		return 0, 0, nil, fmt.Errorf("runtime module does not expose a valid PE32+ optional header")
	}
	imageSize := binary.LittleEndian.Uint32(header[opt+56 : opt+60])
	headerSize := binary.LittleEndian.Uint32(header[opt+60 : opt+64])
	if imageSize == 0 {
		imageSize = moduleSize
	}
	if moduleSize > 0 && (imageSize == 0 || imageSize > moduleSize+0x200000) {
		// Toolhelp's module size is an independent sanity bound. A small linker
		// alignment difference is fine; a wildly larger SizeOfImage is not.
		imageSize = moduleSize
	}
	secOff := opt + optionalSize
	sectionTableEnd := secOff + sectionCount*40
	if sectionCount <= 0 || sectionCount > 512 || sectionTableEnd > len(header) {
		return 0, 0, nil, fmt.Errorf("runtime section table is incomplete")
	}
	if headerSize < uint32(sectionTableEnd) {
		return 0, 0, nil, fmt.Errorf("runtime SizeOfHeaders 0x%X does not cover the section table ending at 0x%X", headerSize, sectionTableEnd)
	}

	sections := make([]runtimePESection, 0, sectionCount)
	for i := 0; i < sectionCount; i++ {
		off := secOff + i*40
		nameBytes := header[off : off+8]
		n := 0
		for n < len(nameBytes) && nameBytes[n] != 0 {
			n++
		}
		name := string(nameBytes[:n])
		vsize := binary.LittleEndian.Uint32(header[off+8 : off+12])
		rva := binary.LittleEndian.Uint32(header[off+12 : off+16])
		rawSize := binary.LittleEndian.Uint32(header[off+16 : off+20])
		characteristics := binary.LittleEndian.Uint32(header[off+36 : off+40])
		executable := characteristics&0x20000000 != 0
		span := vsize
		if rawSize > span {
			span = rawSize
		}
		if rva >= imageSize {
			span = 0
		} else if uint64(rva)+uint64(span) > uint64(imageSize) {
			span = imageSize - rva
		}
		sections = append(sections, runtimePESection{
			HeaderOffset: uint32(off),
			Name:         name,
			RVA:          rva,
			VirtualSize:  vsize,
			RawSize:      rawSize,
			Span:         span,
			Executable:   executable,
		})
	}
	return imageSize, headerSize, sections, nil
}

func queryMemory(h syscall.Handle, address uintptr) (memoryBasicInformation64, error) {
	var mbi memoryBasicInformation64
	r1, _, e1 := procVirtualQueryEx.Call(
		uintptr(h),
		address,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return mbi, e1
		}
		return mbi, fmt.Errorf("VirtualQueryEx failed")
	}
	return mbi, nil
}

func readableRegion(mbi memoryBasicInformation64) bool {
	if mbi.State != memCommit {
		return false
	}
	if mbi.Protect&pageGuard != 0 || mbi.Protect&pageNoAccess != 0 || mbi.Protect == 0 {
		return false
	}
	return true
}

func copyRuntimeRange(h syscall.Handle, moduleBase uintptr, rva uint32, size uint32, f *os.File) (uint64, uint64) {
	if size == 0 {
		return 0, 0
	}
	const chunkSize = 1 << 20
	start := moduleBase + uintptr(rva)
	end := start + uintptr(size)
	cur := start
	var readTotal, failedTotal uint64

	for cur < end {
		mbi, err := queryMemory(h, cur)
		if err != nil || mbi.RegionSize == 0 {
			// Query failures are bounded to one page so a single exotic page
			// cannot suppress the rest of a large section.
			step := uintptr(0x1000)
			if cur+step > end {
				step = end - cur
			}
			failedTotal += uint64(step)
			cur += step
			continue
		}
		regionEnd := mbi.BaseAddress + mbi.RegionSize
		if regionEnd <= cur {
			regionEnd = cur + 0x1000
		}
		if regionEnd > end {
			regionEnd = end
		}
		if !readableRegion(mbi) {
			failedTotal += uint64(regionEnd - cur)
			cur = regionEnd
			continue
		}

		for cur < regionEnd {
			want := regionEnd - cur
			if want > chunkSize {
				want = chunkSize
			}
			buf, got, err := readProcessMemoryExactish(h, cur, uint32(want))
			if got > 0 {
				fileOff := int64(rva) + int64(cur-start)
				if _, werr := f.WriteAt(buf, fileOff); werr == nil {
					readTotal += uint64(got)
				} else {
					failedTotal += uint64(got)
				}
			}
			if err != nil || uintptr(got) < want {
				missing := want - uintptr(got)
				// Retry an unread tail page-by-page. ReadProcessMemory can fail
				// a large chunk merely because one page at its end is guarded.
				retryCur := cur + uintptr(got)
				for missing > 0 {
					pageWant := missing
					if pageWant > 0x1000 {
						pageWant = 0x1000
					}
					pbuf, pgot, _ := readProcessMemoryExactish(h, retryCur, uint32(pageWant))
					if pgot > 0 {
						fileOff := int64(rva) + int64(retryCur-start)
						if _, werr := f.WriteAt(pbuf, fileOff); werr == nil {
							readTotal += uint64(pgot)
						} else {
							failedTotal += uint64(pgot)
						}
					}
					if uintptr(pgot) < pageWant {
						failedTotal += uint64(pageWant - uintptr(pgot))
					}
					retryCur += pageWant
					missing -= pageWant
				}
			}
			cur += want
		}
	}
	return readTotal, failedTotal
}

func writeRuntimeProgress(path string, pct int, stage string) {
	if path == "" {
		return
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	stage = strings.ReplaceAll(stage, "\t", " ")
	stage = strings.ReplaceAll(stage, "\r", " ")
	stage = strings.ReplaceAll(stage, "\n", " ")
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, []byte(fmt.Sprintf("RUNTIME\t%d\t%s\n", pct, stage)), 0644)
	_ = os.Rename(tmp, path)
}

func captureRuntimeImage(exePath, outPath, progressPath string, waitMs int) RuntimeCaptureResult {
	result := RuntimeCaptureResult{Status: "ERROR", SourceKind: "live", SourcePath: exePath, Format: "LIVE_PROCESS"}
	if outPath == "" {
		result.Detail = "runtime capture output path is empty"
		return result
	}

	deadline := time.Now().Add(time.Duration(waitMs) * time.Millisecond)
	for {
		writeRuntimeProgress(progressPath, 2, "Locating the running game process")
		pid, h, actualPath, err := findMatchingProcess(exePath)
		if pid != 0 && h != 0 {
			defer closeWinHandle(h)
			result.PID = pid
			result.ProcessPath = actualPath

			writeRuntimeProgress(progressPath, 6, "Locating the mapped main module")
			base, moduleSize, modulePath, moduleErr := findMainModule(pid, actualPath)
			moduleDiscovery := "Toolhelp module snapshot"
			if moduleErr != nil {
				// Some protected games deny TH32CS_SNAPMODULE while still allowing the
				// exact process to be path-verified and opened with PROCESS_VM_READ.
				// Recover the main image base from the target's PEB in that case.
				pebBase, pebSize, pebErr := findMainModuleFromPEB(h)
				if pebErr != nil {
					result.Status = "ACCESS_DENIED"
					result.Detail = "process matched, but main-module discovery failed; module snapshot: " + moduleErr.Error() + "; PEB fallback: " + pebErr.Error()
					return result
				}
				base = pebBase
				moduleSize = pebSize
				modulePath = actualPath
				moduleDiscovery = "PEB ImageBaseAddress fallback (Toolhelp module enumeration was denied)"
			}
			result.Base = uint64(base)
			result.ProcessPath = modulePath

			writeRuntimeProgress(progressPath, 9, "Reading runtime PE headers")
			firstHeaderSize := uint32(0x10000)
			if moduleSize > 0 && firstHeaderSize > moduleSize {
				firstHeaderSize = moduleSize
			}
			headerProbe, got, err := readProcessMemoryExactish(h, base, firstHeaderSize)
			if err != nil || got < 0x200 {
				result.Status = "ACCESS_DENIED"
				result.Detail = fmt.Sprintf("process opened read-only, but runtime PE headers could not be read: %v", err)
				return result
			}
			imageSize, headerSize, sections, err := parseRuntimePEHeaders(headerProbe, moduleSize)
			if err != nil {
				result.Detail = err.Error()
				return result
			}
			result.ImageSize = uint64(imageSize)
			result.Sections = len(sections)

			if headerSize == 0 || headerSize > imageSize || headerSize > 16*1024*1024 {
				result.Detail = fmt.Sprintf("runtime SizeOfHeaders 0x%X is not sane for image size 0x%X", headerSize, imageSize)
				return result
			}
			fullHeader, got, err := readProcessMemoryExactish(h, base, headerSize)
			if err != nil || got < headerSize {
				result.Status = "ACCESS_DENIED"
				result.Detail = fmt.Sprintf("could not read the complete runtime PE headers (%d/%d bytes): %v", got, headerSize, err)
				return result
			}

			// Normalize the memory layout into a scanner-friendly PE snapshot:
			// each section's raw file offset becomes its RVA, so all existing
			// RVA<->raw logic sees exactly the bytes present in mapped memory.
			for _, sec := range sections {
				off := int(sec.HeaderOffset)
				if off+24 > len(fullHeader) {
					continue
				}
				binary.LittleEndian.PutUint32(fullHeader[off+16:off+20], sec.Span)
				binary.LittleEndian.PutUint32(fullHeader[off+20:off+24], sec.RVA)
			}

			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				result.Detail = "create runtime capture directory: " + err.Error()
				return result
			}
			f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				result.Detail = "create runtime snapshot: " + err.Error()
				return result
			}
			defer f.Close()
			if err := f.Truncate(int64(imageSize)); err != nil {
				result.Detail = "size runtime snapshot: " + err.Error()
				return result
			}
			if _, err := f.WriteAt(fullHeader, 0); err != nil {
				result.Detail = "write normalized runtime headers: " + err.Error()
				return result
			}
			result.ReadBytes += uint64(len(fullHeader))

			var totalSpan uint64
			for _, sec := range sections {
				totalSpan += uint64(sec.Span)
				if sec.Executable {
					result.ExecSpanBytes += uint64(sec.Span)
				}
			}
			if totalSpan == 0 {
				result.Detail = "runtime image has no mappable section bytes"
				return result
			}

			var doneSpan uint64
			for i, sec := range sections {
				if sec.Span == 0 {
					continue
				}
				pct := 12 + int((doneSpan*82)/totalSpan)
				stage := fmt.Sprintf("Capturing mapped section %d/%d (%s)", i+1, len(sections), sec.Name)
				writeRuntimeProgress(progressPath, pct, stage)
				readN, failedN := copyRuntimeRange(h, base, sec.RVA, sec.Span, f)
				result.ReadBytes += readN
				result.FailedBytes += failedN
				if sec.Executable {
					result.FailedExecBytes += failedN
				}
				doneSpan += uint64(sec.Span)
			}

			_ = f.Sync()
			writeRuntimeProgress(progressPath, 96, "Validating normalized runtime snapshot")
			info, err := f.Stat()
			if err != nil {
				result.Detail = "stat runtime snapshot: " + err.Error()
				return result
			}
			if info.Size() != int64(imageSize) {
				result.Detail = fmt.Sprintf("runtime snapshot size mismatch: got %d, expected %d", info.Size(), imageSize)
				return result
			}

			result.Success = true
			result.Status = "OK"
			result.Detail = fmt.Sprintf("captured mapped main module from PID %d using read-only process access; module discovery: %s", pid, moduleDiscovery)
			if result.FailedBytes > 0 {
				result.Detail += fmt.Sprintf("; %d mapped bytes were unreadable and remain zero-filled", result.FailedBytes)
			}
			writeRuntimeProgress(progressPath, 100, "Runtime image captured")
			return result
		}

		if err != nil {
			// Any error returned by findMatchingProcess means a same-name/path
			// candidate existed but ordinary query/read access was unavailable.
			result.Status = "ACCESS_DENIED"
			result.Detail = err.Error() + ". The scanner does not bypass protected-process or anti-cheat access controls."
			return result
		}
		if waitMs <= 0 || time.Now().After(deadline) {
			result.Status = "NOT_RUNNING"
			result.Detail = "no running process matched the selected executable path"
			return result
		}
		writeRuntimeProgress(progressPath, 2, "Waiting for the selected game process to start")
		time.Sleep(500 * time.Millisecond)
	}
}

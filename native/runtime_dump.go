package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	minidumpSignature      = 0x504D444D // "MDMP" little-endian
	moduleListStream       = 4
	memoryListStream       = 5
	memory64ListStream     = 9
	imageScnMemExecute     = 0x20000000
	maxReasonableDumpItems = 2_000_000
)

type dumpStream struct {
	typ      uint32
	dataSize uint32
	rva      uint32
}

type dumpModule struct {
	base uint64
	size uint32
	name string
}

type dumpMemoryRange struct {
	start   uint64
	size    uint64
	fileOff uint64
}

type coverageRange struct {
	start uint64
	end   uint64
}

type normalizedSection struct {
	headerOffset uint32
	name         string
	rva          uint32
	span         uint32
	executable   bool
}

func writeDumpProgress(path string, pct int, stage string) {
	if path == "" {
		return
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	stage = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(stage)
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, []byte(fmt.Sprintf("RUNTIME\t%d\t%s\n", pct, stage)), 0644)
	_ = os.Rename(tmp, path)
}

func readAtExact(f *os.File, off uint64, n uint64) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	if n > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("requested read is too large: %d bytes", n)
	}
	buf := make([]byte, int(n))
	got, err := f.ReadAt(buf, int64(off))
	if err != nil && err != io.EOF {
		return nil, err
	}
	if got != len(buf) {
		return nil, fmt.Errorf("short read at 0x%X: got %d of %d bytes", off, got, len(buf))
	}
	return buf, nil
}

func parseMinidumpStreams(f *os.File) ([]dumpStream, error) {
	hdr, err := readAtExact(f, 0, 32)
	if err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(hdr[0:4]) != minidumpSignature {
		return nil, fmt.Errorf("not a Windows minidump (missing MDMP signature)")
	}
	count := binary.LittleEndian.Uint32(hdr[8:12])
	dirRVA := binary.LittleEndian.Uint32(hdr[12:16])
	if count == 0 || count > maxReasonableDumpItems {
		return nil, fmt.Errorf("minidump stream count %d is not sane", count)
	}
	raw, err := readAtExact(f, uint64(dirRVA), uint64(count)*12)
	if err != nil {
		return nil, fmt.Errorf("read minidump stream directory: %w", err)
	}
	out := make([]dumpStream, 0, count)
	for i := uint32(0); i < count; i++ {
		off := i * 12
		out = append(out, dumpStream{
			typ:      binary.LittleEndian.Uint32(raw[off : off+4]),
			dataSize: binary.LittleEndian.Uint32(raw[off+4 : off+8]),
			rva:      binary.LittleEndian.Uint32(raw[off+8 : off+12]),
		})
	}
	return out, nil
}

func streamOfType(streams []dumpStream, typ uint32) (dumpStream, bool) {
	for _, s := range streams {
		if s.typ == typ {
			return s, true
		}
	}
	return dumpStream{}, false
}

func readMinidumpUTF16String(f *os.File, rva uint32) string {
	if rva == 0 {
		return ""
	}
	lenRaw, err := readAtExact(f, uint64(rva), 4)
	if err != nil {
		return ""
	}
	byteLen := binary.LittleEndian.Uint32(lenRaw)
	if byteLen == 0 || byteLen > 1<<20 || byteLen%2 != 0 {
		return ""
	}
	raw, err := readAtExact(f, uint64(rva)+4, uint64(byteLen))
	if err != nil {
		return ""
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

func parseMinidumpModules(f *os.File, streams []dumpStream) ([]dumpModule, error) {
	s, ok := streamOfType(streams, moduleListStream)
	if !ok {
		return nil, fmt.Errorf("minidump has no ModuleListStream")
	}
	countRaw, err := readAtExact(f, uint64(s.rva), 4)
	if err != nil {
		return nil, fmt.Errorf("read module count: %w", err)
	}
	count := binary.LittleEndian.Uint32(countRaw)
	if count == 0 || count > maxReasonableDumpItems {
		return nil, fmt.Errorf("minidump module count %d is not sane", count)
	}
	const moduleSize = 108
	raw, err := readAtExact(f, uint64(s.rva)+4, uint64(count)*moduleSize)
	if err != nil {
		return nil, fmt.Errorf("read module list: %w", err)
	}
	out := make([]dumpModule, 0, count)
	for i := uint32(0); i < count; i++ {
		off := i * moduleSize
		base := binary.LittleEndian.Uint64(raw[off : off+8])
		size := binary.LittleEndian.Uint32(raw[off+8 : off+12])
		nameRVA := binary.LittleEndian.Uint32(raw[off+20 : off+24])
		out = append(out, dumpModule{base: base, size: size, name: readMinidumpUTF16String(f, nameRVA)})
	}
	return out, nil
}

func parseMinidumpMemoryRanges(f *os.File, streams []dumpStream) ([]dumpMemoryRange, error) {
	ranges := make([]dumpMemoryRange, 0, 4096)

	if s, ok := streamOfType(streams, memory64ListStream); ok {
		hdr, err := readAtExact(f, uint64(s.rva), 16)
		if err != nil {
			return nil, fmt.Errorf("read Memory64ListStream header: %w", err)
		}
		count := binary.LittleEndian.Uint64(hdr[0:8])
		baseRVA := binary.LittleEndian.Uint64(hdr[8:16])
		if count > maxReasonableDumpItems {
			return nil, fmt.Errorf("Memory64 range count %d is not sane", count)
		}
		raw, err := readAtExact(f, uint64(s.rva)+16, count*16)
		if err != nil {
			return nil, fmt.Errorf("read Memory64 descriptors: %w", err)
		}
		dataOff := baseRVA
		for i := uint64(0); i < count; i++ {
			off := i * 16
			start := binary.LittleEndian.Uint64(raw[off : off+8])
			size := binary.LittleEndian.Uint64(raw[off+8 : off+16])
			if size > 0 {
				ranges = append(ranges, dumpMemoryRange{start: start, size: size, fileOff: dataOff})
			}
			if ^uint64(0)-dataOff < size {
				return nil, fmt.Errorf("Memory64 data offset overflow")
			}
			dataOff += size
		}
	}

	if s, ok := streamOfType(streams, memoryListStream); ok {
		countRaw, err := readAtExact(f, uint64(s.rva), 4)
		if err != nil {
			return nil, fmt.Errorf("read MemoryListStream count: %w", err)
		}
		count := binary.LittleEndian.Uint32(countRaw)
		if count > maxReasonableDumpItems {
			return nil, fmt.Errorf("MemoryList range count %d is not sane", count)
		}
		raw, err := readAtExact(f, uint64(s.rva)+4, uint64(count)*16)
		if err != nil {
			return nil, fmt.Errorf("read MemoryList descriptors: %w", err)
		}
		for i := uint32(0); i < count; i++ {
			off := i * 16
			start := binary.LittleEndian.Uint64(raw[off : off+8])
			size := binary.LittleEndian.Uint32(raw[off+8 : off+12])
			rva := binary.LittleEndian.Uint32(raw[off+12 : off+16])
			if size > 0 {
				ranges = append(ranges, dumpMemoryRange{start: start, size: uint64(size), fileOff: uint64(rva)})
			}
		}
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("minidump has no MemoryListStream or Memory64ListStream data")
	}
	return ranges, nil
}

func normalizePathForDumpMatch(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, `\\?\`)
	return strings.ToLower(path)
}

func selectDumpModule(modules []dumpModule, exePath string) (dumpModule, error) {
	target := normalizePathForDumpMatch(exePath)
	targetBase := strings.ToLower(filepath.Base(exePath))
	exact := make([]dumpModule, 0, 1)
	baseMatches := make([]dumpModule, 0, 2)
	for _, m := range modules {
		if m.size == 0 || m.base == 0 {
			continue
		}
		if m.name != "" && normalizePathForDumpMatch(m.name) == target {
			exact = append(exact, m)
		}
		if strings.ToLower(filepath.Base(m.name)) == targetBase {
			baseMatches = append(baseMatches, m)
		}
	}
	if len(exact) == 1 {
		return exact[0], nil
	}
	if len(exact) > 1 {
		return dumpModule{}, fmt.Errorf("minidump contains %d exact-path copies of the selected executable", len(exact))
	}
	if len(baseMatches) == 1 {
		return baseMatches[0], nil
	}
	if len(baseMatches) > 1 {
		return dumpModule{}, fmt.Errorf("minidump contains %d modules named %s; exact executable path was not available to disambiguate", len(baseMatches), filepath.Base(exePath))
	}
	return dumpModule{}, fmt.Errorf("selected executable %s was not found in the minidump module list", filepath.Base(exePath))
}

func intersect(a0, a1, b0, b1 uint64) (uint64, uint64, bool) {
	s := a0
	if b0 > s {
		s = b0
	}
	e := a1
	if b1 < e {
		e = b1
	}
	return s, e, e > s
}

func mergeCoverage(in []coverageRange) []coverageRange {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].start == in[j].start {
			return in[i].end < in[j].end
		}
		return in[i].start < in[j].start
	})
	out := make([]coverageRange, 0, len(in))
	cur := in[0]
	for _, r := range in[1:] {
		if r.start <= cur.end {
			if r.end > cur.end {
				cur.end = r.end
			}
			continue
		}
		out = append(out, cur)
		cur = r
	}
	out = append(out, cur)
	return out
}

func coverageBytes(ranges []coverageRange, start, end uint64) uint64 {
	if end <= start {
		return 0
	}
	var total uint64
	for _, r := range ranges {
		s, e, ok := intersect(start, end, r.start, r.end)
		if ok {
			total += e - s
		}
	}
	return total
}

func copyFileRange(src, dst *os.File, srcOff, dstOff, size uint64) error {
	const chunkSize = 1 << 20
	buf := make([]byte, chunkSize)
	var done uint64
	for done < size {
		want := uint64(len(buf))
		if remain := size - done; remain < want {
			want = remain
		}
		n, err := src.ReadAt(buf[:want], int64(srcOff+done))
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		if _, err := dst.WriteAt(buf[:n], int64(dstOff+done)); err != nil {
			return err
		}
		done += uint64(n)
		if uint64(n) != want {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func parseMappedPELayout(header []byte, limit uint64) (uint64, uint64, []normalizedSection, error) {
	if len(header) < 0x200 || header[0] != 'M' || header[1] != 'Z' {
		return 0, 0, nil, fmt.Errorf("mapped image does not begin with an MZ header")
	}
	peOff := uint64(binary.LittleEndian.Uint32(header[0x3C:0x40]))
	if peOff+24 > uint64(len(header)) {
		return 0, 0, nil, fmt.Errorf("PE header offset 0x%X is outside captured headers", peOff)
	}
	if string(header[peOff:peOff+4]) != "PE\x00\x00" {
		return 0, 0, nil, fmt.Errorf("mapped image has an invalid PE signature")
	}
	numSections := binary.LittleEndian.Uint16(header[peOff+6 : peOff+8])
	optSize := binary.LittleEndian.Uint16(header[peOff+20 : peOff+22])
	optOff := peOff + 24
	if optOff+uint64(optSize) > uint64(len(header)) || optSize < 0x70 {
		return 0, 0, nil, fmt.Errorf("optional header is truncated")
	}
	if binary.LittleEndian.Uint16(header[optOff:optOff+2]) != 0x20B {
		return 0, 0, nil, fmt.Errorf("mapped image is not PE32+ (Win64)")
	}
	imageBase := binary.LittleEndian.Uint64(header[optOff+24 : optOff+32])
	imageSize := uint64(binary.LittleEndian.Uint32(header[optOff+56 : optOff+60]))
	headerSize := uint64(binary.LittleEndian.Uint32(header[optOff+60 : optOff+64]))
	if imageSize == 0 || imageSize > limit || headerSize == 0 || headerSize > imageSize || headerSize > 16*1024*1024 {
		return 0, 0, nil, fmt.Errorf("mapped PE SizeOfImage/SizeOfHeaders is not sane (image=0x%X headers=0x%X limit=0x%X)", imageSize, headerSize, limit)
	}
	sectionOff := optOff + uint64(optSize)
	if sectionOff+uint64(numSections)*40 > uint64(len(header)) {
		return 0, 0, nil, fmt.Errorf("section table is truncated")
	}
	sections := make([]normalizedSection, 0, numSections)
	for i := uint16(0); i < numSections; i++ {
		off := sectionOff + uint64(i)*40
		nameRaw := header[off : off+8]
		if z := bytesIndexByte(nameRaw, 0); z >= 0 {
			nameRaw = nameRaw[:z]
		}
		name := string(nameRaw)
		vsize := binary.LittleEndian.Uint32(header[off+8 : off+12])
		rva := binary.LittleEndian.Uint32(header[off+12 : off+16])
		rawSize := binary.LittleEndian.Uint32(header[off+16 : off+20])
		characteristics := binary.LittleEndian.Uint32(header[off+36 : off+40])
		span := vsize
		if rawSize > span {
			span = rawSize
		}
		if uint64(rva) >= imageSize {
			span = 0
		} else if uint64(rva)+uint64(span) > imageSize {
			span = uint32(imageSize - uint64(rva))
		}
		sections = append(sections, normalizedSection{
			headerOffset: uint32(off),
			name:         name,
			rva:          rva,
			span:         span,
			executable:   characteristics&imageScnMemExecute != 0,
		})
	}
	return imageBase, imageSize, sections, nil
}

func bytesIndexByte(b []byte, v byte) int {
	for i, x := range b {
		if x == v {
			return i
		}
	}
	return -1
}

func normalizeMappedPEFile(outPath string, coverage []coverageRange, expectedLimit uint64) (uint64, uint64, int, uint64, uint64, error) {
	f, err := os.OpenFile(outPath, os.O_RDWR, 0)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	defer f.Close()

	probeSize := uint64(0x10000)
	if expectedLimit < probeSize {
		probeSize = expectedLimit
	}
	probe, err := readAtExact(f, 0, probeSize)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	_, imageSize, sections, err := parseMappedPELayout(probe, expectedLimit)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}

	// Reload enough bytes for the full PE header/section table if the first probe
	// happened to be smaller than SizeOfHeaders.
	peOff := uint64(binary.LittleEndian.Uint32(probe[0x3C:0x40]))
	optOff := peOff + 24
	headerSize := uint64(binary.LittleEndian.Uint32(probe[optOff+60 : optOff+64]))
	fullHeader, err := readAtExact(f, 0, headerSize)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}

	var execSpan uint64
	var failedExec uint64
	merged := mergeCoverage(coverage)
	for _, sec := range sections {
		off := int(sec.headerOffset)
		if off+24 > len(fullHeader) {
			return 0, 0, 0, 0, 0, fmt.Errorf("section header for %s is outside SizeOfHeaders", sec.name)
		}
		binary.LittleEndian.PutUint32(fullHeader[off+16:off+20], sec.span)
		binary.LittleEndian.PutUint32(fullHeader[off+20:off+24], sec.rva)
		if sec.executable && sec.span > 0 {
			execSpan += uint64(sec.span)
			have := coverageBytes(merged, uint64(sec.rva), uint64(sec.rva)+uint64(sec.span))
			if have < uint64(sec.span) {
				failedExec += uint64(sec.span) - have
			}
		}
	}
	if _, err := f.WriteAt(fullHeader, 0); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	if err := f.Truncate(int64(imageSize)); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	return imageSize, headerSize, len(sections), execSpan, failedExec, nil
}

func importMinidump(exePath, dumpPath, outPath, progressPath string) RuntimeCaptureResult {
	result := RuntimeCaptureResult{Status: "ERROR", SourceKind: "dump", SourcePath: dumpPath, Format: "MINIDUMP"}
	f, err := os.Open(dumpPath)
	if err != nil {
		result.Detail = "open runtime dump: " + err.Error()
		return result
	}
	defer f.Close()

	writeDumpProgress(progressPath, 4, "Reading minidump streams")
	streams, err := parseMinidumpStreams(f)
	if err != nil {
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = err.Error()
		return result
	}
	modules, err := parseMinidumpModules(f, streams)
	if err != nil {
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = err.Error()
		return result
	}
	mod, err := selectDumpModule(modules, exePath)
	if err != nil {
		result.Status = "MODULE_NOT_FOUND"
		result.Detail = err.Error()
		return result
	}
	result.Base = mod.base
	result.ImageSize = uint64(mod.size)
	result.ProcessPath = mod.name

	writeDumpProgress(progressPath, 10, "Indexing dumped memory ranges")
	ranges, err := parseMinidumpMemoryRanges(f, streams)
	if err != nil {
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = err.Error()
		return result
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		result.Detail = "create runtime snapshot directory: " + err.Error()
		return result
	}
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		result.Detail = "create normalized runtime snapshot: " + err.Error()
		return result
	}
	if err := out.Truncate(int64(mod.size)); err != nil {
		out.Close()
		result.Detail = "size normalized runtime snapshot: " + err.Error()
		return result
	}

	moduleStart := mod.base
	moduleEnd := mod.base + uint64(mod.size)
	coverage := make([]coverageRange, 0, 128)
	overlapping := make([]dumpMemoryRange, 0, 128)
	for _, r := range ranges {
		if _, _, ok := intersect(moduleStart, moduleEnd, r.start, r.start+r.size); ok {
			overlapping = append(overlapping, r)
		}
	}
	if len(overlapping) == 0 {
		out.Close()
		_ = os.Remove(outPath)
		result.Status = "NO_MODULE_MEMORY"
		result.Detail = "the dump lists the selected executable module but contains no memory ranges for it"
		return result
	}

	for i, r := range overlapping {
		s, e, ok := intersect(moduleStart, moduleEnd, r.start, r.start+r.size)
		if !ok {
			continue
		}
		pct := 12 + int((uint64(i)*70)/uint64(len(overlapping)))
		writeDumpProgress(progressPath, pct, fmt.Sprintf("Copying module memory range %d/%d", i+1, len(overlapping)))
		srcOff := r.fileOff + (s - r.start)
		dstOff := s - moduleStart
		size := e - s
		if err := copyFileRange(f, out, srcOff, dstOff, size); err != nil {
			out.Close()
			_ = os.Remove(outPath)
			result.Detail = fmt.Sprintf("copy dumped module range at 0x%X: %v", s, err)
			return result
		}
		coverage = append(coverage, coverageRange{start: dstOff, end: dstOff + size})
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(outPath)
		result.Detail = "sync normalized runtime snapshot: " + err.Error()
		return result
	}
	out.Close()

	merged := mergeCoverage(coverage)
	var covered uint64
	for _, c := range merged {
		covered += c.end - c.start
	}
	result.ReadBytes = covered
	if covered < uint64(mod.size) {
		result.FailedBytes = uint64(mod.size) - covered
	}

	writeDumpProgress(progressPath, 86, "Normalizing mapped PE section layout")
	imageSize, _, sections, execSpan, failedExec, err := normalizeMappedPEFile(outPath, merged, uint64(mod.size))
	if err != nil {
		_ = os.Remove(outPath)
		result.Status = "INVALID_MAPPED_IMAGE"
		result.Detail = "dumped module could not be normalized as PE32+: " + err.Error()
		return result
	}
	result.ImageSize = imageSize
	result.Sections = sections
	result.ExecSpanBytes = execSpan
	result.FailedExecBytes = failedExec
	if result.ReadBytes > imageSize {
		result.ReadBytes = imageSize
	}
	result.FailedBytes = imageSize - result.ReadBytes

	result.Success = true
	result.Status = "OK"
	result.Detail = fmt.Sprintf("imported %s for %s from a Windows minidump; %d of %d mapped bytes present", filepath.Base(exePath), filepath.Base(dumpPath), result.ReadBytes, imageSize)
	if failedExec > 0 {
		result.Detail += fmt.Sprintf("; %d executable bytes are absent and remain zero-filled", failedExec)
	}
	writeDumpProgress(progressPath, 100, "Runtime dump imported")
	return result
}

func importMappedPE(exePath, dumpPath, outPath, progressPath string) RuntimeCaptureResult {
	result := RuntimeCaptureResult{Status: "ERROR", SourceKind: "dump", SourcePath: dumpPath, Format: "MAPPED_PE"}
	f, err := os.Open(dumpPath)
	if err != nil {
		result.Detail = "open mapped image: " + err.Error()
		return result
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		result.Detail = "stat mapped image: " + err.Error()
		return result
	}
	if info.Size() < 0x1000 {
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = "mapped image is too small"
		return result
	}
	probeLen := uint64(0x10000)
	if uint64(info.Size()) < probeLen {
		probeLen = uint64(info.Size())
	}
	probe, err := readAtExact(f, 0, probeLen)
	if err != nil {
		result.Detail = "read mapped image headers: " + err.Error()
		return result
	}
	imageBase, imageSize, _, err := parseMappedPELayout(probe, uint64(info.Size()))
	if err != nil {
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = err.Error()
		return result
	}
	// A mapped image must be large enough to address bytes by RVA. This rejects
	// an ordinary packed on-disk EXE whose raw file layout is smaller/different.
	if uint64(info.Size()) < imageSize {
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = fmt.Sprintf("PE file is %d bytes but SizeOfImage is %d; this looks like an on-disk PE rather than a mapped-image snapshot", info.Size(), imageSize)
		return result
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		result.Detail = "create runtime snapshot directory: " + err.Error()
		return result
	}
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		result.Detail = "create normalized runtime snapshot: " + err.Error()
		return result
	}
	if err := out.Truncate(int64(imageSize)); err != nil {
		out.Close()
		result.Detail = "size normalized runtime snapshot: " + err.Error()
		return result
	}
	writeDumpProgress(progressPath, 20, "Copying mapped PE image")
	if err := copyFileRange(f, out, 0, 0, imageSize); err != nil {
		out.Close()
		_ = os.Remove(outPath)
		result.Detail = "copy mapped PE image: " + err.Error()
		return result
	}
	out.Close()

	coverage := []coverageRange{{start: 0, end: imageSize}}
	writeDumpProgress(progressPath, 82, "Normalizing mapped PE section layout")
	normalizedSize, _, sections, execSpan, failedExec, err := normalizeMappedPEFile(outPath, coverage, imageSize)
	if err != nil {
		_ = os.Remove(outPath)
		result.Status = "INVALID_MAPPED_IMAGE"
		result.Detail = err.Error()
		return result
	}
	result.Success = true
	result.Status = "OK"
	result.Base = imageBase
	result.ImageSize = normalizedSize
	result.Sections = sections
	result.ReadBytes = normalizedSize
	result.ExecSpanBytes = execSpan
	result.FailedExecBytes = failedExec
	result.ProcessPath = exePath
	result.Detail = fmt.Sprintf("imported mapped PE snapshot %s", filepath.Base(dumpPath))
	writeDumpProgress(progressPath, 100, "Mapped runtime image imported")
	return result
}

func importRuntimeDump(exePath, dumpPath, outPath, progressPath string) RuntimeCaptureResult {
	result := RuntimeCaptureResult{Status: "ERROR", SourceKind: "dump", SourcePath: dumpPath, Format: "UNKNOWN"}
	if strings.TrimSpace(dumpPath) == "" {
		result.Status = "NOT_FOUND"
		result.Detail = "runtime dump path is empty"
		return result
	}
	f, err := os.Open(dumpPath)
	if err != nil {
		result.Status = "NOT_FOUND"
		result.Detail = "open runtime dump: " + err.Error()
		return result
	}
	sig := make([]byte, 4)
	n, readErr := f.Read(sig)
	f.Close()
	if readErr != nil && readErr != io.EOF {
		result.Detail = "read runtime dump signature: " + readErr.Error()
		return result
	}
	if n < 2 {
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = "runtime dump is too small"
		return result
	}

	switch {
	case n >= 4 && binary.LittleEndian.Uint32(sig) == minidumpSignature:
		return importMinidump(exePath, dumpPath, outPath, progressPath)
	case sig[0] == 'M' && sig[1] == 'Z':
		return importMappedPE(exePath, dumpPath, outPath, progressPath)
	default:
		result.Status = "UNSUPPORTED_DUMP"
		result.Detail = "unsupported runtime artifact: expected a Windows MDMP dump or a mapped PE image beginning with MZ"
		return result
	}
}

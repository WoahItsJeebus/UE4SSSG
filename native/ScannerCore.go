package main

import (
	"bufio"
	"bytes"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf16"

	"ue4ssscanner/x86asm"
)

type Pattern struct {
	ID       int
	Text     string
	B        []byte
	M        []byte
	RunStart int
	Run      []byte
}

type Section struct {
	Name        string
	RVA         uint32
	Raw         uint32
	Size        uint32 // raw-backed bytes available in the file
	VirtualSize uint32 // mapped image extent, including zero-filled BSS
	Exec        bool
}

type Match struct {
	Raw     int
	RVA     uint32
	Section string
}

type Result struct {
	ID      int
	Matches []Match
}

type RuntimeFunc struct {
	Begin  uint32
	End    uint32
	Unwind uint32
}

type SemanticIndex struct {
	LeaByTarget map[uint32][]uint32
	Outgoing    map[uint32][]Edge
	Inbound     map[uint32][]Edge
}

type Image struct {
	Data          []byte
	Sections      []Section
	ImageBase     uint64
	SizeOfImage   uint32
	Runtime       []RuntimeFunc
	RuntimeSource string
	Starts        map[uint32]RuntimeFunc
	Semantic      *SemanticIndex
}

type Edge struct {
	Site         uint32
	Target       uint32
	DirectTarget uint32
	Opcode       byte
	Caller       RuntimeFunc
}

type SCOResult struct {
	Found      bool
	TargetRVA  uint32
	CallRVA    uint32
	CallOpcode byte
	Support    int
	RunnerUp   int
	Detail     string
}

type SCOProofResult struct {
	Passed         bool
	TargetRVA      uint32
	Score          int
	DistinctFields int
	CoreCalls      int
	ClassFlagsDisp int64
	ReturnsResult  bool
	Detail         string
}

type LegacyFNameResult struct {
	Found      bool
	GNamesRVA  uint32
	GetterRVA  uint32
	TargetRVA  uint32
	Score      int
	RunnerUp   int
	Candidates int
	Detail     string
}

type FNameCtorProofResult struct {
	Passed       bool
	TargetRVA    uint32
	HelperRVA    uint32
	WrapperScore int
	HelperScore  int
	Detail       string
}

type GUObjectProofResult struct {
	Passed     bool
	TargetRVA  uint32
	CtorRVA    uint32
	CallRVA    uint32
	LeaRVA     uint32
	Score      int
	RunnerUp   int
	Candidates int
	Detail     string
	Adjustment int32
	ProofKinds int
}

type RuntimeCaptureResult struct {
	Success         bool
	Status          string
	PID             uint32
	Base            uint64
	ImageSize       uint64
	Sections        int
	ReadBytes       uint64
	FailedBytes     uint64
	ExecSpanBytes   uint64
	FailedExecBytes uint64
	ProcessPath     string
	SourceKind      string
	SourcePath      string
	Format          string
	Detail          string
}

func main() {
	exePath := flag.String("exe", "", "PE executable to scan")
	manifestPath := flag.String("manifest", "", "TSV manifest")
	outPath := flag.String("out", "", "TSV results")
	progressPath := flag.String("progress", "", "progress file")
	scoOut := flag.String("semantic-sco", "", "resolve StaticConstructObject semantically and write TSV result")
	scoProofOut := flag.String("semantic-sco-proof", "", "corroborate a StaticConstructObject candidate structurally and write TSV result")
	scoCandidate := flag.String("sco-candidate", "", "StaticConstructObject candidate RVA (hex or decimal) for semantic proof")
	legacyFNameOut := flag.String("semantic-legacy-fname", "", "resolve pre-4.23 FName::ToString semantically and write TSV result")
	fnameCtorOut := flag.String("semantic-fname-ctor-proof", "", "corroborate an FName wchar constructor candidate structurally and write TSV result")
	fnameCtorCandidate := flag.String("fname-ctor-candidate", "", "FName constructor candidate RVA (hex or decimal) for semantic proof")
	guObjectOut := flag.String("semantic-guobject-proof", "", "corroborate a GUObjectArray candidate structurally and write TSV result")
	guObjectDiscoverOut := flag.String("semantic-guobject-discover", "", "discover GUObjectArray structurally from its constructor and write TSV result")
	guObjectOutlinedOut := flag.String("semantic-guobject-outlined", "", "discover GUObjectArray from outlined/LTO Allocate/Free/shutdown field clusters")
	guObjectCandidate := flag.String("guobject-candidate", "", "GUObjectArray candidate RVA (hex or decimal) for semantic proof")
	captureRuntimeOut := flag.String("capture-runtime", "", "capture the running selected executable into a normalized mapped-image PE snapshot")
	runtimeMetaOut := flag.String("runtime-meta", "", "write runtime capture/import metadata as TSV")
	runtimeDumpPath := flag.String("runtime-dump", "", "import a Windows process dump or mapped PE image instead of reading a live process")
	runtimeWaitMs := flag.Int("runtime-wait-ms", 0, "milliseconds to wait for the selected executable process")
	maxMatches := flag.Int("max-matches", 256, "maximum matches retained per pattern")
	workers := flag.Int("workers", 0, "worker count")
	flag.Parse()

	if *exePath == "" {
		fatalf("missing --exe")
	}
	if *captureRuntimeOut != "" {
		var result RuntimeCaptureResult
		if strings.TrimSpace(*runtimeDumpPath) != "" {
			result = importRuntimeDump(*exePath, *runtimeDumpPath, *captureRuntimeOut, *progressPath)
		} else {
			result = captureRuntimeImage(*exePath, *captureRuntimeOut, *progressPath, *runtimeWaitMs)
		}
		if *runtimeMetaOut != "" {
			if err := writeRuntimeCaptureMeta(*runtimeMetaOut, result); err != nil {
				fatalf("write runtime capture metadata: %v", err)
			}
		}
		if !result.Success {
			os.Exit(3)
		}
		return
	}
	data, err := os.ReadFile(*exePath)
	if err != nil {
		fatalf("read exe: %v", err)
	}
	img, err := parseImage(data)
	if err != nil {
		fatalf("parse PE: %v", err)
	}

	if *scoOut != "" {
		writeSemanticProgress(*progressPath, 2, "Parsing PE runtime-function metadata")
		result := resolveSCO(img, func(p int, stage string) {
			writeSemanticProgress(*progressPath, p, stage)
		})
		if err := writeSCOResult(*scoOut, result); err != nil {
			fatalf("write semantic result: %v", err)
		}
		writeSemanticProgress(*progressPath, 100, "Complete")
		return
	}

	if *scoProofOut != "" {
		if strings.TrimSpace(*scoCandidate) == "" {
			fatalf("--semantic-sco-proof requires --sco-candidate")
		}
		candidate64, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(*scoCandidate), "0x"), 16, 32)
		if err != nil {
			fatalf("invalid --sco-candidate: %v", err)
		}
		writeSemanticProgress(*progressPath, 2, "Parsing PE runtime-function metadata")
		result := corroborateStaticConstructObjectCandidate(img, uint32(candidate64), func(p int, stage string) {
			writeSemanticProgress(*progressPath, p, stage)
		})
		if err := writeSCOProofResult(*scoProofOut, result); err != nil {
			fatalf("write StaticConstructObject proof result: %v", err)
		}
		writeSemanticProgress(*progressPath, 100, "Complete")
		return
	}

	if *legacyFNameOut != "" {
		writeSemanticProgress(*progressPath, 2, "Parsing PE runtime-function metadata")
		result := resolveLegacyFName(img, func(p int, stage string) {
			writeSemanticProgress(*progressPath, p, stage)
		})
		if err := writeLegacyFNameResult(*legacyFNameOut, result); err != nil {
			fatalf("write legacy FName result: %v", err)
		}
		writeSemanticProgress(*progressPath, 100, "Complete")
		return
	}

	if *fnameCtorOut != "" {
		if strings.TrimSpace(*fnameCtorCandidate) == "" {
			fatalf("--semantic-fname-ctor-proof requires --fname-ctor-candidate")
		}
		candidate64, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(*fnameCtorCandidate), "0x"), 16, 32)
		if err != nil {
			fatalf("invalid --fname-ctor-candidate: %v", err)
		}
		writeSemanticProgress(*progressPath, 2, "Parsing PE runtime-function metadata")
		result := corroborateFNameConstructor(img, uint32(candidate64), func(p int, stage string) {
			writeSemanticProgress(*progressPath, p, stage)
		})
		if err := writeFNameCtorProofResult(*fnameCtorOut, result); err != nil {
			fatalf("write FName constructor proof result: %v", err)
		}
		writeSemanticProgress(*progressPath, 100, "Complete")
		return
	}

	if *guObjectOutlinedOut != "" {
		writeSemanticProgress(*progressPath, 2, "Parsing PE runtime-function metadata")
		result := discoverGUObjectArrayOutlined(img, func(p int, stage string) {
			writeSemanticProgress(*progressPath, p, stage)
		})
		if err := writeGUObjectProofResult(*guObjectOutlinedOut, result); err != nil {
			fatalf("write outlined GUObjectArray discovery result: %v", err)
		}
		writeSemanticProgress(*progressPath, 100, "Complete")
		return
	}

	if *guObjectDiscoverOut != "" {
		writeSemanticProgress(*progressPath, 2, "Parsing PE runtime-function metadata")
		result := discoverGUObjectArrayStructure(img, func(p int, stage string) {
			writeSemanticProgress(*progressPath, p, stage)
		})
		if err := writeGUObjectProofResult(*guObjectDiscoverOut, result); err != nil {
			fatalf("write GUObjectArray discovery result: %v", err)
		}
		writeSemanticProgress(*progressPath, 100, "Complete")
		return
	}

	if *guObjectOut != "" {
		if strings.TrimSpace(*guObjectCandidate) == "" {
			fatalf("--semantic-guobject-proof requires --guobject-candidate")
		}
		candidate64, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(*guObjectCandidate), "0x"), 16, 32)
		if err != nil {
			fatalf("invalid --guobject-candidate: %v", err)
		}
		writeSemanticProgress(*progressPath, 2, "Parsing PE runtime-function metadata")
		result := corroborateGUObjectArrayStructure(img, uint32(candidate64), func(p int, stage string) {
			writeSemanticProgress(*progressPath, p, stage)
		})
		if err := writeGUObjectProofResult(*guObjectOut, result); err != nil {
			fatalf("write GUObjectArray proof result: %v", err)
		}
		writeSemanticProgress(*progressPath, 100, "Complete")
		return
	}

	if *manifestPath == "" || *outPath == "" {
		fatalf("missing required static-scan arguments")
	}
	patterns, err := readManifest(*manifestPath)
	if err != nil {
		fatalf("manifest: %v", err)
	}

	nWorkers := *workers
	if nWorkers <= 0 {
		nWorkers = runtime.NumCPU() / 2
		if nWorkers < 2 {
			nWorkers = 2
		}
		if nWorkers > 8 {
			nWorkers = 8
		}
	}
	if nWorkers > len(patterns) && len(patterns) > 0 {
		nWorkers = len(patterns)
	}
	if nWorkers < 1 {
		nWorkers = 1
	}

	jobs := make(chan Pattern)
	results := make(chan Result, len(patterns))
	var done atomic.Int64
	var wg sync.WaitGroup
	var progressMu sync.Mutex

	writeProgress := func(d int64) {
		if *progressPath == "" {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		tmp := *progressPath + ".tmp"
		_ = os.WriteFile(tmp, []byte(fmt.Sprintf("%d\t%d\n", d, len(patterns))), 0644)
		_ = os.Rename(tmp, *progressPath)
	}
	writeProgress(0)

	for i := 0; i < nWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				matches := scanPattern(img.Data, img.Sections, p, *maxMatches)
				results <- Result{ID: p.ID, Matches: matches}
				writeProgress(done.Add(1))
			}
		}()
	}
	go func() {
		for _, p := range patterns {
			jobs <- p
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	all := make([]Result, 0, len(patterns))
	for r := range results {
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	f, err := os.Create(*outPath)
	if err != nil {
		fatalf("create output: %v", err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	for _, r := range all {
		fmt.Fprintf(w, "RESULT\t%d\t%d", r.ID, len(r.Matches))
		for _, m := range r.Matches {
			sec := strings.ReplaceAll(m.Section, "|", "_")
			fmt.Fprintf(w, "\t%X,%X,%s", m.Raw, m.RVA, sec)
		}
		fmt.Fprintln(w)
	}
	_ = w.Flush()
	_ = f.Close()
	writeProgress(int64(len(patterns)))
}

func writeRuntimeCaptureMeta(path string, result RuntimeCaptureResult) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	clean := func(v string) string {
		v = strings.ReplaceAll(v, "\t", " ")
		v = strings.ReplaceAll(v, "\r", " ")
		v = strings.ReplaceAll(v, "\n", " ")
		return v
	}
	fmt.Fprintf(w, "STATUS\t%s\n", clean(result.Status))
	fmt.Fprintf(w, "PID\t%d\n", result.PID)
	fmt.Fprintf(w, "BASE\t%X\n", result.Base)
	fmt.Fprintf(w, "IMAGE_SIZE\t%d\n", result.ImageSize)
	fmt.Fprintf(w, "SECTIONS\t%d\n", result.Sections)
	fmt.Fprintf(w, "READ_BYTES\t%d\n", result.ReadBytes)
	fmt.Fprintf(w, "FAILED_BYTES\t%d\n", result.FailedBytes)
	fmt.Fprintf(w, "EXEC_SPAN_BYTES\t%d\n", result.ExecSpanBytes)
	fmt.Fprintf(w, "FAILED_EXEC_BYTES\t%d\n", result.FailedExecBytes)
	fmt.Fprintf(w, "PROCESS_PATH\t%s\n", clean(result.ProcessPath))
	fmt.Fprintf(w, "SOURCE_KIND\t%s\n", clean(result.SourceKind))
	fmt.Fprintf(w, "SOURCE_PATH\t%s\n", clean(result.SourcePath))
	fmt.Fprintf(w, "FORMAT\t%s\n", clean(result.Format))
	fmt.Fprintf(w, "DETAIL\t%s\n", clean(result.Detail))
	return w.Flush()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func parseImage(data []byte) (*Image, error) {
	pf, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer pf.Close()

	img := &Image{Data: data, Starts: make(map[uint32]RuntimeFunc)}
	var exceptionRVA, exceptionSize uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		img.ImageBase = oh.ImageBase
		img.SizeOfImage = oh.SizeOfImage
		// IMAGE_DIRECTORY_ENTRY_EXCEPTION (index 3) is the authoritative
		// Win64 RUNTIME_FUNCTION directory. Do not assume the table must live
		// in a section literally named ".pdata"; linkers are free to merge or
		// rename sections while still advertising the exception directory.
		if oh.NumberOfRvaAndSizes > 3 {
			exceptionRVA = oh.DataDirectory[3].VirtualAddress
			exceptionSize = oh.DataDirectory[3].Size
		}
	default:
		return nil, fmt.Errorf("expected PE32+ executable")
	}

	img.Sections = make([]Section, 0, len(pf.Sections))
	for _, s := range pf.Sections {
		size := s.Size
		if uint64(s.Offset)+uint64(size) > uint64(len(data)) {
			if uint64(s.Offset) >= uint64(len(data)) {
				size = 0
			} else {
				size = uint32(len(data)) - s.Offset
			}
		}
		exec := (s.Characteristics&0x20000000) != 0 || s.Name == ".text"
		vsize := s.VirtualSize
		if vsize < size {
			vsize = size
		}
		sec := Section{Name: s.Name, RVA: s.VirtualAddress, Raw: s.Offset, Size: size, VirtualSize: vsize, Exec: exec}
		img.Sections = append(img.Sections, sec)
	}

	appendRuntime := func(begin, finish, unwind uint32) {
		if begin == 0 || finish <= begin || begin >= img.SizeOfImage || finish > img.SizeOfImage {
			return
		}
		fn := RuntimeFunc{Begin: begin, End: finish, Unwind: unwind}
		img.Runtime = append(img.Runtime, fn)
		img.Starts[begin] = fn
	}

	// Preferred path: parse the PE exception directory entry itself. Mapping
	// every 12-byte record through RVA->raw also keeps this correct if the
	// directory does not happen to be represented by one convenient raw slice.
	if exceptionRVA != 0 && exceptionSize >= 12 {
		limit := exceptionSize - (exceptionSize % 12)
		for off := uint32(0); off+12 <= limit; off += 12 {
			raw, ok := img.rvaToRaw(exceptionRVA + off)
			if !ok || raw < 0 || raw+12 > len(data) {
				continue
			}
			appendRuntime(
				binary.LittleEndian.Uint32(data[raw:raw+4]),
				binary.LittleEndian.Uint32(data[raw+4:raw+8]),
				binary.LittleEndian.Uint32(data[raw+8:raw+12]),
			)
		}
		if len(img.Runtime) > 0 {
			img.RuntimeSource = fmt.Sprintf("PE exception directory RVA 0x%X (%d entries)", exceptionRVA, len(img.Runtime))
		}
	}

	// Compatibility fallback for malformed/unusual images whose exception
	// directory is missing even though a conventional .pdata section exists.
	if len(img.Runtime) == 0 {
		for _, sec := range img.Sections {
			if sec.Name != ".pdata" || sec.Size < 12 {
				continue
			}
			end := int(sec.Raw + sec.Size)
			if end > len(data) {
				end = len(data)
			}
			for raw := int(sec.Raw); raw+12 <= end; raw += 12 {
				appendRuntime(
					binary.LittleEndian.Uint32(data[raw:raw+4]),
					binary.LittleEndian.Uint32(data[raw+4:raw+8]),
					binary.LittleEndian.Uint32(data[raw+8:raw+12]),
				)
			}
		}
		if len(img.Runtime) > 0 {
			img.RuntimeSource = fmt.Sprintf("named .pdata fallback (%d entries)", len(img.Runtime))
		}
	}

	sort.Slice(img.Runtime, func(i, j int) bool { return img.Runtime[i].Begin < img.Runtime[j].Begin })
	return img, nil
}

func (img *Image) rvaToRaw(rva uint32) (int, bool) {
	for _, s := range img.Sections {
		if rva >= s.RVA && uint64(rva-s.RVA) < uint64(s.Size) {
			return int(s.Raw + (rva - s.RVA)), true
		}
	}
	return 0, false
}

func (img *Image) rawToRVA(raw int) (uint32, bool) {
	if raw < 0 {
		return 0, false
	}
	r := uint32(raw)
	for _, s := range img.Sections {
		if r >= s.Raw && uint64(r-s.Raw) < uint64(s.Size) {
			return s.RVA + (r - s.Raw), true
		}
	}
	return 0, false
}

func (img *Image) executableRVA(rva uint32) bool {
	for _, s := range img.Sections {
		if !s.Exec {
			continue
		}
		if rva >= s.RVA && uint64(rva-s.RVA) < uint64(s.Size) {
			return true
		}
	}
	return false
}

func (img *Image) canonicalRuntimeFunction(fn RuntimeFunc) RuntimeFunc {
	seen := make(map[uint32]struct{}, 4)
	for depth := 0; depth < 8; depth++ {
		if fn.Unwind == 0 {
			break
		}
		if _, ok := seen[fn.Begin]; ok {
			break
		}
		seen[fn.Begin] = struct{}{}

		raw, ok := img.rvaToRaw(fn.Unwind &^ 0x3)
		if !ok || raw+4 > len(img.Data) {
			break
		}
		flags := img.Data[raw] >> 3
		if flags&0x4 == 0 { // UNW_FLAG_CHAININFO
			break
		}
		countCodes := int(img.Data[raw+2])
		off := 4 + countCodes*2
		if off%4 != 0 {
			off += 2
		}
		if raw+off+12 > len(img.Data) {
			break
		}
		begin := binary.LittleEndian.Uint32(img.Data[raw+off : raw+off+4])
		end := binary.LittleEndian.Uint32(img.Data[raw+off+4 : raw+off+8])
		unwind := binary.LittleEndian.Uint32(img.Data[raw+off+8 : raw+off+12])
		if begin == 0 || end <= begin {
			break
		}
		fn = RuntimeFunc{Begin: begin, End: end, Unwind: unwind}
	}
	return fn
}

func (img *Image) functionContaining(rva uint32) (RuntimeFunc, bool) {
	if fn, ok := img.Starts[rva]; ok {
		return fn, true
	}
	n := len(img.Runtime)
	if n == 0 {
		return RuntimeFunc{}, false
	}
	idx := sort.Search(n, func(i int) bool { return img.Runtime[i].Begin > rva }) - 1
	for checked := 0; idx >= 0 && checked < 256; idx, checked = idx-1, checked+1 {
		fn := img.Runtime[idx]
		if rva >= fn.Begin && rva < fn.End {
			return fn, true
		}
		if rva > fn.Begin && rva-fn.Begin > 0x100000 {
			break
		}
	}
	return RuntimeFunc{}, false
}

func (img *Image) rootFunction(rva uint32) (RuntimeFunc, bool) {
	fn, ok := img.functionContaining(rva)
	if !ok {
		return RuntimeFunc{}, false
	}
	return img.canonicalRuntimeFunction(fn), true
}

func decodeRuntimeFunction(img *Image, fn RuntimeFunc, visit func(site uint32, inst x86asm.Inst) bool) {
	rawStart, ok1 := img.rvaToRaw(fn.Begin)
	rawEndLast, ok2 := img.rvaToRaw(fn.End - 1)
	if !ok1 || !ok2 || rawEndLast < rawStart {
		return
	}
	rawEnd := rawEndLast + 1
	if rawEnd > len(img.Data) {
		rawEnd = len(img.Data)
	}
	raw := rawStart
	site := fn.Begin
	for raw < rawEnd {
		inst, err := x86asm.Decode(img.Data[raw:rawEnd], 64)
		if err != nil || inst.Len <= 0 {
			raw++
			site++
			continue
		}
		if !visit(site, inst) {
			return
		}
		raw += inst.Len
		site += uint32(inst.Len)
	}
}

func decodeLinearRVA(img *Image, start uint32, maxBytes uint32, visit func(site uint32, inst x86asm.Inst) bool) {
	rawStart, ok := img.rvaToRaw(start)
	if !ok || rawStart >= len(img.Data) {
		return
	}
	rawEnd := rawStart + int(maxBytes)
	if rawEnd > len(img.Data) {
		rawEnd = len(img.Data)
	}
	raw := rawStart
	site := start
	for raw < rawEnd {
		inst, err := x86asm.Decode(img.Data[raw:rawEnd], 64)
		if err != nil || inst.Len <= 0 {
			raw++
			site++
			continue
		}
		if !visit(site, inst) {
			return
		}
		raw += inst.Len
		site += uint32(inst.Len)
	}
}

func decodedInstructionAt(img *Image, site uint32) (x86asm.Inst, bool) {
	leaf, ok := img.functionContaining(site)
	if !ok {
		return x86asm.Inst{}, false
	}
	var found x86asm.Inst
	okFound := false
	decodeRuntimeFunction(img, leaf, func(ip uint32, inst x86asm.Inst) bool {
		if ip == site {
			found = inst
			okFound = true
			return false
		}
		if ip > site {
			return false
		}
		return true
	})
	return found, okFound
}

func readManifest(path string) ([]Pattern, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []Pattern{}
	sc := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	sc.Buffer(buf, 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		id, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		p, err := parsePattern(id, parts[1])
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

func parsePattern(id int, text string) (Pattern, error) {
	toks := strings.Fields(text)
	b := []byte{}
	m := []byte{}
	for _, t := range toks {
		if t == "|" {
			continue
		}
		if len(t) != 2 {
			return Pattern{}, fmt.Errorf("pattern %d unsupported token %q", id, t)
		}
		var val, mask byte
		for n := 0; n < 2; n++ {
			c := t[n]
			shift := uint(4 * (1 - n))
			if c == '?' {
				continue
			}
			x, ok := hexNibble(c)
			if !ok {
				return Pattern{}, fmt.Errorf("pattern %d invalid hex %q", id, t)
			}
			val |= x << shift
			mask |= 0xF << shift
		}
		b = append(b, val)
		m = append(m, mask)
	}
	if len(b) == 0 {
		return Pattern{}, fmt.Errorf("pattern %d empty", id)
	}
	bestStart, bestLen := -1, 0
	for i := 0; i < len(m); {
		if m[i] != 0xFF {
			i++
			continue
		}
		j := i
		for j < len(m) && m[j] == 0xFF {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	p := Pattern{ID: id, Text: text, B: b, M: m, RunStart: bestStart}
	if bestStart >= 0 {
		p.Run = append([]byte(nil), b[bestStart:bestStart+bestLen]...)
	}
	return p, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func scanPattern(data []byte, sections []Section, p Pattern, limit int) []Match {
	out := make([]Match, 0, 4)
	plen := len(p.B)
	for _, s := range sections {
		if !s.Exec || s.Size < uint32(plen) {
			continue
		}
		start := int(s.Raw)
		end := start + int(s.Size)
		if start < 0 || end > len(data) || start >= end {
			continue
		}
		sec := data[start:end]
		if p.RunStart >= 0 && len(p.Run) > 0 {
			pos := 0
			for pos < len(sec) && len(out) < limit {
				idx := bytes.Index(sec[pos:], p.Run)
				if idx < 0 {
					break
				}
				runAt := pos + idx
				cand := runAt - p.RunStart
				if cand >= 0 && cand+plen <= len(sec) && matchesAt(sec, cand, p) {
					out = append(out, Match{Raw: start + cand, RVA: s.RVA + uint32(cand), Section: s.Name})
				}
				pos = runAt + 1
			}
		} else {
			for cand := 0; cand+plen <= len(sec) && len(out) < limit; cand++ {
				if matchesAt(sec, cand, p) {
					out = append(out, Match{Raw: start + cand, RVA: s.RVA + uint32(cand), Section: s.Name})
				}
			}
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}

func matchesAt(sec []byte, pos int, p Pattern) bool {
	for i := range p.B {
		if p.M[i] == 0 {
			continue
		}
		if sec[pos+i]&p.M[i] != p.B[i] {
			return false
		}
	}
	return true
}

// ---------------- Native semantic legacy Unreal resolvers ----------------

func writeLegacyFNameResult(path string, r LegacyFNameResult) error {
	status := "NOT_FOUND"
	gnames, getter, target := "-", "-", "-"
	if r.Found {
		status = "FOUND"
		gnames = fmt.Sprintf("%X", r.GNamesRVA)
		getter = fmt.Sprintf("%X", r.GetterRVA)
		target = fmt.Sprintf("%X", r.TargetRVA)
	}
	detail := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(r.Detail)
	return os.WriteFile(path, []byte(fmt.Sprintf("FNAME\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n",
		status, gnames, getter, target, r.Score, r.RunnerUp, r.Candidates, detail)), 0644)
}

func writeFNameCtorProofResult(path string, r FNameCtorProofResult) error {
	status := "NOT_PROVED"
	target, helper := "-", "-"
	if r.Passed {
		status = "PROVED"
		target = fmt.Sprintf("%X", r.TargetRVA)
		helper = fmt.Sprintf("%X", r.HelperRVA)
	}
	detail := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(r.Detail)
	return os.WriteFile(path, []byte(fmt.Sprintf("FCTOR\t%s\t%s\t%s\t%d\t%d\t%s\n",
		status, target, helper, r.WrapperScore, r.HelperScore, detail)), 0644)
}

func writeGUObjectProofResult(path string, r GUObjectProofResult) error {
	status := "NOT_PROVED"
	target, ctor, call, lea := "-", "-", "-", "-"
	if r.Passed {
		status = "PROVED"
		target = fmt.Sprintf("%X", r.TargetRVA)
		ctor = fmt.Sprintf("%X", r.CtorRVA)
		call = fmt.Sprintf("%X", r.CallRVA)
		lea = fmt.Sprintf("%X", r.LeaRVA)
	}
	detail := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(r.Detail)
	return os.WriteFile(path, []byte(fmt.Sprintf("GUOBJ\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\n",
		status, target, ctor, call, lea, r.Score, r.RunnerUp, r.Candidates, detail, r.Adjustment, r.ProofKinds)), 0644)
}

func (img *Image) virtualSectionForRVA(rva uint32) (Section, bool) {
	for _, s := range img.Sections {
		sz := s.VirtualSize
		if sz == 0 {
			sz = s.Size
		}
		if rva >= s.RVA && uint64(rva-s.RVA) < uint64(sz) {
			return s, true
		}
	}
	return Section{}, false
}

func (img *Image) nonExecutableImageRVA(rva uint32) bool {
	s, ok := img.virtualSectionForRVA(rva)
	return ok && !s.Exec
}

func ripMemTarget(site uint32, inst x86asm.Inst, mem x86asm.Mem) (uint32, bool) {
	if mem.Base != x86asm.RIP {
		return 0, false
	}
	t := int64(site) + int64(inst.Len) + mem.Disp
	if t < 0 || t > 0xFFFFFFFF {
		return 0, false
	}
	return uint32(t), true
}

func directBranchTarget(site uint32, inst x86asm.Inst) (uint32, bool) {
	if inst.Op != x86asm.CALL && inst.Op != x86asm.JMP {
		return 0, false
	}
	rel, ok := inst.Args[0].(x86asm.Rel)
	if !ok {
		return 0, false
	}
	t := int64(site) + int64(inst.Len) + int64(rel)
	if t < 0 || t > 0xFFFFFFFF {
		return 0, false
	}
	return uint32(t), true
}

func hasImmediate(inst x86asm.Inst, want int64) bool {
	for _, a := range inst.Args {
		if imm, ok := a.(x86asm.Imm); ok && int64(imm) == want {
			return true
		}
	}
	return false
}

// regFamily collapses byte/word/dword/qword aliases to one GPR identity.
// The result is 0..15 for RAX..R15, or -1 for non-GPR registers.
func regFamily(r x86asm.Reg) int {
	switch r {
	case x86asm.AL, x86asm.AH, x86asm.AX, x86asm.EAX, x86asm.RAX:
		return 0
	case x86asm.CL, x86asm.CH, x86asm.CX, x86asm.ECX, x86asm.RCX:
		return 1
	case x86asm.DL, x86asm.DH, x86asm.DX, x86asm.EDX, x86asm.RDX:
		return 2
	case x86asm.BL, x86asm.BH, x86asm.BX, x86asm.EBX, x86asm.RBX:
		return 3
	case x86asm.SPB, x86asm.SP, x86asm.ESP, x86asm.RSP:
		return 4
	case x86asm.BPB, x86asm.BP, x86asm.EBP, x86asm.RBP:
		return 5
	case x86asm.SIB, x86asm.SI, x86asm.ESI, x86asm.RSI:
		return 6
	case x86asm.DIB, x86asm.DI, x86asm.EDI, x86asm.RDI:
		return 7
	case x86asm.R8B, x86asm.R8W, x86asm.R8L, x86asm.R8:
		return 8
	case x86asm.R9B, x86asm.R9W, x86asm.R9L, x86asm.R9:
		return 9
	case x86asm.R10B, x86asm.R10W, x86asm.R10L, x86asm.R10:
		return 10
	case x86asm.R11B, x86asm.R11W, x86asm.R11L, x86asm.R11:
		return 11
	case x86asm.R12B, x86asm.R12W, x86asm.R12L, x86asm.R12:
		return 12
	case x86asm.R13B, x86asm.R13W, x86asm.R13L, x86asm.R13:
		return 13
	case x86asm.R14B, x86asm.R14W, x86asm.R14L, x86asm.R14:
		return 14
	case x86asm.R15B, x86asm.R15W, x86asm.R15L, x86asm.R15:
		return 15
	}
	return -1
}

type runtimeGroup struct {
	Begin  uint32
	End    uint32
	Leaves []RuntimeFunc
}

func buildRuntimeGroups(img *Image) []runtimeGroup {
	m := make(map[uint32]*runtimeGroup)
	for _, leaf := range img.Runtime {
		root := img.canonicalRuntimeFunction(leaf)
		g := m[root.Begin]
		if g == nil {
			g = &runtimeGroup{Begin: root.Begin, End: root.End}
			m[root.Begin] = g
		}
		g.Leaves = append(g.Leaves, leaf)
		if leaf.Begin < g.Begin {
			g.Begin = leaf.Begin
		}
		if leaf.End > g.End {
			g.End = leaf.End
		}
	}
	out := make([]runtimeGroup, 0, len(m))
	for _, g := range m {
		sort.Slice(g.Leaves, func(i, j int) bool { return g.Leaves[i].Begin < g.Leaves[j].Begin })
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Begin < out[j].Begin })
	return out
}

func decodeRuntimeGroup(img *Image, g runtimeGroup, visit func(site uint32, inst x86asm.Inst) bool) {
	for _, leaf := range g.Leaves {
		keepGoing := true
		decodeRuntimeFunction(img, leaf, func(site uint32, inst x86asm.Inst) bool {
			if !visit(site, inst) {
				keepGoing = false
				return false
			}
			return true
		})
		if !keepGoing {
			return
		}
	}
}

func groupRuntimeFunc(g runtimeGroup) RuntimeFunc {
	return RuntimeFunc{Begin: g.Begin, End: g.End}
}

func sameRegFamilyArg(a x86asm.Arg, family int) bool {
	r, ok := a.(x86asm.Reg)
	return ok && regFamily(r) == family
}

func corroborateStaticConstructObjectCandidate(img *Image, candidate uint32, progress func(int, string)) SCOProofResult {
	progress(10, "Decoding StaticConstructObject candidate parameter flow")

	root, ok := img.rootFunction(candidate)
	if !ok || root.Begin != candidate {
		return SCOProofResult{TargetRVA: candidate, Detail: fmt.Sprintf("candidate RVA 0x%X is not an exact canonical runtime-function start", candidate)}
	}

	var group runtimeGroup
	foundGroup := false
	for _, g := range buildRuntimeGroups(img) {
		if g.Begin == candidate {
			group = g
			foundGroup = true
			break
		}
	}
	if !foundGroup {
		return SCOProofResult{TargetRVA: candidate, Detail: fmt.Sprintf("candidate RVA 0x%X has no decodable runtime-function group", candidate)}
	}
	if group.End <= group.Begin || group.End-group.Begin < 0x80 || group.End-group.Begin > 0x1200 {
		return SCOProofResult{TargetRVA: candidate, Detail: fmt.Sprintf("candidate runtime-function group size 0x%X is outside the bounded StaticConstructObject range", group.End-group.Begin)}
	}

	// Track where each GPR came from. -1 means the incoming RCX parameter-pack
	// pointer, >=0 means a field loaded from that pack, and <=-100 identifies a
	// return value from a structurally matched core allocation call.
	source := map[int]int{1: -1}
	fields := make(map[int64]struct{})
	classFlags := false
	classFlagsDisp := int64(-1)
	coreCalls := 0
	lastResultMarker := -100
	returnMoveSite := uint32(0)
	paramAlias := false

	required := map[int64]bool{0x00: false, 0x08: false, 0x10: false, 0x18: false}

	clearWrittenReg := func(inst x86asm.Inst) {
		if len(inst.Args) == 0 {
			return
		}
		r, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return
		}
		f := regFamily(r)
		if f < 0 {
			return
		}
		switch inst.Op {
		case x86asm.CMP, x86asm.TEST, x86asm.PUSH, x86asm.CALL, x86asm.JMP:
			return
		}
		delete(source, f)
	}

	decodeRuntimeGroup(img, group, func(site uint32, inst x86asm.Inst) bool {
		// The UClass identity check is the long-lived SCO fingerprint. Unlike the
		// older direct-ABI implementation, newer engines first load Class from
		// params+0 and then test EClassFlags on that loaded object.
		if inst.Op == x86asm.TEST && hasImmediate(inst, 0x10000080) {
			for _, arg := range inst.Args {
				mem, ok := arg.(x86asm.Mem)
				if !ok {
					continue
				}
				bf := regFamily(mem.Base)
				if bf >= 0 {
					if src, ok := source[bf]; ok && src == 0 && mem.Disp >= 0x70 && mem.Disp <= 0x200 {
						classFlags = true
						classFlagsDisp = mem.Disp
					}
				}
			}
		}

		if inst.Op == x86asm.MOV && len(inst.Args) >= 2 {
			dst, dstOK := inst.Args[0].(x86asm.Reg)
			if dstOK {
				df := regFamily(dst)
				if df >= 0 {
					assigned := false
					if srcReg, ok := inst.Args[1].(x86asm.Reg); ok {
						sf := regFamily(srcReg)
						if v, ok := source[sf]; ok {
							source[df] = v
							assigned = true
							if v == -1 && df != 1 {
								paramAlias = true
							}
							if df == 0 && v <= -100 {
								returnMoveSite = site
							}
						}
					}
					if mem, ok := inst.Args[1].(x86asm.Mem); ok {
						bf := regFamily(mem.Base)
						if baseSrc, ok := source[bf]; ok && baseSrc == -1 && mem.Index == 0 {
							off := mem.Disp
							if off >= 0 && off <= 0x100 {
								fields[off] = struct{}{}
								if _, wanted := required[off]; wanted {
									required[off] = true
								}
								source[df] = int(off)
								assigned = true
							}
						}
					}
					if !assigned {
						delete(source, df)
					}
				}
			}
		} else if inst.Op == x86asm.CALL {
			// Immediately before a core call, newer SCO reconstructs the historical
			// StaticAllocateObject quartet from the parameter pack:
			// RCX=Class, RDX=Outer, R8=Name, R9=ObjectFlags.
			if source[1] == 0x00 && source[2] == 0x08 && source[8] == 0x10 && source[9] == 0x18 {
				coreCalls++
				lastResultMarker = -100 - coreCalls
			}
			// Windows x64 volatile GPRs are not stable across a call. Nonvolatile
			// aliases keep their provenance, which is exactly how optimized SCO
			// bodies carry the parameter-pack pointer and Class/Outer/Flags forward.
			for _, f := range []int{0, 1, 2, 8, 9, 10, 11} {
				delete(source, f)
			}
			if coreCalls > 0 {
				source[0] = lastResultMarker
			}
		} else {
			clearWrittenReg(inst)
		}
		return true
	})

	progress(78, "Scoring parameter-pack and allocation semantics")
	requiredCount := 0
	for _, hit := range required {
		if hit {
			requiredCount++
		}
	}
	extraFields := 0
	for _, off := range []int64{0x1c, 0x20, 0x21, 0x28, 0x30, 0x38, 0x40, 0x70} {
		if _, ok := fields[off]; ok {
			extraFields++
		}
	}
	returnsResult := returnMoveSite != 0 && group.End >= returnMoveSite && group.End-returnMoveSite <= 0x90

	score := 0
	if paramAlias {
		score += 2
	}
	score += requiredCount * 2
	if classFlags {
		score += 7
	}
	if classFlags && classFlagsDisp >= 0x80 && classFlagsDisp <= 0x180 {
		score++
	}
	if extraFields > 4 {
		score += 4
	} else {
		score += extraFields
	}
	if coreCalls >= 1 {
		score += 6
	}
	if coreCalls >= 2 {
		score += 2
	}
	if returnsResult {
		score += 3
	}

	passed := paramAlias && requiredCount == 4 && len(fields) >= 6 && classFlags && coreCalls >= 1 && score >= 24
	detail := fmt.Sprintf(
		"candidate 0x%X decodes as the newer StaticConstructObject parameter-pack form: params alias=%t; required field loads Class(+0), Outer(+8), Name(+0x10), ObjectFlags(+0x18)=%d/4; %d distinct pack field(s) observed (%d auxiliary construction field(s)); loaded Class is tested with EClassFlags mask 0x10000080 at class offset 0x%X; %d decoded call(s) reconstruct RCX=Class/RDX=Outer/R8=Name/R9=ObjectFlags; returned core-allocation result propagated toward function return=%t. Structural score %d. This proof uses decoded parameter/data flow rather than the AOB that nominated the target.",
		candidate, paramAlias, requiredCount, len(fields), extraFields, classFlagsDisp, coreCalls, returnsResult, score)

	progress(94, "StaticConstructObject candidate proof complete")
	return SCOProofResult{
		Passed: passed, TargetRVA: candidate, Score: score, DistinctFields: len(fields), CoreCalls: coreCalls,
		ClassFlagsDisp: classFlagsDisp, ReturnsResult: returnsResult, Detail: detail,
	}
}

func corroborateFNameConstructor(img *Image, candidate uint32, progress func(int, string)) FNameCtorProofResult {
	progress(10, "Decoding candidate constructor wrapper")

	root, ok := img.rootFunction(candidate)
	if !ok || root.Begin != candidate {
		return FNameCtorProofResult{Detail: fmt.Sprintf("candidate RVA 0x%X is not an exact canonical runtime-function start", candidate)}
	}

	var group runtimeGroup
	foundGroup := false
	for _, g := range buildRuntimeGroups(img) {
		if g.Begin == candidate {
			group = g
			foundGroup = true
			break
		}
	}
	if !foundGroup {
		return FNameCtorProofResult{Detail: fmt.Sprintf("candidate RVA 0x%X has no decodable runtime-function group", candidate)}
	}
	if group.End <= group.Begin || group.End-group.Begin > 0x180 {
		return FNameCtorProofResult{Detail: fmt.Sprintf("candidate wrapper size 0x%X is outside the bounded constructor-wrapper range", group.End-group.Begin)}
	}

	// Newer/custom builds can stage wchar parsing through a compact helper before
	// invoking the internal FName construction path. Prove that family first.
	// It is deliberately stricter than a generic "calls a wchar helper" check:
	// the outer wrapper must preserve this + incoming EFindName, the parser must
	// consume the original RDX as wchar_t, and a later call must restore exactly
	// RCX=this and R8D=the incoming EFindName. This rejects adjacent overloads
	// that share the same parser but route the enum into a different argument.
	if staged := corroborateStagedFNameConstructor(img, candidate, group); staged.Passed {
		progress(90, "FName staged wchar-constructor proof complete")
		return staged
	}

	preserveThis := false
	testName := false
	forwardFindName := false
	zeroR8 := false
	stackDefault := false
	stackBool := false
	returnThis := false
	nullZero := false
	callTargets := []uint32{}

	decodeRuntimeGroup(img, group, func(site uint32, inst x86asm.Inst) bool {
		if inst.Op == x86asm.MOV {
			if sameRegFamilyArg(inst.Args[0], 3) && sameRegFamilyArg(inst.Args[1], 1) {
				preserveThis = true
			}
			if sameRegFamilyArg(inst.Args[0], 9) && sameRegFamilyArg(inst.Args[1], 8) {
				forwardFindName = true
			}
			if sameRegFamilyArg(inst.Args[0], 0) && sameRegFamilyArg(inst.Args[1], 3) {
				returnThis = true
			}
			if m, ok := inst.Args[0].(x86asm.Mem); ok && regFamily(m.Base) == 4 {
				if m.Disp == 0x28 && (hasImmediate(inst, -1) || hasImmediate(inst, 0xffffffff)) {
					stackDefault = true
				}
				if m.Disp == 0x20 && hasImmediate(inst, 1) {
					stackBool = true
				}
			}
			if m, ok := inst.Args[0].(x86asm.Mem); ok && regFamily(m.Base) == 1 && m.Disp == 0 && sameRegFamilyArg(inst.Args[1], 0) {
				nullZero = true
			}
		}
		if inst.Op == x86asm.TEST && sameRegFamilyArg(inst.Args[0], 2) && sameRegFamilyArg(inst.Args[1], 2) {
			testName = true
		}
		if inst.Op == x86asm.XOR && sameRegFamilyArg(inst.Args[0], 8) && sameRegFamilyArg(inst.Args[1], 8) {
			zeroR8 = true
		}
		if inst.Op == x86asm.CALL {
			if t, ok := directBranchTarget(site, inst); ok {
				callTargets = append(callTargets, followJumpThunk(img, t, 4))
			}
		}
		return true
	})

	wrapperScore := 0
	if preserveThis {
		wrapperScore += 2
	}
	if testName {
		wrapperScore += 2
	}
	if forwardFindName {
		wrapperScore += 3
	}
	if zeroR8 {
		wrapperScore += 1
	}
	if stackDefault {
		wrapperScore += 1
	}
	if stackBool {
		wrapperScore += 1
	}
	if returnThis {
		wrapperScore += 2
	}
	if nullZero {
		wrapperScore += 1
	}
	if len(callTargets) == 1 {
		wrapperScore += 2
	}

	if wrapperScore < 12 || len(callTargets) != 1 {
		return FNameCtorProofResult{
			TargetRVA: candidate, WrapperScore: wrapperScore,
			Detail: fmt.Sprintf("delegating constructor wrapper proof incomplete at 0x%X: score=%d, calls=%d, preserve-this=%t, test-name=%t, forward-EFindName=%t, zero-r8=%t, stack-default=%t, stack-bool=%t, return-this=%t, null-zero=%t",
				candidate, wrapperScore, len(callTargets), preserveThis, testName, forwardFindName, zeroR8, stackDefault, stackBool, returnThis, nullZero),
		}
	}

	progress(45, "Following wrapper helper and checking wchar semantics")
	helper := callTargets[0]
	hroot, ok := img.rootFunction(helper)
	if ok {
		helper = hroot.Begin
	}

	var hgroup runtimeGroup
	foundHelper := false
	for _, g := range buildRuntimeGroups(img) {
		if g.Begin == helper {
			hgroup = g
			foundHelper = true
			break
		}
	}
	if !foundHelper {
		return FNameCtorProofResult{
			TargetRVA: candidate, HelperRVA: helper, WrapperScore: wrapperScore,
			Detail: fmt.Sprintf("constructor wrapper at 0x%X is structurally strong but helper RVA 0x%X has no runtime-function group", candidate, helper),
		}
	}

	nameRegs := map[int]bool{2: true}
	wideLoads := 0
	byteLoads := 0
	directWideRDX := false
	stepTwo := false
	asciiBoundary := false
	wordZeroTest := false
	wideDstRegs := map[int]bool{}
	decodedBytes := uint32(0)

	decodeRuntimeGroup(img, hgroup, func(site uint32, inst x86asm.Inst) bool {
		if site >= helper {
			decodedBytes = site - helper
		}
		if decodedBytes > 0x180 {
			return false
		}

		if inst.Op == x86asm.MOV {
			if dst, ok := inst.Args[0].(x86asm.Reg); ok {
				df := regFamily(dst)
				if df >= 0 {
					if src, ok := inst.Args[1].(x86asm.Reg); ok {
						sf := regFamily(src)
						if sf >= 0 && nameRegs[sf] {
							nameRegs[df] = true
						} else {
							delete(nameRegs, df)
						}
					}
				}
			}
		}
		if inst.Op == x86asm.LEA {
			if dst, ok := inst.Args[0].(x86asm.Reg); ok {
				df := regFamily(dst)
				if mem, ok := inst.Args[1].(x86asm.Mem); ok {
					bf := regFamily(mem.Base)
					if df >= 0 && bf >= 0 && nameRegs[bf] && (mem.Disp == 0 || mem.Disp == 2 || mem.Disp == -2) {
						nameRegs[df] = true
						if mem.Disp == 2 || mem.Disp == -2 {
							stepTwo = true
						}
					}
				}
			}
		}

		for _, arg := range inst.Args {
			mem, ok := arg.(x86asm.Mem)
			if !ok {
				continue
			}
			bf := regFamily(mem.Base)
			if bf < 0 || !nameRegs[bf] {
				continue
			}
			switch inst.MemBytes {
			case 2:
				wideLoads++
				if bf == 2 {
					directWideRDX = true
				}
				if dst, ok := inst.Args[0].(x86asm.Reg); ok {
					wideDstRegs[regFamily(dst)] = true
				}
			case 1:
				byteLoads++
			}
		}

		if (inst.Op == x86asm.ADD || inst.Op == x86asm.SUB) && hasImmediate(inst, 2) {
			if r, ok := inst.Args[0].(x86asm.Reg); ok && nameRegs[regFamily(r)] {
				stepTwo = true
			}
		}
		if inst.Op == x86asm.TEST || inst.Op == x86asm.CMP {
			for _, a := range inst.Args {
				if r, ok := a.(x86asm.Reg); ok && wideDstRegs[regFamily(r)] {
					if inst.Op == x86asm.TEST || hasImmediate(inst, 0) {
						wordZeroTest = true
					}
				}
			}
		}
		if inst.Op == x86asm.CMP && hasImmediate(inst, 0x7f) {
			asciiBoundary = true
		}
		return true
	})

	helperScore := 0
	if directWideRDX {
		helperScore += 5
	}
	if wideLoads >= 2 {
		helperScore += 4
	}
	if stepTwo {
		helperScore += 2
	}
	if wordZeroTest {
		helperScore += 2
	}
	if asciiBoundary {
		helperScore += 1
	}
	if byteLoads == 0 {
		helperScore += 1
	}

	passed := wrapperScore >= 12 && helperScore >= 10 && directWideRDX && wideLoads >= 2
	detail := fmt.Sprintf(
		"candidate 0x%X is a bounded delegating FName-style constructor wrapper (score %d): preserves RCX as this, null-tests RDX, forwards incoming R8D/EFindName into R9D, supplies internal defaults, returns this, and has a null-name zeroing path. Its sole decoded helper is 0x%X; within the first 0x180 bytes that helper performs %d propagated wchar_t word load(s) versus %d byte load(s), direct-RDX-wide=%t, 2-byte stepping=%t, word-zero-test=%t, ASCII-boundary=%t (helper score %d). This distinguishes the wchar constructor wrapper from sibling ANSI wrappers without relying on game RVAs or strings.",
		candidate, wrapperScore, helper, wideLoads, byteLoads, directWideRDX, stepTwo, wordZeroTest, asciiBoundary, helperScore)

	progress(90, "FName constructor structural proof complete")
	return FNameCtorProofResult{
		Passed: passed, TargetRVA: candidate, HelperRVA: helper,
		WrapperScore: wrapperScore, HelperScore: helperScore, Detail: detail,
	}
}

type wcharHelperEvidence struct {
	HelperRVA     uint32
	Score         int
	WideLoads     int
	ByteLoads     int
	DirectWideRDX bool
	StepTwo       bool
	WordZeroTest  bool
	ASCIIBoundary bool
}

func analyzeWcharNameHelper(img *Image, helper uint32) wcharHelperEvidence {
	if root, ok := img.rootFunction(helper); ok {
		helper = root.Begin
	}

	var hgroup runtimeGroup
	found := false
	for _, g := range buildRuntimeGroups(img) {
		if g.Begin == helper {
			hgroup = g
			found = true
			break
		}
	}

	nameRegs := map[int]bool{2: true}
	wideDstRegs := map[int]bool{}
	ev := wcharHelperEvidence{HelperRVA: helper}

	visit := func(site uint32, inst x86asm.Inst) bool {
		if site >= helper && site-helper > 0x180 {
			return false
		}

		if inst.Op == x86asm.MOV {
			if dst, ok := inst.Args[0].(x86asm.Reg); ok {
				df := regFamily(dst)
				if df >= 0 {
					if src, ok := inst.Args[1].(x86asm.Reg); ok && nameRegs[regFamily(src)] {
						nameRegs[df] = true
					}
				}
			}
		}
		if inst.Op == x86asm.LEA {
			if dst, ok := inst.Args[0].(x86asm.Reg); ok {
				df := regFamily(dst)
				if mem, ok := inst.Args[1].(x86asm.Mem); ok {
					bf := regFamily(mem.Base)
					if df >= 0 && bf >= 0 && nameRegs[bf] && (mem.Disp == 0 || mem.Disp == 2 || mem.Disp == -2) {
						nameRegs[df] = true
						if mem.Disp == 2 || mem.Disp == -2 {
							ev.StepTwo = true
						}
					}
				}
			}
		}

		for _, arg := range inst.Args {
			mem, ok := arg.(x86asm.Mem)
			if !ok {
				continue
			}
			bf := regFamily(mem.Base)
			if bf < 0 || !nameRegs[bf] {
				continue
			}
			switch inst.MemBytes {
			case 2:
				ev.WideLoads++
				if bf == 2 {
					ev.DirectWideRDX = true
				}
				if dst, ok := inst.Args[0].(x86asm.Reg); ok {
					wideDstRegs[regFamily(dst)] = true
				}
			case 1:
				ev.ByteLoads++
			}
		}

		if (inst.Op == x86asm.ADD || inst.Op == x86asm.SUB) && hasImmediate(inst, 2) {
			if r, ok := inst.Args[0].(x86asm.Reg); ok && nameRegs[regFamily(r)] {
				ev.StepTwo = true
			}
		}
		if inst.Op == x86asm.TEST || inst.Op == x86asm.CMP {
			for _, a := range inst.Args {
				if r, ok := a.(x86asm.Reg); ok && wideDstRegs[regFamily(r)] {
					if inst.Op == x86asm.TEST || hasImmediate(inst, 0) {
						ev.WordZeroTest = true
					}
				}
			}
		}
		if inst.Op == x86asm.CMP && hasImmediate(inst, 0x7f) {
			ev.ASCIIBoundary = true
		}
		return inst.Op != x86asm.RET
	}

	if found {
		decodeRuntimeGroup(img, hgroup, visit)
	} else {
		// Leaf helper functions do not necessarily receive unwind metadata. Decode
		// a bounded linear window from the direct CALL target and stop at RET.
		decodeLinearRVA(img, helper, 0x180, visit)
	}

	if ev.DirectWideRDX {
		ev.Score += 5
	}
	if ev.WideLoads >= 2 {
		ev.Score += 4
	}
	if ev.StepTwo {
		ev.Score += 2
	}
	if ev.WordZeroTest {
		ev.Score += 2
	}
	if ev.ASCIIBoundary {
		ev.Score += 1
	}
	if ev.ByteLoads == 0 {
		ev.Score += 1
	}
	return ev
}

func corroborateStagedFNameConstructor(img *Image, candidate uint32, group runtimeGroup) FNameCtorProofResult {
	thisAliases := map[int]bool{1: true}
	findAliases := map[int]bool{8: true}
	preserveThis := false
	preserveFind := false
	returnThis := false
	lastThisRestore := uint32(0)
	lastFindRestore := uint32(0)
	parserCall := uint32(0)
	parser := wcharHelperEvidence{}
	forwardCall := uint32(0)
	directCalls := 0
	nameRdxLive := true

	decodeRuntimeGroup(img, group, func(site uint32, inst x86asm.Inst) bool {
		if inst.Op == x86asm.MOV {
			dst, dok := inst.Args[0].(x86asm.Reg)
			src, sok := inst.Args[1].(x86asm.Reg)
			if dok && sok {
				df, sf := regFamily(dst), regFamily(src)
				if df >= 0 && sf >= 0 {
					if thisAliases[sf] {
						thisAliases[df] = true
						if df != 1 {
							preserveThis = true
						}
					}
					if findAliases[sf] {
						findAliases[df] = true
						if df != 8 {
							preserveFind = true
						}
					}
					if df == 1 && thisAliases[sf] {
						lastThisRestore = site
					}
					if df == 8 && findAliases[sf] {
						lastFindRestore = site
					}
					if df == 0 && thisAliases[sf] {
						returnThis = true
					}
				}
			}
		}

		if inst.Op == x86asm.CALL {
			t, ok := directBranchTarget(site, inst)
			if !ok {
				nameRdxLive = false
				return true
			}
			directCalls++
			t = followJumpThunk(img, t, 4)
			if parserCall == 0 && nameRdxLive && site-candidate <= 0x40 {
				ev := analyzeWcharNameHelper(img, t)
				if ev.Score >= 10 && ev.DirectWideRDX && ev.WideLoads >= 2 {
					parserCall = site
					parser = ev
				}
			}
			if parserCall != 0 && site > parserCall && lastThisRestore > parserCall && lastFindRestore > parserCall {
				latest := lastThisRestore
				if lastFindRestore > latest {
					latest = lastFindRestore
				}
				if site-latest <= 0x20 {
					forwardCall = site
				}
			}
			// A CALL clobbers volatile RDX. No later helper can be claimed to consume
			// the original incoming name pointer unless the wrapper explicitly reloads it.
			nameRdxLive = false
		}

		if parserCall == 0 && nameRdxLive && inst.Op != x86asm.CMP && inst.Op != x86asm.TEST {
			if dst, ok := inst.Args[0].(x86asm.Reg); ok && regFamily(dst) == 2 {
				nameRdxLive = false
			}
		}
		return true
	})

	score := 0
	if preserveThis {
		score += 2
	}
	if preserveFind {
		score += 3
	}
	if parserCall != 0 {
		score += 4
	}
	if parser.Score >= 10 {
		score += 5
	}
	if parser.StepTwo && parser.WordZeroTest {
		score += 2
	}
	if forwardCall != 0 {
		score += 6
	}
	if returnThis {
		score += 2
	}

	passed := preserveThis && preserveFind && parserCall != 0 && parser.Score >= 10 && parser.DirectWideRDX && parser.WideLoads >= 2 && forwardCall != 0 && returnThis && score >= 20
	detail := fmt.Sprintf(
		"candidate 0x%X is a staged FName(wchar_t const*, EFindName) wrapper (score %d): preserves this=%t and incoming EFindName=%t; early parser CALL at 0x%X -> helper 0x%X consumes the original incoming RDX as wchar_t (%d wide load(s), %d byte load(s), 2-byte stepping=%t, word-zero-test=%t, helper score=%d); a later CALL at 0x%X is preceded by restoring RCX=this and R8D=incoming EFindName; returns this=%t. This distinguishes the public wchar constructor from adjacent overloads that share the same parser but route EFindName through a different argument slot. Direct calls observed=%d.",
		candidate, score, preserveThis, preserveFind, parserCall, parser.HelperRVA, parser.WideLoads, parser.ByteLoads, parser.StepTwo, parser.WordZeroTest, parser.Score, forwardCall, returnThis, directCalls)

	return FNameCtorProofResult{
		Passed: passed, TargetRVA: candidate, HelperRVA: parser.HelperRVA,
		WrapperScore: score, HelperScore: parser.Score, Detail: detail,
	}
}

type legacyGNamesCandidate struct {
	GlobalRVA uint32
	Getter    RuntimeFunc
	Score     int
	Loads     int
	Stores    int
	Detail    string
}

func findLegacyGNames(img *Image, progress func(int, string)) (legacyGNamesCandidate, int, int) {
	progress(12, "Locating pre-4.23 GNames lazy-singleton getters")
	cands := []legacyGNamesCandidate{}
	groups := buildRuntimeGroups(img)

	for i, g := range groups {
		if len(groups) > 0 && i%2500 == 0 {
			p := 12 + int(float64(i)/float64(len(groups))*23.0)
			progress(p, "Decoding old GNames getter candidates")
		}
		if g.End <= g.Begin || g.End-g.Begin > 0x380 {
			continue
		}

		type refCounts struct{ loads, stores int }
		refs := make(map[uint32]*refCounts)
		hasAllocSize := false
		hasBackingSize := false
		hasTest := false
		callCount := 0
		decodeRuntimeGroup(img, g, func(site uint32, inst x86asm.Inst) bool {
			if hasImmediate(inst, 0x408) || hasImmediate(inst, 0x808) {
				hasAllocSize = true
			}
			if hasImmediate(inst, 0x400) || hasImmediate(inst, 0x800) {
				hasBackingSize = true
			}
			if inst.Op == x86asm.TEST {
				hasTest = true
			}
			if inst.Op == x86asm.CALL {
				callCount++
			}
			if inst.Op != x86asm.MOV {
				return true
			}
			if mem, ok := inst.Args[1].(x86asm.Mem); ok {
				if target, ok := ripMemTarget(site, inst, mem); ok && img.nonExecutableImageRVA(target) {
					c := refs[target]
					if c == nil {
						c = &refCounts{}
						refs[target] = c
					}
					c.loads++
				}
			}
			if mem, ok := inst.Args[0].(x86asm.Mem); ok {
				if target, ok := ripMemTarget(site, inst, mem); ok && img.nonExecutableImageRVA(target) {
					c := refs[target]
					if c == nil {
						c = &refCounts{}
						refs[target] = c
					}
					c.stores++
				}
			}
			return true
		})

		if !hasAllocSize {
			continue
		}
		for target, rc := range refs {
			if rc.loads == 0 || rc.stores == 0 {
				continue
			}
			score := 2 + 3 + 4
			if hasBackingSize {
				score += 2
			}
			if hasTest {
				score++
			}
			if callCount >= 1 {
				score++
			}
			cands = append(cands, legacyGNamesCandidate{
				GlobalRVA: target, Getter: groupRuntimeFunc(g), Score: score, Loads: rc.loads, Stores: rc.stores,
				Detail: fmt.Sprintf("lazy singleton getter 0x%X loads/stores writable RVA 0x%X (%d/%d), has 0x408/0x808 allocation size, backing-size=%t, pointer-test=%t",
					g.Begin, target, rc.loads, rc.stores, hasBackingSize, hasTest),
			})
		}
	}

	if len(cands) == 0 {
		return legacyGNamesCandidate{}, 0, 0
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Score > cands[j].Score })
	runner := 0
	if len(cands) > 1 {
		runner = cands[1].Score
	}
	return cands[0], runner, len(cands)
}

type fnameConsumerScore struct {
	Fn            RuntimeFunc
	GetterCallRVA uint32
	Score         int
	Detail        string
}

func scoreLegacyFNameConsumer(img *Image, g runtimeGroup, getter uint32) fnameConsumerScore {
	thisRegs := map[int]bool{1: true} // RCX
	outRegs := map[int]bool{2: true}  // RDX
	preserveThis := false
	preserveOut := false
	comparisonRead := false
	numberRead := false
	hasMask3FFF := false
	hasShift14 := false
	hasUnderscore := false
	hasNumberMinusOne := false
	scale8Reads := 0
	callCount := 0
	getterCall := uint32(0)

	decodeRuntimeGroup(img, g, func(site uint32, inst x86asm.Inst) bool {
		if target, ok := directBranchTarget(site, inst); ok && inst.Op == x86asm.CALL {
			callCount++
			final := followJumpThunk(img, target, 4)
			if tf, ok := img.rootFunction(final); ok {
				final = tf.Begin
			}
			if final == getter {
				getterCall = site
			}
		}

		if inst.Op == x86asm.MOV {
			if dst, ok := inst.Args[0].(x86asm.Reg); ok {
				df := regFamily(dst)
				if df >= 0 {
					if src, ok := inst.Args[1].(x86asm.Reg); ok {
						sf := regFamily(src)
						if sf >= 0 && thisRegs[sf] {
							thisRegs[df] = true
							if sf == 1 && df != 1 {
								preserveThis = true
							}
						} else {
							delete(thisRegs, df)
						}
						if sf >= 0 && outRegs[sf] {
							outRegs[df] = true
							if sf == 2 && df != 2 {
								preserveOut = true
							}
						} else {
							delete(outRegs, df)
						}
					} else {
						delete(thisRegs, df)
						delete(outRegs, df)
					}
				}
			}
			if mem, ok := inst.Args[1].(x86asm.Mem); ok {
				bf := regFamily(mem.Base)
				if bf >= 0 && thisRegs[bf] {
					switch mem.Disp {
					case 0:
						comparisonRead = true
					case 4:
						numberRead = true
					}
				}
				if mem.Scale == 8 {
					scale8Reads++
				}
			}
		}

		if inst.Op == x86asm.AND && hasImmediate(inst, 0x3fff) {
			hasMask3FFF = true
		}
		if (inst.Op == x86asm.SAR || inst.Op == x86asm.SHR) && hasImmediate(inst, 0xe) {
			hasShift14 = true
		}
		if inst.Op == x86asm.MOV && hasImmediate(inst, 0x5f) {
			if _, ok := inst.Args[0].(x86asm.Mem); ok {
				hasUnderscore = true
			}
		}
		if inst.Op == x86asm.DEC || (inst.Op == x86asm.SUB && hasImmediate(inst, 1)) {
			hasNumberMinusOne = true
		}
		return true
	})

	if getterCall == 0 {
		return fnameConsumerScore{Fn: groupRuntimeFunc(g)}
	}
	score := 2
	if preserveThis {
		score++
	}
	if preserveOut {
		score += 2
	}
	if comparisonRead {
		score += 2
	}
	if numberRead {
		score += 3
	}
	if hasMask3FFF {
		score += 3
	}
	if hasShift14 {
		score += 3
	}
	if hasUnderscore {
		score += 4
	}
	if hasNumberMinusOne {
		score += 2
	}
	if scale8Reads >= 2 {
		score += 2
	}
	if callCount >= 2 {
		score++
	}
	detail := fmt.Sprintf("getter-call=yes, FName-this-preserved=%t, FString-out-preserved=%t, ComparisonIndex(+0)=%t, Number(+4)=%t, mask-0x3FFF=%t, shift-14=%t, underscore-append=%t, Number-1=%t, scale8-index-reads=%d, calls=%d",
		preserveThis, preserveOut, comparisonRead, numberRead, hasMask3FFF, hasShift14, hasUnderscore, hasNumberMinusOne, scale8Reads, callCount)
	return fnameConsumerScore{Fn: groupRuntimeFunc(g), GetterCallRVA: getterCall, Score: score, Detail: detail}
}

func resolveLegacyFName(img *Image, progress func(int, string)) LegacyFNameResult {
	if len(img.Runtime) == 0 {
		return LegacyFNameResult{Detail: "no Win64 runtime-function metadata available"}
	}
	gnames, gRunner, gCount := findLegacyGNames(img, progress)
	if gnames.Score < 10 || (gCount > 1 && gnames.Score <= gRunner) {
		return LegacyFNameResult{Score: gnames.Score, RunnerUp: gRunner, Candidates: gCount,
			Detail: fmt.Sprintf("pre-4.23 GNames semantic getter was not decisive (best=%d runner-up=%d candidates=%d)", gnames.Score, gRunner, gCount)}
	}

	progress(38, fmt.Sprintf("GNames RVA 0x%X found; tracing decoded callers of getter 0x%X", gnames.GlobalRVA, gnames.Getter.Begin))
	candidates := []fnameConsumerScore{}
	groups := buildRuntimeGroups(img)
	for i, g := range groups {
		if i%2500 == 0 {
			p := 38 + int(float64(i)/float64(len(groups))*48.0)
			progress(p, "Scoring decoded GNames-getter callers for FName::ToString semantics")
		}
		if g.End <= g.Begin || g.End-g.Begin > 0x900 {
			continue
		}
		sc := scoreLegacyFNameConsumer(img, g, gnames.Getter.Begin)
		if sc.GetterCallRVA != 0 && sc.Score > 0 {
			candidates = append(candidates, sc)
		}
	}
	if len(candidates) == 0 {
		return LegacyFNameResult{GNamesRVA: gnames.GlobalRVA, GetterRVA: gnames.Getter.Begin,
			Detail: gnames.Detail + "; no decoded caller of the getter had FName::ToString semantics"}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	best := candidates[0]
	runner := 0
	if len(candidates) > 1 {
		runner = candidates[1].Score
	}
	// Require the old FName chunk math plus Number/output behavior. The threshold
	// intentionally leaves generic GNames consumers far below a positive result.
	if best.Score < 17 || (runner > 0 && best.Score < runner+3) {
		return LegacyFNameResult{GNamesRVA: gnames.GlobalRVA, GetterRVA: gnames.Getter.Begin,
			Score: best.Score, RunnerUp: runner, Candidates: len(candidates),
			Detail: fmt.Sprintf("%s; ToString consumer ranking was not decisive: best 0x%X score=%d, runner-up=%d across %d getter callers; %s",
				gnames.Detail, best.Fn.Begin, best.Score, runner, len(candidates), best.Detail)}
	}
	progress(92, "Legacy FName::ToString semantic identity converged")
	return LegacyFNameResult{Found: true, GNamesRVA: gnames.GlobalRVA, GetterRVA: gnames.Getter.Begin,
		TargetRVA: best.Fn.Begin, Score: best.Score, RunnerUp: runner, Candidates: len(candidates),
		Detail: fmt.Sprintf("%s; unique old-FName consumer 0x%X scored %d vs runner-up %d across %d getter callers: %s",
			gnames.Detail, best.Fn.Begin, best.Score, runner, len(candidates), best.Detail)}
}

type guCtorScore struct {
	Fn     RuntimeFunc
	Score  int
	Detail string
}

func scoreGUObjectConstructor(img *Image, g runtimeGroup) guCtorScore {
	// Track aliases of the incoming RCX this pointer, including LEA aliases with
	// a fixed field displacement. Track registers proven zero by XOR reg,reg so
	// compiler-selected zero registers do not make the shape brittle.
	thisOff := map[int]int64{1: 0}
	zeroRegs := make(map[int]bool)
	zeroFields := make(map[int64]bool)
	minusOne4 := false
	oneC := false
	thousandB0 := false
	callCount := 0

	decodeRuntimeGroup(img, g, func(site uint32, inst x86asm.Inst) bool {
		_ = site
		if inst.Op == x86asm.CALL {
			callCount++
		}
		if inst.Op == x86asm.XOR {
			a, aok := inst.Args[0].(x86asm.Reg)
			b, bok := inst.Args[1].(x86asm.Reg)
			if aok && bok && regFamily(a) >= 0 && regFamily(a) == regFamily(b) {
				zeroRegs[regFamily(a)] = true
			}
		}
		if inst.Op == x86asm.MOV {
			if dst, ok := inst.Args[0].(x86asm.Reg); ok {
				if src, ok := inst.Args[1].(x86asm.Reg); ok {
					df, sf := regFamily(dst), regFamily(src)
					if off, exists := thisOff[sf]; exists && df >= 0 {
						thisOff[df] = off
					}
					if zeroRegs[sf] && df >= 0 {
						zeroRegs[df] = true
					}
				}
			}
			if mem, ok := inst.Args[0].(x86asm.Mem); ok {
				bf := regFamily(mem.Base)
				baseOff, exists := thisOff[bf]
				if exists {
					off := baseOff + mem.Disp
					switch src := inst.Args[1].(type) {
					case x86asm.Reg:
						if zeroRegs[regFamily(src)] {
							zeroFields[off] = true
						}
					case x86asm.Imm:
						v := int64(src)
						if v == 0 {
							zeroFields[off] = true
						}
						if off == 4 && (v == -1 || uint64(v)&0xffffffff == 0xffffffff) {
							minusOne4 = true
						}
						if off == 0xC && v == 1 {
							oneC = true
						}
						if off == 0xB0 && v == 0x3E8 {
							thousandB0 = true
						}
					}
				}
			}
		}
		if inst.Op == x86asm.LEA {
			dst, dok := inst.Args[0].(x86asm.Reg)
			mem, mok := inst.Args[1].(x86asm.Mem)
			if dok && mok {
				df, bf := regFamily(dst), regFamily(mem.Base)
				if off, exists := thisOff[bf]; exists && df >= 0 && mem.Index == 0 {
					thisOff[df] = off + mem.Disp
				}
			}
		}
		return true
	})

	score := 0
	for _, off := range []int64{0, 8, 0x10, 0x18} {
		if zeroFields[off] {
			score += 2
		}
	}
	if minusOne4 {
		score += 4
	}
	if oneC {
		score += 3
	}
	extraZeros := 0
	for _, off := range []int64{0x48, 0x50, 0x58, 0x60, 0x64, 0x68, 0x70, 0x78, 0x80} {
		if zeroFields[off] {
			extraZeros++
		}
	}
	if extraZeros > 4 {
		extraZeros = 4
	}
	score += extraZeros
	if thousandB0 {
		score += 2
	}
	if callCount >= 2 {
		score++
	}
	detail := fmt.Sprintf("ctor defaults: +0=%t +4=-1=%t +8=%t +0xC=1=%t +0x10=%t +0x18=%t, later-zero-fields=%d, +0xB0=1000=%t, calls=%d",
		zeroFields[0], minusOne4, zeroFields[8], oneC, zeroFields[0x10], zeroFields[0x18], extraZeros, thousandB0, callCount)
	return guCtorScore{Fn: groupRuntimeFunc(g), Score: score, Detail: detail}
}

func discoverGUObjectArrayStructure(img *Image, progress func(int, string)) GUObjectProofResult {
	if len(img.Runtime) == 0 {
		return GUObjectProofResult{Detail: "no Win64 runtime-function metadata available"}
	}
	groups := buildRuntimeGroups(img)
	groupByBegin := make(map[uint32]runtimeGroup, len(groups))
	progress(12, "Scoring runtime functions for old FUObjectArray constructor layout")
	type ctorCandidate struct {
		g  runtimeGroup
		sc guCtorScore
	}
	ctors := []ctorCandidate{}
	for i, g := range groups {
		groupByBegin[g.Begin] = g
		if i%2500 == 0 {
			p := 12 + int(float64(i)/float64(len(groups))*38.0)
			progress(p, "Decoding constructor-layout candidates")
		}
		if g.End <= g.Begin || g.End-g.Begin > 0x900 {
			continue
		}
		sc := scoreGUObjectConstructor(img, g)
		if sc.Score >= 15 {
			ctors = append(ctors, ctorCandidate{g: g, sc: sc})
		}
	}
	if len(ctors) == 0 {
		return GUObjectProofResult{Detail: "no runtime function reached the conservative old-FUObjectArray constructor-layout threshold"}
	}
	sort.Slice(ctors, func(i, j int) bool { return ctors[i].sc.Score > ctors[j].sc.Score })
	ctorScores := make(map[uint32]int)
	for _, c := range ctors {
		ctorScores[c.g.Begin] = c.sc.Score
	}

	progress(54, fmt.Sprintf("%d constructor-shaped function(s) found; tracing callers and singleton globals", len(ctors)))
	type proof struct {
		target, ctor, call, lea uint32
		score                   int
		detail                  string
	}
	proofs := []proof{}
	for i, g := range groups {
		if i%2500 == 0 {
			p := 54 + int(float64(i)/float64(len(groups))*34.0)
			progress(p, "Tracing LEA RCX singleton callsites into constructor candidates")
		}
		var leaSite, leaTarget uint32
		decodeRuntimeGroup(img, g, func(site uint32, inst x86asm.Inst) bool {
			if inst.Op == x86asm.LEA {
				dst, dok := inst.Args[0].(x86asm.Reg)
				mem, mok := inst.Args[1].(x86asm.Mem)
				if dok && mok && regFamily(dst) == 1 {
					if target, ok := ripMemTarget(site, inst, mem); ok && img.nonExecutableImageRVA(target) {
						leaSite, leaTarget = site, target
					}
				}
				return true
			}
			if leaSite != 0 && site > leaSite && site-leaSite <= 0x30 && inst.Op == x86asm.CALL {
				target, ok := directBranchTarget(site, inst)
				if !ok {
					return true
				}
				final := followJumpThunk(img, target, 4)
				tf, ok := img.rootFunction(final)
				if !ok {
					return true
				}
				if score, wanted := ctorScores[tf.Begin]; wanted {
					cg := groupByBegin[tf.Begin]
					sc := scoreGUObjectConstructor(img, cg)
					proofs = append(proofs, proof{target: leaTarget, ctor: tf.Begin, call: site, lea: leaSite, score: score, detail: sc.Detail})
				}
				leaSite, leaTarget = 0, 0
				return true
			}
			if leaSite != 0 && site > leaSite+0x30 {
				leaSite, leaTarget = 0, 0
			}
			return true
		})
	}
	if len(proofs) == 0 {
		return GUObjectProofResult{Candidates: len(ctors), Detail: fmt.Sprintf("%d constructor-shaped function(s) existed, but none had a decoded LEA RCX,writable-global -> CALL singleton path", len(ctors))}
	}
	// Collapse duplicate callsites onto the same global and favor the strongest
	// constructor evidence. Multiple callsites to the same target add support,
	// but cannot rescue a weak constructor shape.
	type targetAgg struct {
		best    proof
		support int
	}
	agg := make(map[uint32]*targetAgg)
	for _, p := range proofs {
		a := agg[p.target]
		if a == nil {
			a = &targetAgg{best: p}
			agg[p.target] = a
		}
		a.support++
		if p.score > a.best.score {
			a.best = p
		}
	}
	targets := make([]*targetAgg, 0, len(agg))
	for _, a := range agg {
		targets = append(targets, a)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].best.score != targets[j].best.score {
			return targets[i].best.score > targets[j].best.score
		}
		return targets[i].support > targets[j].support
	})
	best := targets[0]
	runner := 0
	if len(targets) > 1 {
		runner = targets[1].best.score
	}
	if best.best.score < 18 || (runner > 0 && best.best.score < runner+3) {
		return GUObjectProofResult{TargetRVA: best.best.target, CtorRVA: best.best.ctor, CallRVA: best.best.call, LeaRVA: best.best.lea,
			Score: best.best.score, RunnerUp: runner, Candidates: len(targets),
			Detail: fmt.Sprintf("global constructor discovery was not decisive: best target 0x%X via ctor 0x%X score=%d support=%d, runner-up score=%d across %d global candidate(s); %s",
				best.best.target, best.best.ctor, best.best.score, best.support, runner, len(targets), best.best.detail)}
	}
	progress(94, "String-independent GUObjectArray singleton discovery converged")
	return GUObjectProofResult{Passed: true, TargetRVA: best.best.target, CtorRVA: best.best.ctor, CallRVA: best.best.call, LeaRVA: best.best.lea,
		Score: best.best.score, RunnerUp: runner, Candidates: len(targets),
		Detail: fmt.Sprintf("string-independent singleton discovery selected writable RVA 0x%X from LEA RCX 0x%X -> CALL 0x%X -> constructor 0x%X; ctor score=%d, support=%d, runner-up score=%d across %d global candidate(s); %s",
			best.best.target, best.best.lea, best.best.call, best.best.ctor, best.best.score, best.support, runner, len(targets), best.best.detail)}
}

func corroborateGUObjectArrayStructure(img *Image, candidate uint32, progress func(int, string)) GUObjectProofResult {
	if !img.nonExecutableImageRVA(candidate) {
		return GUObjectProofResult{TargetRVA: candidate, Detail: fmt.Sprintf("candidate RVA 0x%X is not inside a non-executable mapped image section", candidate)}
	}
	progress(18, fmt.Sprintf("Tracing decoded LEA RCX references to candidate 0x%X", candidate))
	type proof struct {
		ctor guCtorScore
		call uint32
		lea  uint32
	}
	proofs := []proof{}
	seenCtor := make(map[uint32]struct{})

	groups := buildRuntimeGroups(img)
	groupByBegin := make(map[uint32]runtimeGroup, len(groups))
	for _, g := range groups {
		groupByBegin[g.Begin] = g
	}
	for i, g := range groups {
		if i%2500 == 0 {
			p := 18 + int(float64(i)/float64(len(groups))*55.0)
			progress(p, "Finding candidate-global constructor callsites")
		}
		var leaSite uint32
		decodeRuntimeGroup(img, g, func(site uint32, inst x86asm.Inst) bool {
			if inst.Op == x86asm.LEA {
				dst, dok := inst.Args[0].(x86asm.Reg)
				mem, mok := inst.Args[1].(x86asm.Mem)
				if dok && mok && regFamily(dst) == 1 {
					if target, ok := ripMemTarget(site, inst, mem); ok && target == candidate {
						leaSite = site
					}
				}
				return true
			}
			if leaSite != 0 && site > leaSite && site-leaSite <= 0x30 && inst.Op == x86asm.CALL {
				target, ok := directBranchTarget(site, inst)
				if !ok {
					return true
				}
				final := followJumpThunk(img, target, 4)
				tf, ok := img.rootFunction(final)
				if !ok {
					return true
				}
				tg, ok := groupByBegin[tf.Begin]
				if !ok {
					return true
				}
				if _, seen := seenCtor[tg.Begin]; seen {
					leaSite = 0
					return true
				}
				seenCtor[tg.Begin] = struct{}{}
				sc := scoreGUObjectConstructor(img, tg)
				if sc.Score > 0 {
					proofs = append(proofs, proof{ctor: sc, call: site, lea: leaSite})
				}
				leaSite = 0
				return true
			}
			if leaSite != 0 && site > leaSite+0x30 {
				leaSite = 0
			}
			return true
		})
	}

	if len(proofs) == 0 {
		return GUObjectProofResult{TargetRVA: candidate, Detail: fmt.Sprintf("no decoded LEA RCX -> CALL path from candidate RVA 0x%X reached a constructor-shaped function", candidate)}
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].ctor.Score > proofs[j].ctor.Score })
	best := proofs[0]
	runner := 0
	if len(proofs) > 1 {
		runner = proofs[1].ctor.Score
	}
	if best.ctor.Score < 15 || (runner > 0 && best.ctor.Score < runner+3) {
		return GUObjectProofResult{TargetRVA: candidate, CtorRVA: best.ctor.Fn.Begin, CallRVA: best.call,
			Score: best.ctor.Score, RunnerUp: runner, Candidates: len(proofs),
			Detail: fmt.Sprintf("candidate constructor corroboration was not decisive: best ctor 0x%X score=%d runner-up=%d candidates=%d; %s",
				best.ctor.Fn.Begin, best.ctor.Score, runner, len(proofs), best.ctor.Detail)}
	}
	progress(92, "GUObjectArray constructor-layout corroboration converged")
	return GUObjectProofResult{Passed: true, TargetRVA: candidate, CtorRVA: best.ctor.Fn.Begin, CallRVA: best.call, LeaRVA: best.lea,
		Score: best.ctor.Score, RunnerUp: runner, Candidates: len(proofs),
		Detail: fmt.Sprintf("independent LEA RCX at 0x%X materializes candidate RVA 0x%X, CALL 0x%X reaches constructor-shaped function 0x%X scoring %d vs runner-up %d; %s",
			best.lea, candidate, best.call, best.ctor.Fn.Begin, best.ctor.Score, runner, best.ctor.Detail)}
}

// ---------------- Native semantic StaticConstructObject resolver ----------------

func writeSemanticProgress(path string, percent int, stage string) {
	if path == "" {
		return
	}
	stage = strings.ReplaceAll(stage, "\t", " ")
	stage = strings.ReplaceAll(stage, "\r", " ")
	stage = strings.ReplaceAll(stage, "\n", " ")
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, []byte(fmt.Sprintf("SEM\t%d\t%s\n", percent, stage)), 0644)
	_ = os.Rename(tmp, path)
}

func writeSCOResult(path string, r SCOResult) error {
	status := "NOT_FOUND"
	target := "-"
	call := "-"
	opcode := "-"
	if r.Found {
		status = "FOUND"
		target = fmt.Sprintf("%X", r.TargetRVA)
		if r.CallRVA != 0 {
			call = fmt.Sprintf("%X", r.CallRVA)
			opcode = fmt.Sprintf("%02X", r.CallOpcode)
		}
	}
	detail := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(r.Detail)
	return os.WriteFile(path, []byte(fmt.Sprintf("SCO\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", status, target, call, opcode, r.Support, r.RunnerUp, detail)), 0644)
}

func writeSCOProofResult(path string, r SCOProofResult) error {
	status := "NOT_PROVED"
	target := "-"
	if r.Passed {
		status = "PROVED"
		target = fmt.Sprintf("%X", r.TargetRVA)
	}
	detail := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(r.Detail)
	return os.WriteFile(path, []byte(fmt.Sprintf("SCOPROOF\t%s\t%s\t%d\t%d\t%d\t%d\t%t\t%s\n",
		status, target, r.Score, r.DistinctFields, r.CoreCalls, r.ClassFlagsDisp, r.ReturnsResult, detail)), 0644)
}

func utf16LE(s string, includeNull bool) []byte {
	rs := []rune(s)
	enc := utf16.Encode(rs)
	if includeNull {
		enc = append(enc, 0)
	}
	out := make([]byte, 0, len(enc)*2)
	for _, u := range enc {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func findBytesRVAs(img *Image, needle []byte, max int) []uint32 {
	if len(needle) == 0 {
		return nil
	}
	out := []uint32{}
	for _, s := range img.Sections {
		start, end := int(s.Raw), int(s.Raw+s.Size)
		if start < 0 || end > len(img.Data) || start >= end {
			continue
		}
		sec := img.Data[start:end]
		pos := 0
		for pos < len(sec) && len(out) < max {
			idx := bytes.Index(sec[pos:], needle)
			if idx < 0 {
				break
			}
			raw := start + pos + idx
			rva := s.RVA + uint32(raw-start)
			out = append(out, rva)
			pos += idx + 1
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

func findAbsoluteRefs(img *Image, va uint64, max int) []uint32 {
	var needle [8]byte
	binary.LittleEndian.PutUint64(needle[:], va)
	return findBytesRVAs(img, needle[:], max)
}

func findLEAXrefs(img *Image, targets map[uint32]struct{}, max int) []uint32 {
	// Fast target-driven RIP-relative LEA scanner. The previous implementation
	// searched for broad 48/4C 8D prefixes and then invoked the full x86 decoder
	// for every occurrence across .text. On very large Shipping binaries that can
	// mean millions of needless decodes before we discover the handful of string
	// XREFs we actually care about. A Win64 RIP-relative LEA has a compact,
	// invariant encoding here: REX.W + 8D + ModRM(mod=00,r/m=101) + disp32.
	// Decode the disp32 directly, and only keep instructions whose computed target
	// is already in the requested set. This preserves the same semantic evidence
	// while making the cost one cheap linear pass over executable sections.
	out := []uint32{}
	seen := make(map[uint32]struct{})
	if len(targets) == 0 || max <= 0 {
		return out
	}
	for _, secInfo := range img.Sections {
		if !secInfo.Exec || secInfo.Size < 7 {
			continue
		}
		start, end := int(secInfo.Raw), int(secInfo.Raw+secInfo.Size)
		if start < 0 || end > len(img.Data) || start >= end {
			continue
		}
		sec := img.Data[start:end]
		for at := 0; at+7 <= len(sec) && len(out) < max; {
			rel := bytes.IndexByte(sec[at:], 0x8D)
			if rel < 0 {
				break
			}
			op := at + rel
			if op > 0 && op+5 < len(sec) {
				rex := sec[op-1]
				modrm := sec[op+1]
				// REX.W must be set. For RIP-relative addressing ModRM is mod=00,
				// r/m=101. REX.R may vary with the destination register; REX.B is
				// ignored by RIP-relative addressing but accepting the full 0x48-0x4F
				// range keeps this scanner compiler-agnostic.
				if rex >= 0x48 && rex <= 0x4F && modrm&0xC7 == 0x05 {
					site := secInfo.RVA + uint32(op-1)
					disp := int32(binary.LittleEndian.Uint32(sec[op+2 : op+6]))
					target64 := int64(site) + 7 + int64(disp)
					if target64 >= 0 && target64 <= 0xFFFFFFFF {
						target := uint32(target64)
						if _, wanted := targets[target]; wanted {
							if _, dup := seen[site]; !dup {
								seen[site] = struct{}{}
								out = append(out, site)
							}
						}
					}
				}
			}
			at = op + 1
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

func rootsForStringRVAs(img *Image, stringRVAs []uint32) map[uint32]RuntimeFunc {
	targetSet := make(map[uint32]struct{})
	for _, rva := range stringRVAs {
		targetSet[rva] = struct{}{}
		if rva <= ^uint32(0)-2 {
			targetSet[rva+2] = struct{}{}
		}
		for _, t := range []uint32{rva, rva + 2} {
			for _, ptrRVA := range findAbsoluteRefs(img, img.ImageBase+uint64(t), 512) {
				targetSet[ptrRVA] = struct{}{}
				if ptrRVA <= ^uint32(0)-2 {
					targetSet[ptrRVA+2] = struct{}{}
				}
			}
		}
	}
	roots := make(map[uint32]RuntimeFunc)
	for _, ref := range findLEAXrefs(img, targetSet, 8192) {
		if fn, ok := img.rootFunction(ref); ok {
			roots[fn.Begin] = fn
		}
	}
	return roots
}

func findMagicFunctions(img *Image) map[uint32]RuntimeFunc {
	needle := []byte{0x80, 0x00, 0x00, 0x10}
	out := make(map[uint32]RuntimeFunc)
	checked := make(map[uint32]bool)
	for _, secInfo := range img.Sections {
		if !secInfo.Exec || secInfo.Size < 4 {
			continue
		}
		start, end := int(secInfo.Raw), int(secInfo.Raw+secInfo.Size)
		if start < 0 || end > len(img.Data) || start >= end {
			continue
		}
		sec := img.Data[start:end]
		pos := 0
		for pos+4 <= len(sec) {
			idx := bytes.Index(sec[pos:], needle)
			if idx < 0 {
				break
			}
			at := pos + idx
			rva := secInfo.RVA + uint32(at)
			if leaf, ok := img.functionContaining(rva); ok {
				root := img.canonicalRuntimeFunction(leaf)
				if _, seen := checked[root.Begin]; !seen {
					good := false
					decodeRuntimeFunction(img, leaf, func(_ uint32, inst x86asm.Inst) bool {
						for _, arg := range inst.Args {
							if imm, ok := arg.(x86asm.Imm); ok && uint64(int64(imm))&0xFFFFFFFF == 0x10000080 {
								good = true
								return false
							}
						}
						return true
					})
					checked[root.Begin] = good
				}
				if checked[root.Begin] {
					out[root.Begin] = root
				}
			}
			pos = at + 1
		}
	}
	return out
}

func buildSemanticIndex(img *Image, progress func(int, string)) {
	if img.Semantic != nil {
		return
	}
	idx := &SemanticIndex{
		LeaByTarget: make(map[uint32][]uint32),
		Outgoing:    make(map[uint32][]Edge),
		Inbound:     make(map[uint32][]Edge),
	}

	progress(8, "Indexing RIP-relative LEA xrefs")
	for _, secInfo := range img.Sections {
		if !secInfo.Exec || secInfo.Size < 7 {
			continue
		}
		start, end := int(secInfo.Raw), int(secInfo.Raw+secInfo.Size)
		if start < 0 || end > len(img.Data) || start >= end {
			continue
		}
		sec := img.Data[start:end]
		pos := 1
		for pos+6 < len(sec) {
			rel := bytes.IndexByte(sec[pos:], 0x8D)
			if rel < 0 {
				break
			}
			at := pos + rel
			if at > 0 && at+6 < len(sec) {
				rex := sec[at-1]
				modrm := sec[at+1]
				if (rex == 0x48 || rex == 0x4C) && modrm&0xC7 == 0x05 {
					disp := int32(binary.LittleEndian.Uint32(sec[at+2 : at+6]))
					site := secInfo.RVA + uint32(at-1)
					target64 := int64(site) + 7 + int64(disp)
					if target64 >= 0 && target64 <= 0xFFFFFFFF {
						target := uint32(target64)
						idx.LeaByTarget[target] = append(idx.LeaByTarget[target], site)
					}
				}
			}
			pos = at + 1
		}
	}

	progress(15, "Indexing native CALL/JMP graph")
	for _, secInfo := range img.Sections {
		if !secInfo.Exec || secInfo.Size < 5 {
			continue
		}
		start, end := int(secInfo.Raw), int(secInfo.Raw+secInfo.Size)
		if start < 0 || end > len(img.Data) || start >= end {
			continue
		}
		for _, opcode := range []byte{0xE8, 0xE9} {
			pos := start
			for pos+5 <= end {
				rel := bytes.IndexByte(img.Data[pos:end], opcode)
				if rel < 0 {
					break
				}
				raw := pos + rel
				site, ok := img.rawToRVA(raw)
				if ok && raw+5 <= len(img.Data) {
					disp := int32(binary.LittleEndian.Uint32(img.Data[raw+1 : raw+5]))
					target64 := int64(site) + 5 + int64(disp)
					if target64 >= 0 && target64 <= 0xFFFFFFFF {
						direct := uint32(target64)
						if img.executableRVA(direct) {
							final := followJumpThunk(img, direct, 4)
							if targetFn, ok := img.rootFunction(final); ok {
								final = targetFn.Begin
								if caller, ok := img.rootFunction(site); ok && caller.Begin != final {
									e := Edge{Site: site, Target: final, DirectTarget: direct, Opcode: opcode, Caller: caller}
									idx.Outgoing[caller.Begin] = append(idx.Outgoing[caller.Begin], e)
									idx.Inbound[final] = append(idx.Inbound[final], e)
								}
							}
						}
					}
				}
				pos = raw + 1
			}
		}
	}

	img.Semantic = idx
}

func outgoingEdges(img *Image, fn RuntimeFunc, max int) []Edge {
	out := []Edge{}
	decodeRuntimeFunction(img, fn, func(site uint32, inst x86asm.Inst) bool {
		if len(out) >= max {
			return false
		}
		if inst.Op != x86asm.CALL && inst.Op != x86asm.JMP {
			return true
		}
		rel, ok := inst.Args[0].(x86asm.Rel)
		if !ok {
			return true
		}
		target64 := int64(site) + int64(inst.Len) + int64(rel)
		if target64 < 0 || target64 > 0xFFFFFFFF {
			return true
		}
		direct := uint32(target64)
		if !img.executableRVA(direct) {
			return true
		}
		final := followJumpThunk(img, direct, 4)
		if tf, ok := img.rootFunction(final); ok {
			final = tf.Begin
			if final != fn.Begin {
				opcode := byte(0xE9)
				if inst.Op == x86asm.CALL {
					opcode = 0xE8
				}
				out = append(out, Edge{Site: site, Target: final, DirectTarget: direct, Opcode: opcode, Caller: fn})
			}
		}
		return true
	})
	return out
}

func followJumpThunk(img *Image, rva uint32, depth int) uint32 {
	current := rva
	seen := make(map[uint32]struct{})
	for i := 0; i < depth; i++ {
		if _, ok := seen[current]; ok {
			break
		}
		seen[current] = struct{}{}
		raw, ok := img.rvaToRaw(current)
		if !ok || raw >= len(img.Data) {
			break
		}
		inst, err := x86asm.Decode(img.Data[raw:], 64)
		if err != nil || inst.Len <= 0 || inst.Op != x86asm.JMP {
			break
		}
		var next uint32
		has := false
		switch arg := inst.Args[0].(type) {
		case x86asm.Rel:
			t := int64(current) + int64(inst.Len) + int64(arg)
			if t >= 0 && t <= 0xFFFFFFFF {
				next, has = uint32(t), true
			}
		case x86asm.Mem:
			if arg.Base == x86asm.RIP {
				ptrRVA64 := int64(current) + int64(inst.Len) + arg.Disp
				if ptrRVA64 >= 0 && ptrRVA64 <= 0xFFFFFFFF {
					if ptrRaw, ok := img.rvaToRaw(uint32(ptrRVA64)); ok && ptrRaw+8 <= len(img.Data) {
						va := binary.LittleEndian.Uint64(img.Data[ptrRaw : ptrRaw+8])
						if va >= img.ImageBase && va-img.ImageBase <= 0xFFFFFFFF {
							next, has = uint32(va-img.ImageBase), true
						}
					}
				}
			}
		}
		if !has || !img.executableRVA(next) {
			break
		}
		current = next
	}
	return current
}

func inboundEdges(img *Image, targets map[uint32]struct{}, max int) []Edge {
	out := []Edge{}
	for _, secInfo := range img.Sections {
		if !secInfo.Exec || secInfo.Size < 5 {
			continue
		}
		start, end := int(secInfo.Raw), int(secInfo.Raw+secInfo.Size)
		if start < 0 || end > len(img.Data) || start >= end {
			continue
		}
		for _, opcode := range []byte{0xE8, 0xE9} {
			pos := start
			for pos+5 <= end && len(out) < max {
				idx := bytes.IndexByte(img.Data[pos:end], opcode)
				if idx < 0 {
					break
				}
				raw := pos + idx
				site, ok := img.rawToRVA(raw)
				if ok {
					disp := int32(binary.LittleEndian.Uint32(img.Data[raw+1 : raw+5]))
					target64 := int64(site) + 5 + int64(disp)
					if target64 >= 0 && target64 <= 0xFFFFFFFF {
						direct := uint32(target64)
						final := followJumpThunk(img, direct, 4)
						if tf, ok := img.rootFunction(final); ok {
							final = tf.Begin
						}
						if _, wanted := targets[final]; wanted {
							if inst, valid := decodedInstructionAt(img, site); valid {
								isCall := opcode == 0xE8 && inst.Op == x86asm.CALL
								isJmp := opcode == 0xE9 && inst.Op == x86asm.JMP
								rel, relOK := inst.Args[0].(x86asm.Rel)
								if (isCall || isJmp) && relOK {
									actual := int64(site) + int64(inst.Len) + int64(rel)
									if actual == int64(direct) {
										if caller, ok := img.rootFunction(site); ok {
											out = append(out, Edge{Site: site, Target: final, DirectTarget: direct, Opcode: opcode, Caller: caller})
										}
									}
								}
							}
						}
					}
				}
				pos = raw + 1
			}
			if len(out) >= max {
				break
			}
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

func callerFunctionsForTargets(img *Image, fns map[uint32]RuntimeFunc) map[uint32]RuntimeFunc {
	targets := make(map[uint32]struct{}, len(fns))
	for begin := range fns {
		targets[begin] = struct{}{}
	}
	out := make(map[uint32]RuntimeFunc)
	for _, e := range inboundEdges(img, targets, 16384) {
		out[e.Caller.Begin] = e.Caller
	}
	return out
}

func functionIsOrCallsRoot(img *Image, fn RuntimeFunc, roots map[uint32]RuntimeFunc) bool {
	if _, ok := roots[fn.Begin]; ok {
		return true
	}
	for _, e := range outgoingEdges(img, fn, 1024) {
		t := followJumpThunk(img, e.Target, 4)
		if tf, ok := img.rootFunction(t); ok {
			if _, ok := roots[tf.Begin]; ok {
				return true
			}
		}
	}
	return false
}

func findNewObjectFromClassRoots(img *Image, classRoots, newRoots map[uint32]RuntimeFunc) (RuntimeFunc, bool) {
	if len(classRoots) == 0 || len(newRoots) == 0 {
		return RuntimeFunc{}, false
	}
	current := classRoots
	for depth := 0; depth < 3; depth++ {
		for _, fn := range current {
			if functionIsOrCallsRoot(img, fn, newRoots) {
				return fn, true
			}
		}
		if depth < 2 {
			current = callerFunctionsForTargets(img, current)
			if len(current) == 0 {
				break
			}
		}
	}
	return RuntimeFunc{}, false
}

type scoreEvidence struct {
	score    map[uint32]int
	callSite map[uint32]uint32
	callOp   map[uint32]byte
}

func scoreFromRoots(img *Image, roots map[uint32]RuntimeFunc, magic map[uint32]RuntimeFunc) scoreEvidence {
	ev := scoreEvidence{score: make(map[uint32]int), callSite: make(map[uint32]uint32), callOp: make(map[uint32]byte)}
	for _, root := range roots {
		// PatternSleuth evaluates each NewObject-root function independently.
		// Earlier versions shared this helper-visited set across every root, which
		// accidentally suppressed repeated independent evidence when several
		// NewObject wrappers reached SCO through the same helper. Keep it per root.
		visited := make(map[uint32]struct{})
		for _, e := range outgoingEdges(img, root, 2048) {
			target := followJumpThunk(img, e.Target, 4)
			if _, ok := magic[target]; ok {
				ev.score[target]++
				if e.Opcode == 0xE8 && e.DirectTarget == target {
					ev.callSite[target] = e.Site
					ev.callOp[target] = e.Opcode
				}
			}
			fn2, ok := img.rootFunction(target)
			if !ok {
				continue
			}
			if _, seen := visited[fn2.Begin]; seen {
				continue
			}
			visited[fn2.Begin] = struct{}{}
			for _, inner := range outgoingEdges(img, fn2, 2048) {
				t2 := followJumpThunk(img, inner.Target, 4)
				if _, ok := magic[t2]; ok {
					ev.score[t2]++
					if inner.Opcode == 0xE8 && inner.DirectTarget == t2 {
						ev.callSite[t2] = inner.Site
						ev.callOp[t2] = inner.Opcode
					}
				}
			}
		}
	}
	return ev
}

func topScores(scores map[uint32]int) (target uint32, top, second int) {
	for k, v := range scores {
		if v > top {
			second = top
			top = v
			target = k
		} else if v > second {
			second = v
		}
	}
	return
}

func resolveSCO(img *Image, progress func(int, string)) SCOResult {
	if len(img.Runtime) == 0 {
		return SCOResult{Detail: "No Win64 runtime-function metadata was available from the PE exception directory or .pdata fallback."}
	}

	// IMPORTANT: do NOT build a whole-image CALL/JMP graph here. v0.15 proved
	// that byte-sniffing every E8/E9 in a 600+ MB Shipping executable and then
	// resolving function ownership for each candidate explodes into minutes of
	// work. PatternSleuth works in the opposite direction: start from a concrete
	// string/function target, then scan only for xrefs/calls that can reach that
	// target. Keep img.Semantic nil so findLEAXrefs/inboundEdges use their
	// targeted native scan paths.
	progress(8, "Using bounded target-driven XREF analysis")

	progress(16, "Locating NewObject semantic anchors")
	newText := "NewObject with empty name can't be used to create default"
	newRVAs := findBytesRVAs(img, utf16LE(newText, false), 128)
	if len(newRVAs) == 0 {
		newRVAs = findBytesRVAs(img, utf16LE(newText, true), 128)
	}
	newRoots := rootsForStringRVAs(img, newRVAs)

	progress(28, "Indexing StaticConstructObject RF-flags candidates")
	magic := findMagicFunctions(img)
	if len(magic) == 0 {
		return SCOResult{Detail: fmt.Sprintf("runtime=%s; NewObject roots=%d; no runtime functions containing 0x10000080 were found.", img.RuntimeSource, len(newRoots))}
	}

	progress(38, "Resolving class-name anchor functions")
	classRoots := make(map[uint32]RuntimeFunc)
	anchorsFound := 0
	for _, name := range []string{"UBehaviorTreeManager", "ULeaderboardFlushCallbackProxy", "UPlayMontageCallbackProxy"} {
		rvas := findBytesRVAs(img, utf16LE(name, true), 128)
		if len(rvas) == 0 {
			rvas = findBytesRVAs(img, utf16LE(name, false), 128)
		}
		if len(rvas) > 0 {
			anchorsFound++
		}
		for begin, fn := range rootsForStringRVAs(img, rvas) {
			classRoots[begin] = fn
		}
	}

	detailBase := fmt.Sprintf("native semantic evidence: runtime=%s; NewObject roots=%d, RF-flags candidates=%d, class anchors=%d/3, class-root functions=%d", img.RuntimeSource, len(newRoots), len(magic), anchorsFound, len(classRoots))

	// If neither semantic anchor family mapped back into executable runtime
	// functions, caller climbing cannot possibly add identity evidence. Do not
	// launch broad inbound scans just to rediscover that the graph is empty. A
	// unique RF-flags body can still be preserved below as STRONG.
	if len(newRoots) == 0 && len(classRoots) == 0 && len(magic) != 1 {
		progress(97, "No executable semantic roots; failing fast")
		return SCOResult{Detail: detailBase + "; no NewObject/class anchor XREF mapped to a runtime function, so deep graph analysis was skipped"}
	}

	progress(52, "Walking class-anchor callers toward NewObject")
	if newFn, ok := findNewObjectFromClassRoots(img, classRoots, newRoots); ok {
		roots := map[uint32]RuntimeFunc{newFn.Begin: newFn}
		ev := scoreFromRoots(img, roots, magic)
		target, top, second := topScores(ev.score)
		if top > 0 && (len(ev.score) == 1 || (top >= 2 && top >= second*2)) {
			return SCOResult{Found: true, TargetRVA: target, CallRVA: ev.callSite[target], CallOpcode: ev.callOp[target], Support: top, RunnerUp: second, Detail: detailBase + "; phase1 NewObject wrapper -> RF-flags target"}
		}
	}

	// Preserve the phase-2 winner even when our stricter confidence policy does
	// not immediately accept it. PatternSleuth itself resolves this phase by
	// choosing the maximum-supported RF-flags target. Our AHK layer can keep a
	// non-decisive maximum at STRONG while still benefiting from that evidence.
	var phase2Target, phase2Call uint32
	var phase2Op byte
	phase2Top, phase2Second := 0, 0
	phase2Candidates := 0

	progress(66, "Running NewObject empty-name consensus")
	if len(newRoots) > 0 {
		ev := scoreFromRoots(img, newRoots, magic)
		phase2Candidates = len(ev.score)
		phase2Target, phase2Top, phase2Second = topScores(ev.score)
		phase2Call = ev.callSite[phase2Target]
		phase2Op = ev.callOp[phase2Target]
		if phase2Top > 0 && (len(ev.score) == 1 || (phase2Top >= 2 && phase2Top >= phase2Second*2)) {
			return SCOResult{Found: true, TargetRVA: phase2Target, CallRVA: phase2Call, CallOpcode: phase2Op, Support: phase2Top, RunnerUp: phase2Second, Detail: detailBase + "; phase2 empty-name consensus -> RF-flags target"}
		}
	}

	progress(80, "Running bounded reverse RF-flags evidence")
	magicTargets := make(map[uint32]struct{}, len(magic))
	for begin := range magic {
		magicTargets[begin] = struct{}{}
	}
	first := inboundEdges(img, magicTargets, 32768)
	scores := make(map[uint32]int)
	callSite := make(map[uint32]uint32)
	callOp := make(map[uint32]byte)
	helperTargets := make(map[uint32]map[uint32]struct{})
	helperFns := make(map[uint32]RuntimeFunc)

	for _, e := range first {
		if helperTargets[e.Caller.Begin] == nil {
			helperTargets[e.Caller.Begin] = make(map[uint32]struct{})
		}
		helperTargets[e.Caller.Begin][e.Target] = struct{}{}
		helperFns[e.Caller.Begin] = e.Caller
		weight := 0
		if _, ok := newRoots[e.Caller.Begin]; ok {
			weight += 6
		}
		if _, ok := classRoots[e.Caller.Begin]; ok {
			weight += 2
		}
		if weight > 0 {
			scores[e.Target] += weight
			if e.Opcode == 0xE8 {
				callSite[e.Target] = e.Site
				callOp[e.Target] = e.Opcode
			}
		}
	}

	progress(90, "Checking one helper layer above RF-flags candidates")
	helperSet := make(map[uint32]struct{}, len(helperFns))
	for begin := range helperFns {
		helperSet[begin] = struct{}{}
	}
	secondEdges := inboundEdges(img, helperSet, 32768)
	for _, e := range secondEdges {
		targets := helperTargets[e.Target]
		if len(targets) == 0 {
			continue
		}
		weight := 0
		if _, ok := newRoots[e.Caller.Begin]; ok {
			weight += 4
		}
		if _, ok := classRoots[e.Caller.Begin]; ok {
			weight += 1
		}
		if weight == 0 {
			continue
		}
		for target := range targets {
			scores[target] += weight
		}
	}

	target, top, runner := topScores(scores)
	if top > 0 && (len(scores) == 1 || (top >= 4 && top >= runner*2)) {
		return SCOResult{Found: true, TargetRVA: target, CallRVA: callSite[target], CallOpcode: callOp[target], Support: top, RunnerUp: runner, Detail: detailBase + "; reverse RF-flags evidence converged"}
	}

	// PatternSleuth's PE phase-2 implementation chooses the maximum-supported
	// candidate rather than requiring our extra 2x runner-up margin. If there is
	// a unique leader, preserve it as a lower-confidence candidate. AHK will keep
	// the result STRONG unless another independent identity proof exists. This is
	// especially useful on optimized builds where byte-level call discovery adds
	// a small amount of noise around otherwise-correct NewObject evidence.
	if phase2Top > 0 && phase2Top > phase2Second {
		return SCOResult{Found: true, TargetRVA: phase2Target, CallRVA: phase2Call, CallOpcode: phase2Op, Support: phase2Top, RunnerUp: phase2Second, Detail: fmt.Sprintf("%s; patternsleuth-max-only: phase2 maximum RF-flags target retained at support %d vs %d across %d candidate(s)", detailBase, phase2Top, phase2Second, phase2Candidates)}
	}

	// Last-resort structural candidate: PatternSleuth uses the 0x10000080 RF-flags
	// immediate as a defining SCO body check. If exactly ONE runtime function in
	// the executable contains it, preserve that candidate instead of discarding all
	// evidence merely because string/call-graph convergence failed. Keep this path
	// target-driven: v0.16 intentionally leaves img.Semantic nil, so never dereference
	// a whole-image semantic index here. Ask the bounded inbound scanner only for
	// this one target.
	if len(magic) == 1 {
		for target := range magic {
			var site uint32
			var op byte
			targets := map[uint32]struct{}{target: {}}
			for _, edge := range inboundEdges(img, targets, 256) {
				if edge.Opcode == 0xE8 {
					site, op = edge.Site, edge.Opcode
					break
				}
			}
			return SCOResult{Found: true, TargetRVA: target, CallRVA: site, CallOpcode: op, Support: 1, RunnerUp: 0, Detail: detailBase + "; magic-singleton-only: exactly one runtime function contains the 0x10000080 RF-flags fingerprint, but NewObject graph convergence was unavailable"}
		}
	}

	progress(97, "Semantic SCO evidence exhausted")
	return SCOResult{Detail: fmt.Sprintf("%s; no decisive target. phase3 inbound edges=%d, scores=%d", detailBase, len(first), len(scores)), Support: top, RunnerUp: runner}
}

// outlinedGUFamily captures one independently identified UObject subsystem path.
// Modern PGO/LTO builds can outline diagnostics into tiny cold functions while
// the hot Allocate/Free/Shutdown bodies directly access FUObjectArray fields as
// RIP-relative globals. This family follows the diagnostic back to the hot caller
// and reconstructs the struct base from the field-offset constellation instead of
// assuming the nearest LEA RCX is &GUObjectArray (it may be an internal lock).
type outlinedGUFamily struct {
	Name   string
	Bodies []runtimeGroup
}

type outlinedGUBaseScore struct {
	Base     uint32
	Score    int
	Offsets  map[uint32]struct{}
	Sites    map[uint32]uint32
	Families map[string]struct{}
	Body     uint32
}

func dedupeU32(in []uint32) []uint32 {
	seen := make(map[uint32]struct{})
	out := make([]uint32, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func semanticStringRootsBoth(img *Image, text string) map[uint32]RuntimeFunc {
	rvas := []uint32{}
	rvas = append(rvas, findBytesRVAs(img, []byte(text), 128)...)
	rvas = append(rvas, findBytesRVAs(img, append([]byte(text), 0), 128)...)
	rvas = append(rvas, findBytesRVAs(img, utf16LE(text, false), 128)...)
	rvas = append(rvas, findBytesRVAs(img, utf16LE(text, true), 128)...)
	return rootsForStringRVAs(img, dedupeU32(rvas))
}

func outlinedBodiesFromRoots(img *Image, roots map[uint32]RuntimeFunc, groupByBegin map[uint32]runtimeGroup) []runtimeGroup {
	seen := make(map[uint32]struct{})
	out := []runtimeGroup{}
	targets := make(map[uint32]struct{})
	for _, fn := range roots {
		targets[fn.Begin] = struct{}{}
		if g, ok := groupByBegin[fn.Begin]; ok {
			if g.End-g.Begin >= 0x180 {
				seen[g.Begin] = struct{}{}
				out = append(out, g)
			}
		}
	}
	// PGO/LTO often outlines only the fatal/logging path. One inbound decoded CALL
	// lands us back in the hot body that owns the FUObjectArray field accesses.
	for _, e := range inboundEdges(img, targets, 4096) {
		if e.Opcode != 0xE8 {
			continue
		}
		if g, ok := groupByBegin[e.Caller.Begin]; ok {
			if _, dup := seen[g.Begin]; !dup {
				seen[g.Begin] = struct{}{}
				out = append(out, g)
			}
		}
	}
	return out
}

func ripDataRefsForGroup(img *Image, g runtimeGroup) map[uint32][]uint32 {
	refs := make(map[uint32][]uint32)
	decodeRuntimeGroup(img, g, func(site uint32, inst x86asm.Inst) bool {
		for _, arg := range inst.Args {
			mem, ok := arg.(x86asm.Mem)
			if !ok {
				continue
			}
			target, ok := ripMemTarget(site, inst, mem)
			if !ok || !img.nonExecutableImageRVA(target) {
				continue
			}
			refs[target] = append(refs[target], site)
		}
		return true
	})
	return refs
}

func scoreOutlinedBases(img *Image, family string, g runtimeGroup) []outlinedGUBaseScore {
	refs := ripDataRefsForGroup(img, g)
	// Core UE4/UE5 FUObjectArray offsets. The tail listener/free-index offsets vary
	// a little by branch, so they contribute evidence but are not mandatory.
	offsets := []uint32{0x00, 0x04, 0x08, 0x0C, 0x10, 0x18, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x58, 0x60, 0x64, 0x68, 0x70, 0x74}
	candidates := make(map[uint32]*outlinedGUBaseScore)
	for target, sites := range refs {
		for _, off := range offsets {
			if target < off {
				continue
			}
			base := target - off
			if base&0xF != 0 || !img.nonExecutableImageRVA(base) {
				continue
			}
			c := candidates[base]
			if c == nil {
				c = &outlinedGUBaseScore{Base: base, Offsets: make(map[uint32]struct{}), Sites: make(map[uint32]uint32), Families: make(map[string]struct{}), Body: g.Begin}
				candidates[base] = c
			}
			c.Offsets[off] = struct{}{}
			if _, ok := c.Sites[off]; !ok && len(sites) > 0 {
				c.Sites[off] = sites[0]
			}
		}
	}
	out := []outlinedGUBaseScore{}
	for _, c := range candidates {
		_, has10 := c.Offsets[0x10]
		_, has24 := c.Offsets[0x24]
		coreCount := 0
		for _, o := range []uint32{0x00, 0x04, 0x08, 0x0C} {
			if _, ok := c.Offsets[o]; ok {
				coreCount++
			}
		}
		if !has10 || !has24 || coreCount < 1 {
			continue
		}
		score := 10 // both +0x10 object chunks and +0x24 max-elements are strong anchors
		score += coreCount * 3
		for _, o := range []uint32{0x18, 0x20, 0x28, 0x2C, 0x30} {
			if _, ok := c.Offsets[o]; ok {
				score += 2
			}
		}
		for _, o := range []uint32{0x58, 0x60, 0x64, 0x68, 0x70, 0x74} {
			if _, ok := c.Offsets[o]; ok {
				score++
			}
		}
		c.Score = score
		c.Families[family] = struct{}{}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func simpleRIPRefForBase(img *Image, g runtimeGroup, base uint32, preferred []uint32) (uint32, uint32, bool) {
	wanted := make(map[uint32]uint32)
	for _, off := range preferred {
		wanted[base+off] = off
	}
	var siteOut, offOut uint32
	found := false
	decodeRuntimeGroup(img, g, func(site uint32, inst x86asm.Inst) bool {
		if found {
			return false
		}
		if inst.Len != 7 {
			return true
		}
		raw, ok := img.rvaToRaw(site)
		if !ok || raw+7 > len(img.Data) {
			return true
		}
		rex, op, modrm := img.Data[raw], img.Data[raw+1], img.Data[raw+2]
		if rex < 0x48 || rex > 0x4F || (op != 0x8B && op != 0x8D && op != 0x89) || modrm&0xC7 != 0x05 {
			return true
		}
		disp := int32(binary.LittleEndian.Uint32(img.Data[raw+3 : raw+7]))
		t64 := int64(site) + 7 + int64(disp)
		if t64 < 0 || t64 > 0xFFFFFFFF {
			return true
		}
		if off, ok := wanted[uint32(t64)]; ok {
			siteOut, offOut, found = site, off, true
			return false
		}
		return true
	})
	return siteOut, offOut, found
}

func discoverGUObjectArrayOutlined(img *Image, progress func(int, string)) GUObjectProofResult {
	if len(img.Runtime) == 0 {
		return GUObjectProofResult{Detail: "no Win64 runtime-function metadata available"}
	}
	progress(8, "Locating UObject diagnostic anchors")
	groups := buildRuntimeGroups(img)
	groupByBegin := make(map[uint32]runtimeGroup, len(groups))
	for _, g := range groups {
		groupByBegin[g.Begin] = g
	}

	familyDefs := []struct {
		name  string
		texts []string
	}{
		{"AllocateUObjectIndex", []string{"Unable to add more objects to disregard for GC pool (Max: %d)"}},
		{"FreeUObjectIndex", []string{"Removing object (0x%016llx) at index %d but the index points to a different object (0x%016llx)!", "Unexpected concurency while adding new object"}},
		{"UObjectBaseShutdown", []string{"All UObject delete listeners should be unregistered when shutting down the UObject array"}},
	}
	families := []outlinedGUFamily{}
	for _, fd := range familyDefs {
		roots := make(map[uint32]RuntimeFunc)
		for _, text := range fd.texts {
			for k, v := range semanticStringRootsBoth(img, text) {
				roots[k] = v
			}
		}
		bodies := outlinedBodiesFromRoots(img, roots, groupByBegin)
		if len(bodies) > 0 {
			families = append(families, outlinedGUFamily{Name: fd.name, Bodies: bodies})
		}
	}
	if len(families) == 0 {
		return GUObjectProofResult{Detail: "Allocate/Free/Shutdown diagnostics were absent or had no decoded hot callers"}
	}
	progress(28, "Reconstructing FUObjectArray bases from RIP-relative field clusters")

	type agg struct {
		best   outlinedGUBaseScore
		total  int
		fam    map[string]struct{}
		bodies map[uint32]runtimeGroup
	}
	aggs := make(map[uint32]*agg)
	familyBodyCandidates := 0
	for _, fam := range families {
		famBest := make(map[uint32]outlinedGUBaseScore)
		for _, g := range fam.Bodies {
			scored := scoreOutlinedBases(img, fam.Name, g)
			familyBodyCandidates += len(scored)
			for _, sc := range scored {
				if old, ok := famBest[sc.Base]; !ok || sc.Score > old.Score {
					famBest[sc.Base] = sc
				}
			}
		}
		for base, sc := range famBest {
			a := aggs[base]
			if a == nil {
				a = &agg{best: sc, fam: make(map[string]struct{}), bodies: make(map[uint32]runtimeGroup)}
				aggs[base] = a
			}
			a.total += sc.Score
			a.fam[fam.Name] = struct{}{}
			if sc.Score > a.best.Score {
				a.best = sc
			}
			if g, ok := groupByBegin[sc.Body]; ok {
				a.bodies[g.Begin] = g
			}
		}
	}
	if len(aggs) == 0 {
		return GUObjectProofResult{Candidates: familyBodyCandidates, Detail: "UObject semantic bodies were found, but no aligned writable base exhibited the required +0x10/+0x24 FUObjectArray field constellation"}
	}
	type ranked struct {
		base  uint32
		a     *agg
		score int
	}
	ranks := []ranked{}
	for base, a := range aggs {
		score := a.total + len(a.fam)*8
		ranks = append(ranks, ranked{base: base, a: a, score: score})
	}
	sort.Slice(ranks, func(i, j int) bool { return ranks[i].score > ranks[j].score })
	best := ranks[0]
	runner := 0
	if len(ranks) > 1 {
		runner = ranks[1].score
	}
	if len(best.a.fam) < 2 || best.score < 30 || (runner > 0 && best.score < runner+8) {
		return GUObjectProofResult{TargetRVA: best.base, Score: best.score, RunnerUp: runner, Candidates: len(ranks), ProofKinds: len(best.a.fam), Detail: fmt.Sprintf("outlined/LTO FUObjectArray field clustering was not decisive: best base 0x%X score=%d families=%d runner-up=%d across %d candidate base(s)", best.base, best.score, len(best.a.fam), runner, len(ranks))}
	}
	progress(72, "Selecting relocatable FUObjectArray field reference")
	var refSite, fieldOff, body uint32
	okRef := false
	preferred := []uint32{0x10, 0x24, 0x0C, 0x04, 0x08, 0x30, 0x60, 0x68}
	for _, g := range best.a.bodies {
		if s, o, ok := simpleRIPRefForBase(img, g, best.base, preferred); ok {
			refSite, fieldOff, body, okRef = s, o, g.Begin, true
			break
		}
	}
	if !okRef {
		return GUObjectProofResult{TargetRVA: best.base, Score: best.score, RunnerUp: runner, Candidates: len(ranks), ProofKinds: len(best.a.fam), Detail: fmt.Sprintf("field clustering converged on 0x%X but no simple relocatable RIP-relative field reference was available", best.base)}
	}
	famNames := []string{}
	for n := range best.a.fam {
		famNames = append(famNames, n)
	}
	sort.Strings(famNames)
	offs := []uint32{}
	for o := range best.a.best.Offsets {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	offText := []string{}
	for _, o := range offs {
		offText = append(offText, fmt.Sprintf("+0x%X", o))
	}
	detail := fmt.Sprintf("outlined/LTO UObject semantics converged on FUObjectArray base 0x%X from %d independent family/families (%s), score=%d vs runner-up=%d. A representative hot body at 0x%X exhibits the UE4/UE5 field constellation %s. Relocatable proof site 0x%X references base+0x%X, so generated resolver subtracts 0x%X. This avoids mistaking an internal synchronization object (commonly +0x30) for the struct base.", best.base, len(best.a.fam), strings.Join(famNames, ","), best.score, runner, body, strings.Join(offText, ","), refSite, fieldOff, fieldOff)
	progress(94, "Outlined/LTO FUObjectArray discovery converged")
	return GUObjectProofResult{Passed: true, TargetRVA: best.base, CtorRVA: body, LeaRVA: refSite, Score: best.score, RunnerUp: runner, Candidates: len(ranks), Detail: detail, Adjustment: -int32(fieldOff), ProofKinds: len(best.a.fam)}
}

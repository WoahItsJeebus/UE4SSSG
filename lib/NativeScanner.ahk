; NativeScanner.ahk
; Optional zero-setup native acceleration layer.
;
; Development/raw .ahk mode:
;   Uses bin\ScannerCore.exe beside the project.
;
; Compiled mode:
;   FileInstall embeds ScannerCore.exe into the compiled AHK executable and this
;   layer extracts it silently to %TEMP% at runtime. The end user still launches
;   only the main UE4SS Signature Generator executable.
;
; The native helper pre-scans static resolver AOB families, performs dynamic AOB
; uniqueness checks, and handles the expensive StaticConstructObject semantic
; layer. AHK remains the UI/orchestrator and retains compatibility fallbacks.

global NativeScannerPid := 0

global NativeScannerActive := false

EnsureNativeScanner() {
    global APP_VERSION

    if !A_IsCompiled {
        devPath := A_ScriptDir "\bin\ScannerCore.exe"
        return FileExist(devPath) ? devPath : ""
    }

    outDir := A_Temp "\UE4SSSignatureGenerator"
    DirCreate(outDir)
    outPath := outDir "\ScannerCore-" APP_VERSION ".exe"

    try {
        ; Literal source path is intentional: Ahk2Exe embeds this file into the
        ; compiled main executable. No Rust/Go/Python/runtime installation is
        ; needed on the user's machine.
        FileInstall "bin\ScannerCore.exe", outPath, 1
    } catch {
        return ""
    }
    return FileExist(outPath) ? outPath : ""
}

CollectNativeStaticPatterns(localCorpus) {
    global ResolverDB

    patterns := []
    seen := Map()
    for resolver in ResolverDB {
        activeResolver := MergeResolverWithExistingCorpus(resolver, localCorpus)
        for entry in activeResolver.Patterns {
            patternText := IsObject(entry) ? entry.Pattern : entry
            normalized := RegExReplace(Trim(patternText), "\s+", " ")
            if normalized = "" || seen.Has(normalized)
                continue
            seen[normalized] := true
            patterns.Push(normalized)
        }
    }

    ; Supplemental structural families are consumed by specialized resolver
    ; layers rather than ResolveTargetGeneric, but pre-scan them in the same
    ; native batch so the fallback remains effectively free on huge EXEs.
    for patternText in [
        "8B 05 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 2B 05 ?? ?? ?? ??",
        "48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? B9 08 04 00 00",
        "48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? B9 08 08 00 00"
    ] {
        normalized := RegExReplace(Trim(patternText), "\s+", " ")
        if !seen.Has(normalized) {
            seen[normalized] := true
            patterns.Push(normalized)
        }
    }
    return patterns
}

PrimeNativePatternCache(pe, localCorpus, progressStart := 3.2, progressSpan := 1.7) {
    global NativeScannerPid, NativeScannerActive, ScanCancelled

    helper := EnsureNativeScanner()
    if helper = ""
        return {Available: false, Detail: "ScannerCore.exe is unavailable; using the AHK scanner."}

    patterns := CollectNativeStaticPatterns(localCorpus)
    if patterns.Length = 0
        return {Available: false, Detail: "No static resolver patterns were available for native pre-scan."}

    token := DllCall("GetCurrentProcessId", "UInt") "-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    manifest := workDir "\patterns.tsv"
    output := workDir "\results.tsv"
    progress := workDir "\progress.tsv"

    idToPattern := Map()
    f := FileOpen(manifest, "w", "UTF-8-RAW")
    if !IsObject(f)
        return {Available: false, Detail: "Unable to create native scanner manifest."}
    for index, patternText in patterns {
        idToPattern[index] := patternText
        f.Write(index "`t" patternText "`n")
    }
    f.Close()

    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --manifest " q manifest q
        . " --out " q output q
        . " --progress " q progress q
        . " --max-matches 256"

    SetScanProgress(progressStart, "Native core: pre-scanning resolver pattern families...")
    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Available: false, Detail: "Unable to launch ScannerCore.exe: " err.Message}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastDone := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }

        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                parts := StrSplit(txt, "`t")
                if parts.Length >= 2 {
                    done := parts[1] + 0
                    total := Max(1, parts[2] + 0)
                    if done != lastDone {
                        lastDone := done
                        frac := Min(1.0, done / total)
                        SetScanProgress(progressStart + frac * progressSpan,
                            "Native core: pre-scanning resolver families (" done "/" total ")...")
                    }
                }
            }
        }
        Sleep(25)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)

    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {Available: false, Detail: "ScannerCore exited without producing a result cache; using the AHK scanner."}
    }

    cache := Map()
    try {
        text := FileRead(output, "UTF-8")
        for line in StrSplit(StrReplace(text, "`r", ""), "`n") {
            if line = ""
                continue
            cols := StrSplit(line, "`t")
            if cols.Length < 3 || cols[1] != "RESULT"
                continue
            id := cols[2] + 0
            if !idToPattern.Has(id)
                continue
            key := idToPattern[id]
            hits := []
            Loop Max(0, cols.Length - 3) {
                field := cols[A_Index + 3]
                bits := StrSplit(field, ",")
                if bits.Length < 3
                    continue
                raw := ("0x" bits[1]) + 0
                rva := ("0x" bits[2]) + 0
                sectionName := bits[3]
                hits.Push({Raw: raw, RVA: rva, Section: sectionName})
            }
            cache[key] := hits
        }
        pe.NativePatternCache := cache
    } catch as err {
        try DirDelete(workDir, true)
        return {Available: false, Detail: "ScannerCore result parsing failed: " err.Message "; using the AHK scanner."}
    }

    try DirDelete(workDir, true)
    SetScanProgress(progressStart + progressSpan, "Native core pattern cache ready")
    return {
        Available: true,
        PatternCount: patterns.Length,
        CachedCount: cache.Count,
        Detail: "ScannerCore pre-scanned " patterns.Length " static pattern families in one native batch."
    }
}

StopNativeScanner() {
    global NativeScannerPid, NativeScannerActive
    pid := NativeScannerPid
    if pid && ProcessExist(pid) {
        try ProcessClose(pid)
        ; ProcessClose is synchronous at the API boundary, but give Windows a
        ; brief chance to finish tearing the helper down before the scan thread
        ; resumes and starts cleanup of its temporary files.
        try ProcessWaitClose(pid, 0.5)
    }
    NativeScannerPid := 0
    NativeScannerActive := false
}

NativeCachedScan(pe, parsed, maxMatches) {
    if !HasProp(pe, "NativePatternCache") || !pe.NativePatternCache.Has(parsed.CacheKey)
        return ""

    cached := pe.NativePatternCache[parsed.CacheKey]
    out := []
    limit := Min(maxMatches, cached.Length)
    Loop limit
        out.Push(cached[A_Index])
    return out
}

; Run one dynamically generated AOB through ScannerCore. This is used for
; uniqueness checks created after a resolver has already discovered a target.
; It keeps large-executable uniqueness scans out of the AHK interpreter.
NativeAdHocPatternScan(pe, patternText, maxMatches := 8) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    if !HasProp(pe, "NativeAdHocCache")
        pe.NativeAdHocCache := Map()
    key := RegExReplace(Trim(patternText), "\s+", " ") "|" maxMatches
    if pe.NativeAdHocCache.Has(key)
        return pe.NativeAdHocCache[key]

    helper := EnsureNativeScanner()
    if helper = ""
        return ""

    token := DllCall("GetCurrentProcessId", "UInt") "-adhoc-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    manifest := workDir "\patterns.tsv"
    output := workDir "\results.tsv"

    try {
        f := FileOpen(manifest, "w", "UTF-8-RAW")
        if !IsObject(f)
            throw Error("Unable to create native ad-hoc manifest.")
        f.Write("1`t" RegExReplace(Trim(patternText), "\s+", " ") "`n")
        f.Close()

        q := Chr(34)
        cmd := q helper q
            . " --exe " q pe.Path q
            . " --manifest " q manifest q
            . " --out " q output q
            . " --max-matches " maxMatches

        Run(cmd, , "Hide", &pid)
        NativeScannerPid := pid
        NativeScannerActive := true
        while ProcessExist(pid) {
            if ScanCancelled {
                try ProcessClose(pid)
                throw Error("__SCAN_CANCELLED__")
            }
            Sleep(15)
        }
        NativeScannerPid := 0
        NativeScannerActive := false
        CheckScanCancelled(true)

        if !FileExist(output)
            throw Error("ScannerCore produced no ad-hoc result file.")

        hits := []
        text := FileRead(output, "UTF-8")
        for line in StrSplit(StrReplace(text, "`r", ""), "`n") {
            if line = ""
                continue
            cols := StrSplit(line, "`t")
            if cols.Length < 3 || cols[1] != "RESULT"
                continue
            Loop Max(0, cols.Length - 3) {
                field := cols[A_Index + 3]
                bits := StrSplit(field, ",")
                if bits.Length < 3
                    continue
                hits.Push({
                    Raw: ("0x" bits[1]) + 0,
                    RVA: ("0x" bits[2]) + 0,
                    Section: bits[3]
                })
            }
        }
        pe.NativeAdHocCache[key] := hits
        try DirDelete(workDir, true)
        return hits
    } catch as err {
        NativeScannerPid := 0
        NativeScannerActive := false
        try DirDelete(workDir, true)
        if err.Message = "__SCAN_CANCELLED__"
            throw err
        return ""
    }
}

; Native semantic StaticConstructObject resolver. ScannerCore performs the
; expensive .pdata/XREF/call-graph work and returns a candidate; AHK then
; independently rechecks the RF-flags fingerprint and generated AOB uniqueness.
TryResolveNativeStaticConstructObject(pe) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return ""

    token := DllCall("GetCurrentProcessId", "UInt") "-sco-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    output := workDir "\sco.tsv"
    progress := workDir "\progress.tsv"

    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --semantic-sco " q output q
        . " --progress " q progress q

    SetResolverProgressAtLeast(0.41, "StaticConstructObject: native semantic resolver starting...")
    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {
            Status: "NOT FOUND",
            MatchCount: 0,
            TargetRVA: -1,
            NativeAttempted: true,
            Diagnostics: "ScannerCore could not be launched: " err.Message ". Interpreted deep fallback was suppressed.",
            Source: "ScannerCore native semantic SCO resolver"
        }
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }

        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "SEM" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetResolverProgressAtLeast(0.41 + (pct / 100.0) * 0.50,
                            "StaticConstructObject: native core: " cols[3])
                    }
                }
            }
        }
        Sleep(20)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)

    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {
            Status: "NOT FOUND",
            MatchCount: 0,
            TargetRVA: -1,
            NativeAttempted: true,
            Diagnostics: "ScannerCore launched but exited without producing an SCO result. The multi-minute interpreted AHK duplicate pass was suppressed.",
            Source: "ScannerCore native semantic SCO resolver"
        }
    }

    try {
        line := Trim(FileRead(output, "UTF-8"), "`r`n ")
        cols := StrSplit(line, "`t")
        if cols.Length < 8 || cols[1] != "SCO" {
            try DirDelete(workDir, true)
            return {
                Status: "NOT FOUND",
                MatchCount: 0,
                TargetRVA: -1,
                NativeAttempted: true,
                Diagnostics: "ScannerCore returned a malformed SCO result; interpreted deep fallback was suppressed.",
                Source: "ScannerCore native semantic SCO resolver"
            }
        }

        ; Distinguish "ScannerCore ran and found no decisive target" from
        ; "ScannerCore was unavailable/failed". The former should NOT trigger the
        ; multi-minute interpreted AHK semantic duplicate pass.
        if cols[2] != "FOUND" {
            detail := cols.Length >= 8 ? cols[8] : "Native semantic resolver completed without a decisive target."
            support := cols.Length >= 6 ? cols[6] + 0 : 0
            runner := cols.Length >= 7 ? cols[7] + 0 : 0
            try DirDelete(workDir, true)
            return {
                Status: "NOT FOUND",
                MatchCount: 0,
                TargetRVA: -1,
                NativeAttempted: true,
                Diagnostics: detail,
                Consensus: Format("Native semantic support {} vs runner-up {}.", support, runner),
                Source: "ScannerCore native semantic SCO resolver"
            }
        }

        targetRVA := ("0x" cols[3]) + 0
        callRVA := cols[4] != "-" ? ("0x" cols[4]) + 0 : -1
        opcode := cols[5] != "-" ? ("0x" cols[5]) + 0 : -1
        support := cols[6] + 0
        runner := cols[7] + 0
        detail := cols[8]
        magicSingletonOnly := InStr(detail, "magic-singleton-only") > 0
        patternSleuthMaxOnly := InStr(detail, "patternsleuth-max-only") > 0
        identityIncomplete := magicSingletonOnly || patternSleuthMaxOnly

        proof := StaticConstructMagicProof(pe, targetRVA)
        if !proof.Passed {
            try DirDelete(workDir, true)
            return {
                Status: "NOT FOUND",
                MatchCount: 0,
                TargetRVA: -1,
                NativeAttempted: true,
                Diagnostics: detail " Native target failed AHK RF-flags revalidation: " proof.Detail " Interpreted deep fallback was suppressed.",
                Source: "ScannerCore native semantic SCO resolver"
            }
        }

        result := ""
        if callRVA >= 0 && opcode = 0xE8 {
            callRaw := RvaToRaw(pe, callRVA)
            if callRaw >= 0 && ResolveRel32AtRaw(pe, callRaw) = targetRVA {
                result := BuildUniqueCallResult(pe, callRVA, targetRVA,
                    "ScannerCore native semantic SCO resolver",
                    detail " " proof.Detail)
            }
        }

        if !IsObject(result) || !IsUsableResolverResult(result) {
            result := BuildUniqueDirectResult(pe, targetRVA,
                "ScannerCore native semantic SCO resolver",
                detail " " proof.Detail " Target-entry AOB is unique.")
            if IsObject(result) && result.Status = "STRONG" {
                if identityIncomplete {
                    if magicSingletonOnly
                        result.Validation := proof.Detail " It is the only RF-flags-fingerprint function in the executable and the generated target-entry AOB is unique, but NewObject semantic convergence did not independently complete; retained STRONG."
                    else
                        result.Validation := proof.Detail " PatternSleuth-compatible empty-name evidence selected this unique RF-flags target as the support leader, but the lead did not satisfy the stricter independent-convergence threshold; retained STRONG."
                } else {
                    result.Status := "VERIFIED"
                    result.Validation := proof.Detail " ScannerCore independently connected the target to NewObject semantic anchors/call-graph evidence, and the generated target-entry AOB is unique."
                }
            }
        }

        if IsObject(result) && IsUsableResolverResult(result) {
            if identityIncomplete && result.Status = "VERIFIED" {
                result.Status := "STRONG"
                if magicSingletonOnly
                    result.Validation := proof.Detail " Exactly one RF-flags-fingerprint function exists and the call/AOB is structurally valid, but NewObject semantic convergence was unavailable; retained STRONG rather than claiming full identity verification."
                else
                    result.Validation := proof.Detail " PatternSleuth-compatible phase-2 evidence selected this RF-flags target as the unique support leader and the call/AOB is structurally valid, but our stricter convergence threshold was not met; retained STRONG rather than claiming full identity verification."
            }
            result.NativeAttempted := true
            result.MatchCount := Max(1, support)
            result.Consensus := Format("Native semantic support {} vs runner-up {}.", support, runner)
            result.Diagnostics := detail
            result.SecondaryProof := proof.Detail
        }

        try DirDelete(workDir, true)
        return result
    } catch as err {
        try DirDelete(workDir, true)
        return {
            Status: "NOT FOUND",
            MatchCount: 0,
            TargetRVA: -1,
            NativeAttempted: true,
            Diagnostics: "ScannerCore SCO result parsing/revalidation failed: " err.Message ". Interpreted deep fallback was suppressed.",
            Source: "ScannerCore native semantic SCO resolver"
        }
    }
}

; Candidate-only structural corroboration for newer StaticConstructObject forms.
; The primary AOB/corpus resolver must already have selected targetRVA. ScannerCore
; decodes only that function and verifies the FStaticConstructObjectParameters-like
; field flow: params+0/+8/+0x10/+0x18 become Class/Outer/Name/ObjectFlags, the loaded
; Class receives the 0x10000080 EClassFlags test, and a decoded core call reconstructs
; RCX/RDX/R8/R9 from those exact fields. It never discovers or substitutes a target.
CorroborateNativeStaticConstructObject(pe, targetRVA) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return {Passed: false, Detail: "Native StaticConstructObject parameter-pack corroboration unavailable because ScannerCore is unavailable."}

    token := DllCall("GetCurrentProcessId", "UInt") "-scoproof-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    output := workDir "\sco-proof.tsv"
    progress := workDir "\progress.tsv"
    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --semantic-sco-proof " q output q
        . " --sco-candidate " Format("{:X}", targetRVA)
        . " --progress " q progress q

    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native StaticConstructObject corroboration could not launch: " err.Message}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }
        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "SEM" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetResolverProgressAtLeast(0.40 + (pct / 100.0) * 0.18,
                            "StaticConstructObject: native parameter-pack proof: " cols[3])
                    }
                }
            }
        }
        Sleep(20)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)

    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native StaticConstructObject corroboration produced no result file."}
    }

    try {
        line := Trim(FileRead(output, "UTF-8"), "`r`n ")
        cols := StrSplit(line, "`t")
        if cols.Length < 9 || cols[1] != "SCOPROOF" {
            try DirDelete(workDir, true)
            return {Passed: false, Detail: "Native StaticConstructObject corroboration returned a malformed result."}
        }

        score := cols[4] + 0
        fields := cols[5] + 0
        coreCalls := cols[6] + 0
        classFlagsDisp := cols[7] + 0
        returnsResult := cols[8] = "true"
        detail := cols[9]
        if cols[2] != "PROVED" {
            try DirDelete(workDir, true)
            return {Passed: false, Detail: detail, Score: score, Fields: fields,
                CoreCalls: coreCalls, ClassFlagsDisp: classFlagsDisp, ReturnsResult: returnsResult}
        }

        resolvedTarget := ("0x" cols[3]) + 0
        passed := resolvedTarget = targetRVA
        try DirDelete(workDir, true)
        if !passed
            return {Passed: false, Detail: Format("Native StaticConstructObject proof returned mismatched RVA 0x{:X}; expected 0x{:X}. {}", resolvedTarget, targetRVA, detail)}
        return {Passed: true, Detail: detail, Score: score, Fields: fields,
            CoreCalls: coreCalls, ClassFlagsDisp: classFlagsDisp, ReturnsResult: returnsResult}
    } catch as err {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native StaticConstructObject proof parsing failed: " err.Message}
    }
}


; Native semantic fallback for pre-4.23 FName::ToString. ScannerCore identifies
; the old GNames lazy singleton by behavior (load/test/allocate/store-back) and
; then scores decoded callers of that getter for the invariant FName layout and
; chunk math. This intentionally runs only after the cheap modern/legacy paths
; miss, so current-engine games keep their fast path.
TryResolveNativeLegacyFNameToString(pe) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return ""

    token := DllCall("GetCurrentProcessId", "UInt") "-fnamelegacy-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    output := workDir "\fname.tsv"
    progress := workDir "\progress.tsv"
    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --semantic-legacy-fname " q output q
        . " --progress " q progress q

    SetResolverProgressAtLeast(0.60, "FName_ToString: native old-GNames semantic resolver starting...")
    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore legacy FName resolver could not be launched: " err.Message,
            Source: "ScannerCore pre-4.23 GNames semantic resolver",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }
        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "SEM" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetResolverProgressAtLeast(0.60 + (pct / 100.0) * 0.25,
                            "FName_ToString: native old-UE core: " cols[3])
                    }
                }
            }
        }
        Sleep(20)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)

    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore legacy FName resolver exited without producing a result.",
            Source: "ScannerCore pre-4.23 GNames semantic resolver",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    try {
        line := Trim(FileRead(output, "UTF-8"), "`r`n ")
        cols := StrSplit(line, "`t")
        if cols.Length < 9 || cols[1] != "FNAME" {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: "ScannerCore returned a malformed legacy FName result.",
                Source: "ScannerCore pre-4.23 GNames semantic resolver",
                Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
        }

        score := cols[6] + 0
        runner := cols[7] + 0
        candidates := cols[8] + 0
        detail := cols[9]
        if cols[2] != "FOUND" {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: detail,
                Consensus: Format("Native old-FName semantic score {} vs runner-up {} across {} getter caller candidate(s).", score, runner, candidates),
                Source: "ScannerCore pre-4.23 GNames semantic resolver",
                Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
        }

        gnamesRVA := ("0x" cols[3]) + 0
        getterRVA := ("0x" cols[4]) + 0
        targetRVA := ("0x" cols[5]) + 0
        result := BuildUniqueDirectResult(pe, targetRVA,
            "ScannerCore pre-4.23 GNames semantic resolver",
            "Decoded old-GNames singleton semantics and FName layout/chunk-decoding behavior identify this FName::ToString implementation. Target-entry AOB is unique.")
        if !IsObject(result) || !IsUsableResolverResult(result) {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: candidates, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: Format("{} Native analysis selected FName::ToString RVA 0x{:X}, but no unique target-entry AOB could be manufactured.", detail, targetRVA),
                Source: "ScannerCore pre-4.23 GNames semantic resolver",
                Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
        }

        result.Status := "VERIFIED"
        result.NativeAttempted := true
        result.MatchCount := 1
        result.Tier := 4
        result.TierName := "Semantic XREF"
        result.TierLabel := "T4 - Semantic XREF"
        result.TierLocked := true
        result.Validation := Format("A decoded pre-4.23 GNames lazy getter at 0x{:X} resolves writable GNames RVA 0x{:X}; one decoded caller exhibits the invariant FName ComparisonIndex/Number layout, 0x3FFF chunk mask, >>14 chunk selection, FString output behavior, underscore append, and Number-1 suffix path. The generated target-entry AOB uniquely re-resolves RVA 0x{:X}.", getterRVA, gnamesRVA, targetRVA)
        result.Consensus := Format("Native old-FName semantic score {} beat runner-up {} across {} GNames-getter caller candidate(s).", score, runner, candidates)
        result.Diagnostics := detail
        result.SecondaryProof := Format("GNames RVA 0x{:X}; lazy getter RVA 0x{:X}.", gnamesRVA, getterRVA)
        try DirDelete(workDir, true)
        return result
    } catch as err {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore legacy FName result parsing/revalidation failed: " err.Message,
            Source: "ScannerCore pre-4.23 GNames semantic resolver",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }
}


; Independent structural proof for an already-selected FName(wchar_t*, EFindName)
; constructor candidate. This handles older/custom UE4 compiler shapes where the
; public constructor is a tiny delegating wrapper rather than one of PatternSleuth's
; modern direct prologues. ScannerCore decodes the wrapper, follows its sole helper,
; and verifies that the helper consumes the incoming RDX name as wchar_t words.
; An ANSI sibling wrapper therefore fails the proof even when its outer body is
; byte-for-byte near-identical.
CorroborateNativeFNameConstructor(pe, targetRVA) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return {Passed: false, Detail: "Native FName constructor corroboration unavailable because ScannerCore is unavailable."}

    token := DllCall("GetCurrentProcessId", "UInt") "-fnamector-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    output := workDir "\fname-ctor.tsv"
    progress := workDir "\progress.tsv"
    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --semantic-fname-ctor-proof " q output q
        . " --fname-ctor-candidate " Format("{:X}", targetRVA)
        . " --progress " q progress q

    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native FName constructor corroboration could not launch: " err.Message}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }
        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "SEM" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetResolverProgressAtLeast(0.48 + (pct / 100.0) * 0.12,
                            "FName_Constructor: native wrapper proof: " cols[3])
                    }
                }
            }
        }
        Sleep(20)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)

    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native FName constructor corroboration produced no result file."}
    }

    try {
        line := Trim(FileRead(output, "UTF-8"), "`r`n ")
        cols := StrSplit(line, "`t")
        if cols.Length < 7 || cols[1] != "FCTOR" {
            try DirDelete(workDir, true)
            return {Passed: false, Detail: "Native FName constructor corroboration returned a malformed result."}
        }

        wrapperScore := cols[5] + 0
        helperScore := cols[6] + 0
        detail := cols[7]
        if cols[2] != "PROVED" {
            try DirDelete(workDir, true)
            return {Passed: false, Detail: detail, WrapperScore: wrapperScore, HelperScore: helperScore}
        }

        resolvedTarget := ("0x" cols[3]) + 0
        helperRVA := ("0x" cols[4]) + 0
        passed := resolvedTarget = targetRVA
        try DirDelete(workDir, true)

        if !passed
            return {Passed: false, Detail: Format("Native FName constructor proof returned mismatched RVA 0x{:X}; expected 0x{:X}. {}", resolvedTarget, targetRVA, detail)}
        return {Passed: true, Detail: detail, HelperRVA: helperRVA,
            WrapperScore: wrapperScore, HelperScore: helperScore}
    } catch as err {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native FName constructor proof parsing failed: " err.Message}
    }
}


; Independent structural proof for an already-selected GUObjectArray candidate.
; It never invents a target. It finds a decoded LEA RCX,&candidate -> CALL path
; and requires the callee to initialize the characteristic early-FUObjectArray
; field layout. This gives old engines a string-independent second proof.
CorroborateNativeGUObjectArrayStructure(pe, targetRVA) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return {Passed: false, Detail: "Native GUObjectArray constructor corroboration unavailable because ScannerCore is unavailable."}

    token := DllCall("GetCurrentProcessId", "UInt") "-guobjproof-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    output := workDir "\guobj.tsv"
    progress := workDir "\progress.tsv"
    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --semantic-guobject-proof " q output q
        . " --guobject-candidate " Format("{:X}", targetRVA)
        . " --progress " q progress q

    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native GUObjectArray constructor corroboration could not launch: " err.Message}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }
        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "SEM" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetResolverProgressAtLeast(0.59 + (pct / 100.0) * 0.18,
                            "GUObjectArray: native constructor proof: " cols[3])
                    }
                }
            }
        }
        Sleep(20)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)
    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native GUObjectArray constructor corroboration produced no result file."}
    }

    try {
        line := Trim(FileRead(output, "UTF-8"), "`r`n ")
        cols := StrSplit(line, "`t")
        if cols.Length < 10 || cols[1] != "GUOBJ" {
            try DirDelete(workDir, true)
            return {Passed: false, Detail: "Native GUObjectArray constructor corroboration returned a malformed result."}
        }
        score := cols[7] + 0
        runner := cols[8] + 0
        candidates := cols[9] + 0
        detail := cols[10]
        if cols[2] != "PROVED" {
            try DirDelete(workDir, true)
            return {Passed: false, Detail: detail, Score: score, RunnerUp: runner, Candidates: candidates}
        }
        resolvedTarget := ("0x" cols[3]) + 0
        ctorRVA := ("0x" cols[4]) + 0
        callRVA := ("0x" cols[5]) + 0
        leaRVA := ("0x" cols[6]) + 0
        passed := resolvedTarget = targetRVA
        try DirDelete(workDir, true)
        if !passed
            return {Passed: false, Detail: Format("Native GUObjectArray proof returned mismatched RVA 0x{:X}; expected 0x{:X}. {}", resolvedTarget, targetRVA, detail)}
        return {Passed: true, Detail: detail, CtorRVA: ctorRVA, CallRVA: callRVA, LeaRVA: leaRVA,
            Score: score, RunnerUp: runner, Candidates: candidates}
    } catch as err {
        try DirDelete(workDir, true)
        return {Passed: false, Detail: "Native GUObjectArray constructor proof parsing failed: " err.Message}
    }
}


; String-independent GUObjectArray discovery for old/custom UE4 branches whose
; usual stat patterns and UObject diagnostics are absent. ScannerCore searches
; for the distinctive FUObjectArray constructor body first, then requires a real
; singleton callsite that materializes one writable global as RCX. AHK rechecks
; both rel32 operands and manufactures the final portable signature.
TryResolveNativeGUObjectArrayDiscovery(pe) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return ""

    token := DllCall("GetCurrentProcessId", "UInt") "-guobjdiscover-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    output := workDir "\guobj-discover.tsv"
    progress := workDir "\progress.tsv"
    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --semantic-guobject-discover " q output q
        . " --progress " q progress q

    SetResolverProgressAtLeast(0.66, "GUObjectArray: native string-independent constructor discovery starting...")
    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore GUObjectArray constructor discovery could not launch: " err.Message,
            Source: "ScannerCore GUObjectArray constructor discovery",
            Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }
        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "SEM" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetResolverProgressAtLeast(0.66 + (pct / 100.0) * 0.27,
                            "GUObjectArray: native discovery: " cols[3])
                    }
                }
            }
        }
        Sleep(20)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)
    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore GUObjectArray constructor discovery produced no result file.",
            Source: "ScannerCore GUObjectArray constructor discovery",
            Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true}
    }

    try {
        line := Trim(FileRead(output, "UTF-8"), "`r`n ")
        cols := StrSplit(line, "`t")
        if cols.Length < 10 || cols[1] != "GUOBJ" {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: "ScannerCore returned a malformed GUObjectArray discovery result.",
                Source: "ScannerCore GUObjectArray constructor discovery",
                Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true}
        }

        score := cols[7] + 0
        runner := cols[8] + 0
        candidates := cols[9] + 0
        detail := cols[10]
        if cols[2] != "PROVED" {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: candidates, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: detail,
                Consensus: Format("Native GUObjectArray constructor score {} vs runner-up {} across {} global candidate(s).", score, runner, candidates),
                Source: "ScannerCore GUObjectArray constructor discovery",
                Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true}
        }

        targetRVA := ("0x" cols[3]) + 0
        ctorRVA := ("0x" cols[4]) + 0
        callRVA := ("0x" cols[5]) + 0
        leaRVA := ("0x" cols[6]) + 0
        leaRaw := RvaToRaw(pe, leaRVA)
        callRaw := RvaToRaw(pe, callRVA)
        if leaRaw < 0 || callRaw < 0 || !BytesEqual(pe, leaRaw, [0x48,0x8D,0x0D])
            throw Error("native discovery LEA site failed AHK opcode revalidation")
        leaDisp := NumGet(pe.Data, leaRaw + 3, "Int")
        if leaRVA + 7 + leaDisp != targetRVA
            throw Error("native discovery LEA no longer resolves the reported global")
        if ByteAt(pe, callRaw) != 0xE8 || ResolveRel32AtRaw(pe, callRaw) != ctorRVA
            throw Error("native discovery CALL no longer resolves the reported constructor")

        coreLen := callRaw + 5 - leaRaw
        if coreLen <= 0 || coreLen > 0x60
            throw Error("native discovery LEA/CALL core length was invalid")
        callDispOff := (callRVA - leaRVA) + 1
        result := BuildUniqueRipRelativeResult(pe, leaRVA, targetRVA, 3, 0,
            [[3,4], [callDispOff,4]], coreLen,
            "ScannerCore GUObjectArray constructor discovery",
            "String-independent decoded singleton construction identifies one writable FUObjectArray-shaped global; LEA and constructor CALL operands were independently revalidated.")
        if !IsObject(result) || !IsUsableResolverResult(result) {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: candidates, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: detail " Structural discovery converged but no unique relocatable LEA/callsite AOB could be manufactured.",
                Source: "ScannerCore GUObjectArray constructor discovery",
                Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true}
        }

        result.Status := "VERIFIED"
        result.NativeAttempted := true
        result.MatchCount := 1
        result.Tier := 3
        result.TierName := "Structural / callsite"
        result.TierLabel := "T3 - Structural / callsite"
        result.TierLocked := true
        result.Validation := Format("A decoded singleton callsite at 0x{:X} loads writable RVA 0x{:X} into RCX and CALLs constructor RVA 0x{:X}; the callee initializes the characteristic early FUObjectArray field layout. The generated RIP-relative AOB is unique and re-resolves the same global.", leaRVA, targetRVA, ctorRVA)
        result.Consensus := Format("Native FUObjectArray constructor score {} beat runner-up {} across {} writable-global candidate(s).", score, runner, candidates)
        result.Diagnostics := detail
        result.SecondaryProof := Format("Constructor RVA 0x{:X}; singleton LEA RVA 0x{:X}; CALL RVA 0x{:X}.", ctorRVA, leaRVA, callRVA)
        try DirDelete(workDir, true)
        return result
    } catch as err {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore GUObjectArray discovery parsing/revalidation failed: " err.Message,
            Source: "ScannerCore GUObjectArray constructor discovery",
            Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true}
    }
}

; Optimized/LTO GUObjectArray discovery for UE4/UE5 builds where diagnostic
; branches are outlined into cold runtime functions and FUObjectArray itself is
; accessed as direct RIP-relative fields from the hot callers. This avoids the
; older "nearest LEA RCX before member call" assumption, which can accidentally
; select an internal synchronization object (commonly FUObjectArray+0x30).
TryResolveNativeGUObjectArrayOutlined(pe) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return ""

    token := DllCall("GetCurrentProcessId", "UInt") "-guobjoutlined-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\scan-" token
    DirCreate(workDir)
    output := workDir "\guobj-outlined.tsv"
    progress := workDir "\progress.tsv"
    q := Chr(34)
    cmd := q helper q
        . " --exe " q pe.Path q
        . " --semantic-guobject-outlined " q output q
        . " --progress " q progress q

    SetResolverProgressAtLeast(0.48, "GUObjectArray: native outlined/LTO field-cluster discovery starting...")
    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore outlined/LTO GUObjectArray discovery could not launch: " err.Message,
            Source: "ScannerCore outlined/LTO FUObjectArray field cluster",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }
        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "SEM" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetResolverProgressAtLeast(0.48 + (pct / 100.0) * 0.20,
                            "GUObjectArray: outlined/LTO field clusters: " cols[3])
                    }
                }
            }
        }
        Sleep(20)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)
    if !FileExist(output) {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore outlined/LTO GUObjectArray discovery produced no result file.",
            Source: "ScannerCore outlined/LTO FUObjectArray field cluster",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    try {
        line := Trim(FileRead(output, "UTF-8"), "`r`n ")
        cols := StrSplit(line, "`t")
        if cols.Length < 12 || cols[1] != "GUOBJ" {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: "ScannerCore returned a malformed outlined/LTO GUObjectArray result.",
                Source: "ScannerCore outlined/LTO FUObjectArray field cluster",
                Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
        }

        score := cols[7] + 0
        runner := cols[8] + 0
        candidates := cols[9] + 0
        detail := cols[10]
        adjustment := cols[11] + 0
        proofKinds := cols[12] + 0
        if cols[2] != "PROVED" {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: candidates, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: detail,
                Consensus: Format("Outlined/LTO FUObjectArray score {} vs runner-up {} across {} base candidate(s); {} independent semantic family/families.", score, runner, candidates, proofKinds),
                Source: "ScannerCore outlined/LTO FUObjectArray field cluster",
                Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
        }

        targetRVA := ("0x" cols[3]) + 0
        bodyRVA := ("0x" cols[4]) + 0
        refRVA := ("0x" cols[6]) + 0
        if proofKinds < 2
            throw Error("outlined/LTO proof did not contain at least two independent semantic families")

        refRaw := RvaToRaw(pe, refRVA)
        if refRaw < 0
            throw Error("outlined/LTO proof site was not mapped to raw executable bytes")
        rex := ByteAt(pe, refRaw)
        opcode := ByteAt(pe, refRaw + 1)
        modrm := ByteAt(pe, refRaw + 2)
        if rex < 0x48 || rex > 0x4F || !(opcode = 0x8B || opcode = 0x8D || opcode = 0x89) || (modrm & 0xC7) != 0x05
            throw Error("outlined/LTO proof site was not a simple RIP-relative MOV/LEA field reference")
        disp := NumGet(pe.Data, refRaw + 3, "Int")
        fieldRVA := refRVA + 7 + disp
        if fieldRVA + adjustment != targetRVA
            throw Error(Format("outlined/LTO proof site resolves field RVA 0x{:X}; adjustment {} does not reconstruct target 0x{:X}", fieldRVA, adjustment, targetRVA))

        result := BuildUniqueRipRelativeResult(pe, refRVA, targetRVA, 3, adjustment,
            [[3,4]], 7,
            "ScannerCore outlined/LTO FUObjectArray field cluster",
            "Independent semantically identified UObject subsystem paths converge on one FUObjectArray field constellation; RIP-relative field addressing is decoded and the base adjustment is revalidated.")
        if !IsObject(result) || !IsUsableResolverResult(result) {
            try DirDelete(workDir, true)
            return {Status: "NOT FOUND", MatchCount: candidates, TargetRVA: -1, NativeAttempted: true,
                Diagnostics: detail " Field clustering converged but no unique relocatable field-reference AOB could be manufactured.",
                Source: "ScannerCore outlined/LTO FUObjectArray field cluster",
                Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
        }

        result.Status := "VERIFIED"
        result.NativeAttempted := true
        result.MatchCount := 1
        result.Tier := 4
        result.TierName := "Semantic XREF"
        result.TierLabel := "T4 - Semantic XREF"
        result.TierLocked := true
        result.Validation := Format("{} independently identified UObject semantic family/families converge on FUObjectArray RVA 0x{:X} through a consistent field-offset constellation. Proof site 0x{:X} references field RVA 0x{:X}; signed adjustment {} reconstructs the base, and the generated AOB is unique.", proofKinds, targetRVA, refRVA, fieldRVA, adjustment)
        result.Consensus := Format("Outlined/LTO FUObjectArray score {} beat runner-up {} across {} candidate base(s), with {} independent semantic family/families.", score, runner, candidates, proofKinds)
        result.Diagnostics := detail
        result.SecondaryProof := Format("Representative hot body RVA 0x{:X}; field-reference RVA 0x{:X}; base adjustment {}.", bodyRVA, refRVA, adjustment)
        try DirDelete(workDir, true)
        return result
    } catch as err {
        try DirDelete(workDir, true)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, NativeAttempted: true,
            Diagnostics: "ScannerCore outlined/LTO GUObjectArray parsing/revalidation failed: " err.Message,
            Source: "ScannerCore outlined/LTO FUObjectArray field cluster",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }
}

; Captures the selected executable's already-mapped main module from a running
; process using ordinary read-only Windows process access. ScannerCore rewrites
; each section's raw offset to its RVA in a temporary normalized PE snapshot, so
; the existing static/semantic resolver stack can analyze runtime bytes without
; learning a second PE-addressing model.
CaptureRuntimeImage(exePath, waitMs := 0) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return {Success: false, Status: "UNAVAILABLE", Detail: "ScannerCore.exe is unavailable; runtime image capture cannot start."}

    token := DllCall("GetCurrentProcessId", "UInt") "-runtime-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\runtime-" token
    DirCreate(workDir)
    snapshot := workDir "\mapped-image.exe"
    meta := workDir "\capture.tsv"
    progress := workDir "\progress.tsv"

    q := Chr(34)
    cmd := q helper q
        . " --exe " q exePath q
        . " --capture-runtime " q snapshot q
        . " --runtime-meta " q meta q
        . " --runtime-wait-ms " Max(0, Floor(waitMs))
        . " --progress " q progress q

    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Success: false, Status: "ERROR", Detail: "Unable to launch ScannerCore runtime capture: " err.Message}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }

        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "RUNTIME" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetScanProgress(5.0 + (pct / 100.0) * 5.0,
                            "Runtime capture: " cols[3])
                    }
                }
            }
        }
        Sleep(25)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)

    if !FileExist(meta) {
        try DirDelete(workDir, true)
        return {Success: false, Status: "ERROR", Detail: "ScannerCore runtime capture exited without metadata."}
    }

    fields := Map()
    try {
        text := FileRead(meta, "UTF-8")
        for line in StrSplit(StrReplace(text, "`r", ""), "`n") {
            if line = ""
                continue
            cols := StrSplit(line, "`t")
            if cols.Length < 2
                continue
            fields[cols[1]] := cols[2]
        }
    } catch as err {
        try DirDelete(workDir, true)
        return {Success: false, Status: "ERROR", Detail: "Could not parse ScannerCore runtime metadata: " err.Message}
    }

    status := fields.Get("STATUS", "ERROR")
    detail := fields.Get("DETAIL", "Runtime capture did not provide a detail message.")
    if status != "OK" || !FileExist(snapshot) {
        try DirDelete(workDir, true)
        return {
            Success: false,
            Status: status,
            Detail: detail,
            PID: fields.Get("PID", 0) + 0
        }
    }

    return {
        Success: true,
        Status: status,
        Detail: detail,
        Path: snapshot,
        WorkDir: workDir,
        PID: fields.Get("PID", 0) + 0,
        Base: fields.Has("BASE") ? ("0x" fields["BASE"]) + 0 : 0,
        ImageSize: fields.Get("IMAGE_SIZE", 0) + 0,
        Sections: fields.Get("SECTIONS", 0) + 0,
        ReadBytes: fields.Get("READ_BYTES", 0) + 0,
        FailedBytes: fields.Get("FAILED_BYTES", 0) + 0,
        ExecSpanBytes: fields.Get("EXEC_SPAN_BYTES", 0) + 0,
        FailedExecBytes: fields.Get("FAILED_EXEC_BYTES", 0) + 0,
        ProcessPath: fields.Get("PROCESS_PATH", "")
    }
}


; Imports an offline user-supplied runtime artifact and normalizes the selected
; executable's mapped module into the same scanner-friendly PE format produced
; by CaptureRuntimeImage(). Supported inputs are standard Windows minidumps/full
; user-mode dumps with ModuleList + MemoryList/Memory64List streams, plus mapped
; PE images laid out by virtual address. This path never opens a live process.
ImportRuntimeDump(exePath, dumpPath) {
    global ScanCancelled, NativeScannerPid, NativeScannerActive

    helper := EnsureNativeScanner()
    if helper = ""
        return {Success: false, Status: "UNAVAILABLE", Detail: "ScannerCore.exe is unavailable; runtime dump import cannot start."}
    if !FileExist(dumpPath)
        return {Success: false, Status: "NOT_FOUND", Detail: "The selected runtime dump does not exist."}

    token := DllCall("GetCurrentProcessId", "UInt") "-dump-" A_TickCount
    workDir := A_Temp "\UE4SSSignatureGenerator\dump-" token
    DirCreate(workDir)
    snapshot := workDir "\mapped-image.exe"
    meta := workDir "\capture.tsv"
    progress := workDir "\progress.tsv"

    q := Chr(34)
    cmd := q helper q
        . " --exe " q exePath q
        . " --runtime-dump " q dumpPath q
        . " --capture-runtime " q snapshot q
        . " --runtime-meta " q meta q
        . " --progress " q progress q

    try Run(cmd, , "Hide", &pid)
    catch as err {
        try DirDelete(workDir, true)
        return {Success: false, Status: "ERROR", Detail: "Unable to launch ScannerCore runtime dump import: " err.Message}
    }

    NativeScannerPid := pid
    NativeScannerActive := true
    lastPct := -1
    while ProcessExist(pid) {
        if ScanCancelled {
            try ProcessClose(pid)
            NativeScannerPid := 0
            NativeScannerActive := false
            try DirDelete(workDir, true)
            throw Error("__SCAN_CANCELLED__")
        }

        if FileExist(progress) {
            try {
                txt := Trim(FileRead(progress, "UTF-8"))
                cols := StrSplit(txt, "`t")
                if cols.Length >= 3 && cols[1] = "RUNTIME" {
                    pct := Max(0, Min(100, cols[2] + 0))
                    if pct != lastPct {
                        lastPct := pct
                        SetScanProgress(5.0 + (pct / 100.0) * 5.0,
                            "Runtime dump import: " cols[3])
                    }
                }
            }
        }
        Sleep(25)
    }

    NativeScannerPid := 0
    NativeScannerActive := false
    CheckScanCancelled(true)

    if !FileExist(meta) {
        try DirDelete(workDir, true)
        return {Success: false, Status: "ERROR", Detail: "ScannerCore runtime dump import exited without metadata."}
    }

    fields := Map()
    try {
        text := FileRead(meta, "UTF-8")
        for line in StrSplit(StrReplace(text, "`r", ""), "`n") {
            if line = ""
                continue
            cols := StrSplit(line, "`t")
            if cols.Length < 2
                continue
            fields[cols[1]] := cols[2]
        }
    } catch as err {
        try DirDelete(workDir, true)
        return {Success: false, Status: "ERROR", Detail: "Could not parse ScannerCore runtime dump metadata: " err.Message}
    }

    status := fields.Get("STATUS", "ERROR")
    detail := fields.Get("DETAIL", "Runtime dump import did not provide a detail message.")
    if status != "OK" || !FileExist(snapshot) {
        try DirDelete(workDir, true)
        return {
            Success: false,
            Status: status,
            Detail: detail,
            Format: fields.Get("FORMAT", "UNKNOWN"),
            SourcePath: fields.Get("SOURCE_PATH", dumpPath)
        }
    }

    return {
        Success: true,
        Status: status,
        Detail: detail,
        Path: snapshot,
        WorkDir: workDir,
        PID: fields.Get("PID", 0) + 0,
        Base: fields.Has("BASE") ? ("0x" fields["BASE"]) + 0 : 0,
        ImageSize: fields.Get("IMAGE_SIZE", 0) + 0,
        Sections: fields.Get("SECTIONS", 0) + 0,
        ReadBytes: fields.Get("READ_BYTES", 0) + 0,
        FailedBytes: fields.Get("FAILED_BYTES", 0) + 0,
        ExecSpanBytes: fields.Get("EXEC_SPAN_BYTES", 0) + 0,
        FailedExecBytes: fields.Get("FAILED_EXEC_BYTES", 0) + 0,
        ProcessPath: fields.Get("PROCESS_PATH", ""),
        Format: fields.Get("FORMAT", "UNKNOWN"),
        SourcePath: fields.Get("SOURCE_PATH", dumpPath),
        SourceKind: "dump"
    }
}

CleanupRuntimeImageCapture(capture) {
    if !IsObject(capture) || !HasProp(capture, "WorkDir") || capture.WorkDir = ""
        return
    try DirDelete(capture.WorkDir, true)
}

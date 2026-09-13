; Optional historical evidence layer.
;
; If UE4SS/PatternSleuth has already scanned this exact game build, its log can
; provide a candidate address. We never trust that address blindly: the current
; executable must independently revalidate it before it can become VERIFIED.
; Fresh games without logs simply skip this layer.

TryResolveHistoricalResolverHint(pe, target) {
    ; A local UE4SS runtime log is usable only for identities whose address it
    ; names explicitly. Keep this small and evidence-led: it must not turn
    ; arbitrary old log text into a generic AOB resolver.
    if target != "FName_Constructor"
        && target != "StaticConstructObject"
        && target != "ProcessLocalScriptFunction"
        && target != "ProcessInternal"
        && target != "CallFunctionByNameWithArguments"
        return ""

    hints := GetNearbyUE4SSResolverHints(pe, target)
    if !hints.Has(target)
        return ""

    for hint in hints[target] {
        CheckScanCancelled(true)
        targetRVA := hint.RVA
        if targetRVA < 0 || !IsExecutableRVA(pe, targetRVA)
            continue

        if target = "FName_Constructor" {
            proof := VerifyFNameConstructorBody(pe, targetRVA)
            if !proof.Passed
                continue
            result := BuildUniqueDirectResult(pe, targetRVA,
                "Existing UE4SS/PatternSleuth log + current binary revalidation",
                "A previous PatternSleuth scan named this address FName::FName(wchar_t*); the current executable independently passed the constructor-body fingerprint and unique target-entry AOB checks.")
            if result.Status = "STRONG" {
                result.Status := "VERIFIED"
                result.Validation := proof.Detail " Historical address evidence was revalidated against the currently selected EXE; it was not trusted by address alone."
                result.SecondaryProof := "Historical evidence: " hint.Source
                return result
            }
        }

        if target = "StaticConstructObject" {
            proof := StaticConstructHistoricalProof(pe, targetRVA)
            if !proof.Passed
                continue
            result := BuildUniqueDirectResult(pe, targetRVA,
                "Existing UE4SS/PatternSleuth log + current binary revalidation",
                "A previous PatternSleuth scan named this address StaticConstructObject_Internal; the current executable independently contains the RF-flags fingerprint at that target and has a unique target-entry AOB.")
            if result.Status = "STRONG" {
                result.Status := "VERIFIED"
                result.Validation := proof.Detail " Historical address evidence was revalidated against the currently selected EXE; it was not trusted by address alone."
                result.SecondaryProof := "Historical evidence: " hint.Source
                return result
            }
        }

        if target = "ProcessLocalScriptFunction"
            || target = "ProcessInternal"
            || target = "CallFunctionByNameWithArguments" {
            ; UE4SS writes these address lines only after its own resolver has
            ; selected the hook target. Rebuild an AOB from the present binary
            ; and require that it is unique before treating the runtime record
            ; as independent identity proof. Never reuse the logged RVA by
            ; itself: an updated executable will fail this revalidation.
            if !RuntimeLogIsCurrentForSelectedImage(pe, hint.Source)
                continue

            result := BuildUniqueDirectResult(pe, targetRVA,
                "Existing UE4SS runtime log + current binary revalidation",
                "A nearby UE4SS runtime log recorded the resolved " target " address; the currently selected executable independently produced a unique target-entry AOB at that RVA.")
            if result.Status = "STRONG" {
                result.Status := "VERIFIED"
                result.Validation := "UE4SS runtime resolution evidence for " target " was revalidated against the current executable by a unique target-entry AOB; the historical address was not trusted by itself."
                result.SecondaryProof := "Historical runtime evidence: " hint.Source
                result.Tier := 2
                result.TierName := "Runtime revalidation"
                result.TierLabel := "T2 - Runtime revalidation"
                result.TierLocked := true
                return result
            }
        }
    }
    return ""
}

RuntimeLogIsCurrentForSelectedImage(pe, logPath) {
    ; A log written before the selected EXE was last modified cannot be evidence
    ; for this build. File timestamps are not a substitute for AOB validation,
    ; but this cheap gate prevents an old UE4SS log from being used after a game
    ; update before the binary is inspected.
    imagePath := HasProp(pe, "OriginalPath") && pe.OriginalPath != "" ? pe.OriginalPath : pe.Path
    if imagePath = "" || !FileExist(imagePath) || !FileExist(logPath)
        return false
    try return FileGetTime(logPath, "M") >= FileGetTime(imagePath, "M")
    catch
        return false
}


StaticConstructHistoricalProof(pe, targetRVA) {
    ; Historical PatternSleuth already supplies the identity hypothesis. For
    ; revalidation we only need to prove the current EXE still has executable
    ; code at that exact address and that the distinctive SCO RF-flags immediate
    ; occurs in the bounded function-entry neighborhood. Do not require exact
    ; unwind-root equality here; optimized/chained Win64 unwind metadata can make
    ; that stricter condition reject an otherwise identical current build.
    if targetRVA < 0 || !IsExecutableRVA(pe, targetRVA)
        return {Passed: false, Detail: "Historical SCO target is not executable in the current image."}

    raw := RvaToRaw(pe, targetRVA)
    if raw < 0
        return {Passed: false, Detail: "Historical SCO target bytes are unavailable in the current image."}

    length := Min(0x2000, pe.Size - raw)
    if length <= 0 || !ContainsBytes(pe, raw, length, [0x80, 0x00, 0x00, 0x10])
        return {Passed: false, Detail: "Current code at the historical SCO address does not contain the distinctive 0x10000080 RF-flags immediate within the bounded entry neighborhood."}

    return {Passed: true, Detail: "Historical PatternSleuth SCO address still points to executable code containing the distinctive 0x10000080 RF-flags immediate in the current EXE."}
}

GetNearbyUE4SSResolverHints(pe, requestedTarget := "") {
    if HasProp(pe, "HistoricalResolverHints")
        return pe.HistoricalResolverHints

    hints := Map()
    seenHint := Map()
    evidencePath := HasProp(pe, "OriginalPath") && pe.OriginalPath != "" ? pe.OriginalPath : pe.Path
    files := DiscoverNearbyUE4SSLogFiles(evidencePath, 8)

    regexes := Map(
        "FName_Constructor", "i)\[PS\]\s*Found\s+FName::FName\(wchar_t\*\):\s*0x([0-9A-F]+)",
        "FName_ToString", "i)\[PS\]\s*Found\s+FName::ToString:\s*0x([0-9A-F]+)",
        "StaticConstructObject", "i)\[PS\]\s*Found\s+StaticConstructObject_Internal:\s*0x([0-9A-F]+)",
        "GMalloc", "i)\[PS\]\s*Found\s+GMalloc:\s*0x([0-9A-F]+)",
        "GUObjectArray", "i)\[PS\]\s*Found\s+GUObjectArray:\s*0x([0-9A-F]+)",
        "ProcessLocalScriptFunction", "i)\bProcessLocalScriptFunction\s+address\s*:?\s*0x([0-9A-F]+)",
        "ProcessInternal", "i)\bProcessInternal\s+address\s*:?\s*0x([0-9A-F]+)",
        "CallFunctionByNameWithArguments", "i)\bCallFunctionByNameWithArguments\s+address\s*:?\s*0x([0-9A-F]+)"
    )

    for path in files {
        CheckScanCancelled(true)
        text := ReadLogEvidenceWindows(path, 1024 * 1024)
        if text = ""
            continue

        for target, rx in regexes {
            pos := 1
            while foundPos := RegExMatch(text, rx, &m, pos) {
                addr := ("0x" m[1]) + 0
                rva := HistoricalAddressToRVA(pe, addr)
                if rva >= 0 {
                    key := target "|" Format("{:X}", rva)
                    if !seenHint.Has(key) {
                        seenHint[key] := true
                        if !hints.Has(target)
                            hints[target] := []
                        hints[target].Push({RVA: rva, Source: path})
                    }
                }
                nextPos := foundPos + StrLen(m[0])
                pos := nextPos > pos ? nextPos : pos + 1
            }
        }
    }

    pe.HistoricalResolverHints := hints
    return hints
}

HistoricalAddressToRVA(pe, addr) {
    if addr >= pe.ImageBase && addr < pe.ImageBase + pe.SizeOfImage
        return addr - pe.ImageBase
    if addr >= 0 && addr < pe.SizeOfImage
        return addr
    return -1
}

DiscoverNearbyUE4SSLogFiles(exePath, maxFiles := 20) {
    out := []
    seen := Map()
    SplitPath(exePath, , &exeDir)
    dirs := []
    cur := exeDir
    Loop 5 {
        dirs.Push(cur)
        dirs.Push(cur "\UE4SS")
        parent := RegExReplace(cur, "\\[^\\]+$")
        if parent = cur || parent = ""
            break
        cur := parent
    }

    for dir in dirs {
        if !DirExist(dir)
            continue
        Loop Files dir "\UE4SS*.log", "F" {
            key := StrLower(A_LoopFileFullPath)
            if seen.Has(key)
                continue
            seen[key] := true
            out.Push(A_LoopFileFullPath)
            if out.Length >= maxFiles
                return out
        }
    }
    return out
}


ReadLogEvidenceWindows(path, windowChars := 8388608) {
    ; UE4SS logs can grow very large after dumps/debug mods. PatternSleuth startup
    ; lines may fall outside the first 4 MiB, so inspect both ends without loading
    ; a potentially huge log into AHK memory.
    try {
        f := FileOpen(path, "r", "UTF-8")
        if !IsObject(f)
            return ""
        size := f.Length
        head := f.Read(windowChars)
        tail := ""
        if size > windowChars {
            byteBack := Min(size, windowChars * 2)
            f.Pos := Max(0, size - byteBack)
            tail := f.Read(windowChars * 2)
        }
        f.Close()
        return head "`n" tail
    } catch {
        try {
            f := FileOpen(path, "r")
            if !IsObject(f)
                return ""
            size := f.Length
            head := f.Read(windowChars)
            tail := ""
            if size > windowChars {
                f.Pos := Max(0, size - Min(size, windowChars * 2))
                tail := f.Read(windowChars * 2)
            }
            f.Close()
            return head "`n" tail
        } catch {
            return ""
        }
    }
}

ReadLogPrefix(path, maxChars := 4194304) {
    try {
        f := FileOpen(path, "r", "UTF-8")
        if !IsObject(f)
            return ""
        text := f.Read(maxChars)
        f.Close()
        return text
    } catch {
        try {
            f := FileOpen(path, "r")
            if !IsObject(f)
                return ""
            text := f.Read(maxChars)
            f.Close()
            return text
        } catch {
            return ""
        }
    }
}

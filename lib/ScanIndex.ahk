; Cooperative scan helpers used by semantic resolver layers.
;
; v0.8.2 deliberately does NOT build a whole-executable RIP-relative XREF index.
; Building a Map entry for every RIP-relative LEA in a 650+ MB shipping EXE is
; extremely expensive in AutoHotkey. Instead, only the RIP-relative instruction shapes actually requested by resolver
; layers are indexed, and those much smaller candidate sets are cached.
;
; Every heavy loop yields to the GUI by elapsed wall time rather than by an
; arbitrary hit count. This keeps Cancel responsive even on instruction-dense
; sections where thousands of candidates can be processed before a count-based
; checkpoint is reached.

CooperativeScanYield(&lastYieldTick, intervalMs := 20) {
    if (A_TickCount - lastYieldTick) < intervalMs
        return
    lastYieldTick := A_TickCount
    CheckScanCancelled(true)
}

FindIndexedRipLeaRefs(pe, targetRVA, modrm := -1, rex := -1) {
    if !HasProp(pe, "RipLeaTargetCache")
        pe.RipLeaTargetCache := Map()

    targetKey := Format("{:X}|{}|{}", targetRVA, modrm, rex)
    if pe.RipLeaTargetCache.Has(targetKey)
        return pe.RipLeaTargetCache[targetKey]

    candidates := GetRipLeaCandidates(pe, modrm, rex)
    out := []
    for item in candidates {
        dispRaw := item.Raw + 3
        disp := NumGet(pe.Data, dispRaw, "Int")
        resolved := item.RVA + 7 + disp
        if resolved = targetRVA
            out.Push(item)
    }

    pe.RipLeaTargetCache[targetKey] := out
    return out
}

GetRipLeaCandidates(pe, modrm := -1, rex := -1) {
    ; Cache the instruction SHAPE, not every resolved destination. In practice the
    ; semantic layers use either a specific 48 8D /r form or PatternSleuth's
    ; generic 48/4C RIP-relative LEA search. That means a large EXE is walked only
    ; a small number of times without creating a giant target->refs object graph.
    if !HasProp(pe, "RipLeaShapeCache")
        pe.RipLeaShapeCache := Map()

    cacheKey := modrm "|" rex
    if pe.RipLeaShapeCache.Has(cacheKey)
        return pe.RipLeaShapeCache[cacheKey]

    out := []
    lastYield := A_TickCount

    for section in pe.Sections {
        if !section.Executable || section.RawSize < 7
            continue

        secStart := section.RawPtr
        secEnd := section.RawPtr + section.RawSize
        searchPtr := pe.Data.Ptr + secStart
        searchEndPtr := pe.Data.Ptr + secEnd

        while searchPtr < searchEndPtr {
            CooperativeScanYield(&lastYield)
            remaining := searchEndPtr - searchPtr
            foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", 0x8D, "UPtr", remaining, "Ptr")
            if !foundPtr
                break

            opcodeRaw := foundPtr - pe.Data.Ptr
            if opcodeRaw > secStart && opcodeRaw + 5 < secEnd {
                rexByte := ByteAt(pe, opcodeRaw - 1)
                modrmByte := ByteAt(pe, opcodeRaw + 1)
                ripRelative := (modrmByte & 0xC7) = 0x05

                ; PatternSleuth's generic PE XREF search uses 48 8D and 4C 8D.
                ; For an unconstrained request, limiting to those two forms cuts a
                ; great deal of noise while retaining the resolver behavior we need.
                rexOk := rex >= 0 ? (rexByte = rex) : (rexByte = 0x48 || rexByte = 0x4C)
                modrmOk := modrm >= 0 ? (modrmByte = modrm) : ripRelative

                if rexOk && modrmOk && ripRelative {
                    instrRaw := opcodeRaw - 1
                    instrRVA := section.VA + (instrRaw - section.RawPtr)
                    out.Push({
                        Raw: instrRaw,
                        RVA: instrRVA,
                        Section: section.Name,
                        REX: rexByte,
                        ModRM: modrmByte,
                        Opcode: 0x8D
                    })
                }
            }
            searchPtr := foundPtr + 1
        }
    }

    CheckScanCancelled(true)
    pe.RipLeaShapeCache[cacheKey] := out
    return out
}

FindAbsolute64Refs(pe, value, maxMatches := 256) {
    out := []
    lowByte := value & 0xFF
    lastYield := A_TickCount

    for section in pe.Sections {
        if section.RawSize < 8
            continue
        secStart := section.RawPtr
        secEnd := section.RawPtr + section.RawSize
        searchPtr := pe.Data.Ptr + secStart
        searchEndPtr := pe.Data.Ptr + secEnd

        while searchPtr < searchEndPtr && out.Length < maxMatches {
            CooperativeScanYield(&lastYield)
            remaining := searchEndPtr - searchPtr
            foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", lowByte, "UPtr", remaining, "Ptr")
            if !foundPtr
                break
            raw := foundPtr - pe.Data.Ptr
            if raw + 8 <= secEnd && NumGet(pe.Data, raw, "UInt64") = value {
                rva := section.VA + (raw - section.RawPtr)
                out.Push({Raw: raw, RVA: rva, Section: section.Name})
            }
            searchPtr := foundPtr + 1
        }
        if out.Length >= maxMatches
            break
    }
    CheckScanCancelled(true)
    return out
}

FindCallerFunctionsForTargets(pe, targetFunctions, maxCallers := 2048) {
    callers := Map()
    if targetFunctions.Count = 0
        return callers

    ; Cache caller searches because semantic resolver layers often climb the same
    ; target set more than once.
    cacheKey := CallerTargetCacheKey(targetFunctions)
    if !HasProp(pe, "CallerSearchCache")
        pe.CallerSearchCache := Map()
    if pe.CallerSearchCache.Has(cacheKey)
        return pe.CallerSearchCache[cacheKey]

    lastYield := A_TickCount
    for opcode in [0xE8, 0xE9] {
        for section in pe.Sections {
            if !section.Executable || section.RawSize < 5
                continue

            secStart := section.RawPtr
            secEnd := section.RawPtr + section.RawSize
            searchPtr := pe.Data.Ptr + secStart
            searchEndPtr := pe.Data.Ptr + secEnd

            while searchPtr < searchEndPtr && callers.Count < maxCallers {
                CooperativeScanYield(&lastYield)
                remaining := searchEndPtr - searchPtr
                foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", opcode, "UPtr", remaining, "Ptr")
                if !foundPtr
                    break
                raw := foundPtr - pe.Data.Ptr
                if raw + 5 <= secEnd {
                    siteRVA := section.VA + (raw - section.RawPtr)
                    disp := NumGet(pe.Data, raw + 1, "Int")
                    target := siteRVA + 5 + disp
                    targetKey := Format("{:X}", target)
                    if targetFunctions.Has(targetKey) {
                        caller := FindRuntimeFunction(pe, siteRVA)
                        if caller.BeginRVA >= 0
                            callers[Format("{:X}", caller.BeginRVA)] := caller
                    }
                }
                searchPtr := foundPtr + 1
            }
            if callers.Count >= maxCallers
                break
        }
        if callers.Count >= maxCallers
            break
    }

    CheckScanCancelled(true)
    pe.CallerSearchCache[cacheKey] := callers
    return callers
}

CallerTargetCacheKey(targetFunctions) {
    ; Map iteration is stable for the target sets created by our resolver paths.
    ; Avoid sorting here so this helper stays compatible with stock AHK v2.0.19.
    out := ""
    for key, value in targetFunctions
        out .= (out = "" ? "" : ",") StrUpper(key)
    return out
}

; Return inbound CALL/JMP edges to a set of function starts in one shared pass.
; Unlike FindCallerFunctionsForTargets this retains the target relationship, so
; reverse semantic layers can propagate evidence through helper functions.
FindInboundEdgesForTargets(pe, targetFunctions, maxEdges := 4096) {
    out := []
    if targetFunctions.Count = 0
        return out

    cacheKey := "EDGES|" CallerTargetCacheKey(targetFunctions) "|" maxEdges
    if !HasProp(pe, "InboundEdgeCache")
        pe.InboundEdgeCache := Map()
    if pe.InboundEdgeCache.Has(cacheKey)
        return pe.InboundEdgeCache[cacheKey]

    lastYield := A_TickCount
    for opcode in [0xE8, 0xE9] {
        for section in pe.Sections {
            if !section.Executable || section.RawSize < 5
                continue
            secStart := section.RawPtr
            secEnd := section.RawPtr + section.RawSize
            searchPtr := pe.Data.Ptr + secStart
            searchEndPtr := pe.Data.Ptr + secEnd

            while searchPtr < searchEndPtr && out.Length < maxEdges {
                CooperativeScanYield(&lastYield)
                remaining := searchEndPtr - searchPtr
                foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", opcode, "UPtr", remaining, "Ptr")
                if !foundPtr
                    break
                raw := foundPtr - pe.Data.Ptr
                if raw + 5 <= secEnd {
                    siteRVA := section.VA + (raw - section.RawPtr)
                    disp := NumGet(pe.Data, raw + 1, "Int")
                    target := siteRVA + 5 + disp
                    key := Format("{:X}", target)
                    if targetFunctions.Has(key) {
                        caller := FindRuntimeFunction(pe, siteRVA)
                        if caller.BeginRVA >= 0 {
                            out.Push({
                                SiteRVA: siteRVA,
                                Opcode: opcode,
                                CallerBeginRVA: caller.BeginRVA,
                                CallerEndRVA: caller.EndRVA,
                                TargetRVA: target
                            })
                        }
                    }
                }
                searchPtr := foundPtr + 1
            }
            if out.Length >= maxEdges
                break
        }
        if out.Length >= maxEdges
            break
    }

    CheckScanCancelled(true)
    pe.InboundEdgeCache[cacheKey] := out
    return out
}

; Generic target-specific RIP-relative data references used by late semantic
; fallbacks. LEA uses the existing optimized cache; MOV candidates are cached by
; instruction shape so one old-engine resolver cannot accidentally rescan a huge
; executable for every candidate global.
FindRipDataRefsAny(pe, targetRVA) {
    out := []
    seen := Map()
    for ref in FindIndexedRipLeaRefs(pe, targetRVA) {
        key := Format("{:X}", ref.RVA)
        if !seen.Has(key) {
            seen[key] := true
            out.Push(ref)
        }
    }
    for ref in FindIndexedRipMovRefs(pe, targetRVA) {
        key := Format("{:X}", ref.RVA)
        if !seen.Has(key) {
            seen[key] := true
            out.Push(ref)
        }
    }
    return out
}

FindIndexedRipMovRefs(pe, targetRVA) {
    if !HasProp(pe, "RipMovTargetCache")
        pe.RipMovTargetCache := Map()
    key := Format("{:X}", targetRVA)
    if pe.RipMovTargetCache.Has(key)
        return pe.RipMovTargetCache[key]

    candidates := GetRipMovCandidates(pe)
    out := []
    for item in candidates {
        disp := NumGet(pe.Data, item.Raw + 3, "Int")
        resolved := item.RVA + 7 + disp
        if resolved = targetRVA
            out.Push(item)
    }
    pe.RipMovTargetCache[key] := out
    return out
}

GetRipMovCandidates(pe) {
    if HasProp(pe, "RipMovShapeCache")
        return pe.RipMovShapeCache

    out := []
    lastYield := A_TickCount
    for section in pe.Sections {
        if !section.Executable || section.RawSize < 7
            continue
        secStart := section.RawPtr
        secEnd := section.RawPtr + section.RawSize
        searchPtr := pe.Data.Ptr + secStart
        searchEndPtr := pe.Data.Ptr + secEnd
        while searchPtr < searchEndPtr {
            CooperativeScanYield(&lastYield)
            remaining := searchEndPtr - searchPtr
            foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", 0x8B, "UPtr", remaining, "Ptr")
            if !foundPtr
                break
            opcodeRaw := foundPtr - pe.Data.Ptr
            if opcodeRaw > secStart && opcodeRaw + 5 < secEnd {
                rexByte := ByteAt(pe, opcodeRaw - 1)
                modrmByte := ByteAt(pe, opcodeRaw + 1)
                if (rexByte = 0x48 || rexByte = 0x4C) && ((modrmByte & 0xC7) = 0x05) {
                    instrRaw := opcodeRaw - 1
                    instrRVA := section.VA + (instrRaw - section.RawPtr)
                    out.Push({Raw: instrRaw, RVA: instrRVA, Section: section.Name,
                        REX: rexByte, ModRM: modrmByte, Opcode: 0x8B})
                }
            }
            searchPtr := foundPtr + 1
        }
    }
    CheckScanCancelled(true)
    pe.RipMovShapeCache := out
    return out
}

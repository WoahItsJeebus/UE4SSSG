; StaticConstructObject semantic resolver layer.
; Mirrors the current PatternSleuth strategy more closely than v0.7:
;   1) class-name anchors, including indirect references
;   2) caller climbing to locate NewObject wrappers
;   3) NewObject error-string confirmation
;   4) outgoing call graph + 0x10000080 RF-flags fingerprint
;   5) indirect string-pointer XREFs + CALL/tail-JMP flow edges
;   6) empty-name consensus fallback

ResolveStaticConstructObjectSemantic(pe) {
    SetResolverProgressAtLeast(0.40, "StaticConstructObject: starting semantic fallback...")

    newObjectText := "NewObject with empty name can't be used to create default"
    newStringRVAs := FindUtf16Rvas(pe, newObjectText, false)
    newRoots := RootFunctionsForStringRVAs(pe, newStringRVAs)
    SetResolverProgressAtLeast(0.48, "StaticConstructObject: indexing RF-flags candidate functions...")
    magicFunctions := FindStaticConstructMagicFunctions(pe)
    SetResolverProgressAtLeast(0.52, "StaticConstructObject: indexed NewObject XREFs + RF-flags candidates")

    classNames := ["UBehaviorTreeManager", "ULeaderboardFlushCallbackProxy", "UPlayMontageCallbackProxy"]
    classRoots := Map()
    anchorPresent := 0
    indirectRefs := 0

    for i, text in classNames {
        CheckScanCancelled(true)
        stringRVAs := FindUtf16Rvas(pe, text, true)
        if stringRVAs.Length > 0
            anchorPresent += 1

        for stringRVA in stringRVAs {
            targets := [stringRVA, stringRVA + 2]

            ; PatternSleuth also searches references to pointers which themselves
            ; point at the class-name string. This matters on some optimized UE5 builds.
            for ptrRef in FindAbsolute64Refs(pe, pe.ImageBase + stringRVA, 64) {
                indirectRefs += 1
                targets.Push(ptrRef.RVA)
                targets.Push(ptrRef.RVA + 2)
            }

            for targetRVA in targets {
                for ref in FindRipLeaRefsAny(pe, targetRVA) {
                    fn := FindRuntimeFunction(pe, ref.RVA)
                    if fn.BeginRVA >= 0
                        classRoots[Format("{:X}", fn.BeginRVA)] := fn
                }
            }
        }
        SetResolverProgressAtLeast(0.52 + (i / classNames.Length) * 0.10,
            "StaticConstructObject: processing class-name semantic anchors...")
    }

    diag := Format(
        "StaticConstructObject semantic scan: NewObject roots={}, RF-flags candidate functions={}, class anchors {}/3, class-root functions={}, indirect pointer refs={}.",
        newRoots.Count, magicFunctions.Count, anchorPresent, classRoots.Count, indirectRefs)

    ; Phase 1: PatternSleuth climbs callers of the class-name roots, looking for
    ; the NewObject error text either in the function itself or one called helper.
    newObjectFn := FindNewObjectFunctionFromClassRoots(pe, classRoots, newRoots)
    if newObjectFn >= 0 {
        SetResolverProgressAtLeast(0.73, "StaticConstructObject: NewObject wrapper identified; validating call graph...")
        result := ResolveStaticFromRootFunctions(pe, Map(Format("{:X}", newObjectFn), {BeginRVA: newObjectFn, EndRVA: FindRuntimeFunction(pe, newObjectFn).EndRVA}), magicFunctions, diag " Phase 1 located a NewObject wrapper.")
        if IsUsableResolverResult(result)
            return result
    }

    ; Phase 2: consensus directly from every function which references the
    ; distinctive empty-name error string. This catches builds where class-name
    ; wrappers were inlined or laid out differently.
    SetResolverProgressAtLeast(0.78, "StaticConstructObject: running empty-name consensus fallback...")
    if newRoots.Count > 0 {
        result := ResolveStaticFromRootFunctions(pe, newRoots, magicFunctions, diag " Phase 2 used NewObject empty-name consensus.")
        if IsUsableResolverResult(result)
            return result
        if result.Status = "AMBIGUOUS"
            return result
    }

    ; Phase 3: reverse evidence. Starting from the comparatively small set of
    ; RF-flags-confirmed functions, walk inbound CALL/JMP edges back toward the
    ; NewObject/class-name roots. This is the mirror image of phase 1/2 and helps
    ; when compiler layout makes forward byte walking miss a helper edge.
    SetResolverProgressAtLeast(0.90, "StaticConstructObject: running reverse RF-flags evidence pass...")
    reverse := ResolveStaticFromReverseEvidence(pe, magicFunctions, newRoots, classRoots, diag)
    if IsUsableResolverResult(reverse)
        return reverse
    if reverse.Status = "AMBIGUOUS"
        return reverse

    SetResolverProgressAtLeast(0.94, "StaticConstructObject: semantic fallback exhausted")
    if HasProp(reverse, "Diagnostics")
        diag .= " " reverse.Diagnostics
    return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, Diagnostics: diag " No RF-flags-confirmed StaticConstructObject target was found."}
}

ResolveStaticFromReverseEvidence(pe, magicFunctions, newRoots, classRoots, diag) {
    if magicFunctions.Count = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, Diagnostics: "Reverse pass had no RF-flags candidate functions."}

    firstEdges := FindInboundEdgesForTargets(pe, magicFunctions, 4096)
    if firstEdges.Length = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, Diagnostics: "Reverse pass found no inbound CALL/JMP edges to RF-flags candidates."}

    scores := Map()
    evidence := []
    helperToTargets := Map()
    helperFns := Map()

    for edge in firstEdges {
        callerKey := Format("{:X}", edge.CallerBeginRVA)
        targetKey := Format("{:X}", edge.TargetRVA)
        if !helperToTargets.Has(callerKey)
            helperToTargets[callerKey] := Map()
        helperToTargets[callerKey][targetKey] := edge.TargetRVA
        helperFns[callerKey] := {BeginRVA: edge.CallerBeginRVA, EndRVA: edge.CallerEndRVA}

        weight := 0
        reason := ""
        if newRoots.Has(callerKey) {
            weight += 6
            reason .= "direct NewObject root caller"
        }
        if classRoots.Has(callerKey) {
            weight += 2
            reason .= (reason != "" ? " + " : "") "class-anchor root caller"
        }
        if weight > 0 {
            scores[targetKey] := scores.Get(targetKey, 0) + weight
            evidence.Push({TargetRVA: edge.TargetRVA, SiteRVA: edge.SiteRVA, Opcode: edge.Opcode, Depth: 1, Reason: reason})
        }
    }

    ; One layer farther out: NewObject/class roots may call a helper which then
    ; calls (or tail-jumps to) StaticConstructObject_Internal.
    secondEdges := FindInboundEdgesForTargets(pe, helperFns, 4096)
    for outer in secondEdges {
        outerCallerKey := Format("{:X}", outer.CallerBeginRVA)
        helperKey := Format("{:X}", outer.TargetRVA)
        if !helperToTargets.Has(helperKey)
            continue

        weight := 0
        reason := ""
        if newRoots.Has(outerCallerKey) {
            weight += 4
            reason .= "NewObject root -> helper"
        }
        if classRoots.Has(outerCallerKey) {
            weight += 1
            reason .= (reason != "" ? " + " : "") "class root -> helper"
        }
        if weight <= 0
            continue

        for targetKey, targetRVA in helperToTargets[helperKey] {
            scores[targetKey] := scores.Get(targetKey, 0) + weight
            evidence.Push({TargetRVA: targetRVA, SiteRVA: outer.SiteRVA, Opcode: outer.Opcode, Depth: 2, Reason: reason})
        }
    }

    if scores.Count = 0
        return {Status: "NOT FOUND", MatchCount: firstEdges.Length + secondEdges.Length, TargetRVA: -1, Diagnostics: Format("Reverse pass saw {} direct and {} second-layer inbound edge(s), but none connected RF-flags candidates back to NewObject/class roots.", firstEdges.Length, secondEdges.Length)}

    topKey := ""
    topScore := 0
    secondScore := 0
    for key, score in scores {
        if score > topScore {
            secondScore := topScore
            topScore := score
            topKey := key
        } else if score > secondScore {
            secondScore := score
        }
    }

    if topKey = "" || (scores.Count > 1 && (topScore < 4 || topScore < secondScore * 2))
        return {Status: "AMBIGUOUS", MatchCount: evidence.Length, TargetRVA: -1, Candidates: DescribeTargetCounts(scores), Diagnostics: "Reverse RF-flags evidence did not produce a decisive target."}

    targetRVA := ("0x" topKey) + 0
    proof := StaticConstructMagicProof(pe, targetRVA)
    if !proof.Passed
        return {Status: "NOT FOUND", MatchCount: evidence.Length, TargetRVA: -1, Diagnostics: "Reverse winner failed the RF-flags fingerprint recheck."}

    ; Prefer a direct CALL edge to the winning target so the generated Lua keeps
    ; an address-decoding proof. If only helper/tail-jump evidence exists, the
    ; unique target-entry AOB is still independently supported by the reverse
    ; semantic chain and RF-flags fingerprint.
    for edge in firstEdges {
        if edge.TargetRVA = targetRVA && edge.Opcode = 0xE8 {
            result := BuildUniqueCallResult(pe, edge.SiteRVA, targetRVA,
                "PatternSleuth reverse NewObject/RF-flags evidence",
                Format("Reverse semantic walk scored target 0x{:X} at {} versus runner-up {}; {}", targetRVA, topScore, secondScore, proof.Detail))
            if result.Status = "VERIFIED" {
                result.MatchCount := evidence.Length
                result.Consensus := Format("Reverse semantic score {} vs runner-up {}.", topScore, secondScore)
                result.Diagnostics := diag
                return result
            }
        }
    }

    result := BuildUniqueDirectResult(pe, targetRVA,
        "PatternSleuth reverse NewObject/RF-flags evidence",
        Format("Reverse semantic walk scored target 0x{:X} at {} versus runner-up {}; {}", targetRVA, topScore, secondScore, proof.Detail))
    if result.Status = "STRONG" {
        result.Status := "VERIFIED"
        result.MatchCount := evidence.Length
        result.Consensus := Format("Reverse semantic score {} vs runner-up {}.", topScore, secondScore)
        result.Validation := proof.Detail " Reverse NewObject/class-root evidence independently converged on the same unique target entry."
        result.Diagnostics := diag
    }
    return result
}

IsUsableResolverResult(result) {
    return IsObject(result) && (result.Status = "VERIFIED" || result.Status = "STRONG" || result.Status = "UNVERIFIED")
}

RootFunctionsForStringRVAs(pe, stringRVAs) {
    ; PatternSleuth's scan_xrefs does more than direct RIP-relative LEAs: it first
    ; finds absolute 64-bit pointers to the string and then accepts LEAs to those
    ; pointer slots too. Several optimized UE5 builds reach diagnostic strings
    ; through a pointer table, so direct-only XREF discovery can miss NewObject.
    roots := Map()
    seenTargets := Map()
    for stringRVA in stringRVAs {
        CheckScanCancelled(true)
        targets := [stringRVA, stringRVA + 2]

        for absoluteTargetRVA in [stringRVA, stringRVA + 2] {
            absoluteVA := pe.ImageBase + absoluteTargetRVA
            for ptrRef in FindAbsolute64Refs(pe, absoluteVA, 256) {
                key := Format("{:X}", ptrRef.RVA)
                if !seenTargets.Has(key) {
                    seenTargets[key] := true
                    targets.Push(ptrRef.RVA)
                }
            }
        }

        for targetRVA in targets {
            key := Format("{:X}", targetRVA)
            if seenTargets.Has("lea|" key)
                continue
            seenTargets["lea|" key] := true
            for ref in FindRipLeaRefsAny(pe, targetRVA) {
                fn := FindRuntimeFunction(pe, ref.RVA)
                if fn.BeginRVA >= 0
                    roots[Format("{:X}", fn.BeginRVA)] := fn
            }
        }
    }
    return roots
}

FindNewObjectFunctionFromClassRoots(pe, classRoots, newRoots) {
    if classRoots.Count = 0 || newRoots.Count = 0
        return -1

    current := classRoots
    Loop 3 {
        for key, fn in current {
            if FunctionIsOrCallsNewObjectRoot(pe, fn, newRoots)
                return fn.BeginRVA
        }

        if A_Index >= 3
            break
        SetResolverProgressAtLeast(0.63 + (A_Index - 1) * 0.04, "StaticConstructObject: climbing semantic callers...")
        current := FindCallerFunctionsForTargets(pe, current)
        if current.Count = 0
            break
    }
    return -1
}

FunctionIsOrCallsNewObjectRoot(pe, fn, newRoots) {
    key := Format("{:X}", fn.BeginRVA)
    if newRoots.Has(key)
        return true

    for call in FindCallTargetsInFunction(pe, fn.BeginRVA, fn.EndRVA, 256, true) {
        target := FollowSimpleJumpThunk(pe, call.TargetRVA)
        targetFn := FindRuntimeFunction(pe, target)
        if targetFn.BeginRVA >= 0 && newRoots.Has(Format("{:X}", targetFn.BeginRVA))
            return true
    }
    return false
}

ResolveStaticFromRootFunctions(pe, roots, magicFunctions, diag) {
    counts := Map()
    evidence := []
    visitedFns := Map()
    rootIndex := 0

    for key, root in roots {
        rootIndex += 1
        CheckScanCancelled(true)
        if roots.Count > 0
            SetResolverProgressAtLeast(0.78 + Min(0.12, (rootIndex / roots.Count) * 0.12), "StaticConstructObject: checking RF-flags call graph...")

        for call in FindCallTargetsInFunction(pe, root.BeginRVA, root.EndRVA, 512, true) {
            target := FollowJumpThunkChain(pe, call.TargetRVA)
            if magicFunctions.Has(Format("{:X}", target))
                AddStaticEvidence(counts, evidence, call.CallRVA, call.TargetRVA, target, 1, call.Opcode)

            ; PatternSleuth checks one layer deeper as well.
            fn2 := FindRuntimeFunction(pe, target)
            if fn2.BeginRVA < 0
                continue
            vkey := Format("{:X}", fn2.BeginRVA)
            if visitedFns.Has(vkey)
                continue
            visitedFns[vkey] := true

            for inner in FindCallTargetsInFunction(pe, fn2.BeginRVA, fn2.EndRVA, 512, true) {
                innerTarget := FollowJumpThunkChain(pe, inner.TargetRVA)
                if magicFunctions.Has(Format("{:X}", innerTarget))
                    AddStaticEvidence(counts, evidence, inner.CallRVA, inner.TargetRVA, innerTarget, 2, inner.Opcode)
            }
        }
    }

    if counts.Count = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, Diagnostics: diag}

    topKey := ""
    topCount := 0
    secondCount := 0
    total := 0
    for key, count in counts {
        total += count
        if count > topCount {
            secondCount := topCount
            topCount := count
            topKey := key
        } else if count > secondCount {
            secondCount := count
        }
    }

    targetRVA := ("0x" topKey) + 0
    if counts.Count > 1 && (topCount < 2 || topCount < secondCount * 2)
        return {Status: "AMBIGUOUS", MatchCount: total, TargetRVA: -1, Candidates: DescribeTargetCounts(counts), Diagnostics: diag}

    proof := StaticConstructMagicProof(pe, targetRVA)
    if !proof.Passed
        return {Status: "NOT FOUND", MatchCount: total, TargetRVA: -1, Diagnostics: diag " Winning target lost its RF-flags proof."}

    for ev in evidence {
        if ev.TargetRVA = targetRVA && ev.DirectTarget = targetRVA && ev.Opcode = 0xE8 {
            result := BuildUniqueCallResult(pe, ev.CallRVA, targetRVA,
                "PatternSleuth semantic NewObject/RF-flags fallback",
                diag " " proof.Detail)
            if result.Status = "VERIFIED" {
                result.MatchCount := total
                result.Consensus := Format("Target 0x{:X} received {} semantic call-graph hit(s); runner-up support {}.", targetRVA, topCount, secondCount)
                result.Diagnostics := diag
                return result
            }
        }
    }

    result := BuildUniqueDirectResult(pe, targetRVA,
        "PatternSleuth semantic NewObject/RF-flags fallback",
        diag " " proof.Detail " Target-entry AOB is unique.")
    if result.Status = "STRONG" {
        result.Status := "VERIFIED"
        result.MatchCount := total
        result.Consensus := Format("Target 0x{:X} received {} semantic call-graph hit(s); runner-up support {}.", targetRVA, topCount, secondCount)
        result.Diagnostics := diag
    }
    return result
}

AddStaticEvidence(counts, evidence, callRVA, directTarget, finalTarget, depth, opcode := 0xE8) {
    key := Format("{:X}", finalTarget)
    counts[key] := counts.Get(key, 0) + 1
    evidence.Push({CallRVA: callRVA, DirectTarget: directTarget, TargetRVA: finalTarget, Depth: depth, Opcode: opcode})
}

FindCallTargetsInFunction(pe, beginRVA, endRVA, maxCalls := 512, includeJumps := false) {
    ; PatternSleuth's find_calls treats near CALLs and unconditional branches as
    ; outgoing control-flow edges. SCO is sometimes reached through a tail JMP,
    ; so an E8-only byte walk can miss the exact edge even when the target and
    ; RF-flags fingerprint are both present.
    out := []
    beginRaw := RvaToRaw(pe, beginRVA)
    endRaw := RvaToRaw(pe, endRVA - 1)
    if beginRaw < 0 || endRaw < beginRaw
        return out
    endRaw += 1

    opcodes := includeJumps ? [0xE8, 0xE9] : [0xE8]
    lastYield := A_TickCount
    for opcode in opcodes {
        searchPtr := pe.Data.Ptr + beginRaw
        searchEndPtr := pe.Data.Ptr + endRaw
        while searchPtr < searchEndPtr && out.Length < maxCalls {
            CooperativeScanYield(&lastYield)
            remaining := searchEndPtr - searchPtr
            foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", opcode, "UPtr", remaining, "Ptr")
            if !foundPtr
                break
            raw := foundPtr - pe.Data.Ptr
            if raw + 5 <= endRaw {
                siteRVA := RawToRva(pe, raw)
                target := ResolveRel32AtRaw(pe, raw)
                if target >= 0 && IsExecutableRVA(pe, target) {
                    targetFn := FindRuntimeFunction(pe, target)
                    ; Ignore branches that remain inside this same root function.
                    if targetFn.BeginRVA < 0 || targetFn.BeginRVA != beginRVA
                        out.Push({CallRVA: siteRVA, TargetRVA: target, Opcode: opcode})
                }
            }
            searchPtr := foundPtr + 1
        }
        if out.Length >= maxCalls
            break
    }
    return out
}

FollowSimpleJumpThunk(pe, targetRVA) {
    return FollowJumpThunkChain(pe, targetRVA, 1)
}

FollowJumpThunkChain(pe, targetRVA, maxDepth := 4) {
    current := targetRVA
    seen := Map()
    Loop maxDepth {
        key := Format("{:X}", current)
        if seen.Has(key)
            break
        seen[key] := true
        raw := RvaToRaw(pe, current)
        if raw < 0
            break
        op := ByteAt(pe, raw)
        next := -1
        if op = 0xE9 {
            next := ResolveRel32AtRaw(pe, raw)
        } else if op = 0xEB {
            disp8 := NumGet(pe.Data, raw + 1, "Char")
            next := current + 2 + disp8
        } else if op = 0xFF && ByteAt(pe, raw + 1) = 0x25 {
            disp := NumGet(pe.Data, raw + 2, "Int")
            ptrRVA := current + 6 + disp
            ptrRaw := RvaToRaw(pe, ptrRVA)
            if ptrRaw >= 0 && ptrRaw + 8 <= pe.Size {
                absolute := NumGet(pe.Data, ptrRaw, "UInt64")
                if absolute >= pe.ImageBase
                    next := absolute - pe.ImageBase
            }
        }
        if next < 0 || !IsExecutableRVA(pe, next)
            break
        current := next
    }
    return current
}

FindStaticConstructMagicFunctions(pe) {
    if HasProp(pe, "StaticMagicFunctionCache")
        return pe.StaticMagicFunctionCache
    out := Map()
    lastYield := A_TickCount
    for section in pe.Sections {
        if !section.Executable || section.RawSize < 4
            continue
        secStart := section.RawPtr
        secEnd := section.RawPtr + section.RawSize
        searchPtr := pe.Data.Ptr + secStart
        searchEndPtr := pe.Data.Ptr + secEnd
        while searchPtr < searchEndPtr {
            CooperativeScanYield(&lastYield)
            remaining := searchEndPtr - searchPtr
            foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", 0x80, "UPtr", remaining, "Ptr")
            if !foundPtr
                break
            raw := foundPtr - pe.Data.Ptr
            if raw + 4 <= secEnd
                && ByteAt(pe, raw + 1) = 0x00
                && ByteAt(pe, raw + 2) = 0x00
                && ByteAt(pe, raw + 3) = 0x10 {
                rva := section.VA + (raw - section.RawPtr)
                fn := FindRuntimeFunction(pe, rva)
                if fn.BeginRVA >= 0
                    out[Format("{:X}", fn.BeginRVA)] := fn
            }
            searchPtr := foundPtr + 1
        }
    }
    CheckScanCancelled(true)
    pe.StaticMagicFunctionCache := out
    return out
}

StaticConstructMagicProof(pe, targetRVA) {
    if !HasProp(pe, "StaticMagicCache")
        pe.StaticMagicCache := Map()
    key := Format("{:X}", targetRVA)
    if pe.StaticMagicCache.Has(key)
        return pe.StaticMagicCache[key]

    result := ""
    if targetRVA < 0 || !IsExecutableRVA(pe, targetRVA) {
        result := {Passed: false, Detail: "Target is not executable."}
    } else {
        ; Prefer exact runtime-function ownership when unwind metadata agrees.
        fn := FindRuntimeFunction(pe, targetRVA)
        if IsObject(fn) && fn.BeginRVA >= 0 {
            leafRaw := RvaToRaw(pe, targetRVA)
            endRaw := RvaToRaw(pe, fn.EndRVA - 1)
            if leafRaw >= 0 && endRaw >= leafRaw {
                length := Min(endRaw - leafRaw + 1, 0x2000)
                if ContainsBytes(pe, leafRaw, length, [0x80, 0x00, 0x00, 0x10]) {
                    result := {
                        Passed: true,
                        Detail: (fn.BeginRVA = targetRVA
                            ? "Runtime-function entry"
                            : "Executable target within its runtime-function range")
                            " contains StaticConstructObject_Internal's distinctive 0x10000080 RF-flags test immediate."
                    }
                }
            }
        }

        ; Chained/unusual Win64 unwind layouts can make the canonical root differ
        ; from a valid direct call target. Do not discard otherwise strong native
        ; semantic evidence solely for that metadata shape. Revalidate a bounded
        ; code neighborhood beginning at the exact candidate address.
        if !IsObject(result) || !result.Passed {
            raw := RvaToRaw(pe, targetRVA)
            if raw >= 0 {
                length := Min(0x2000, pe.Size - raw)
                if length > 0 && ContainsBytes(pe, raw, length, [0x80, 0x00, 0x00, 0x10])
                    result := {Passed: true, Detail: "Bounded code at the exact executable target contains StaticConstructObject_Internal's distinctive 0x10000080 RF-flags test immediate."}
            }
        }

        if !IsObject(result) || !result.Passed
            result := {Passed: false, Detail: "Executable target did not contain the 0x10000080 RF-flags immediate within the bounded validation window."}
    }

    pe.StaticMagicCache[key] := result
    return result
}

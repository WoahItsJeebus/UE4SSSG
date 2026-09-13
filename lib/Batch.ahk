; Sequential bulk-scan UI/orchestration. Uses the same resolver pipeline as the
; Single tab, but does not overwrite the last Single scan/generation state.

global BATCH_QUEUE_LIMIT := 50
global BatchQueue := []
global BatchGameTitles := Map()
global IsBatchScanning := false
global BatchTargetResults := Map()
global BatchTargetStates := Map()

global BatchLV, BatchAddBtn, BatchAddRecentBtn, BatchSteamLibraryBtn, BatchRemoveBtn, BatchClearBtn, BatchScanBtn, BatchOpenReportBtn, BatchStatusText, BatchTargetLV, BatchTargetLabel

LoadBatchQueue() {
    global BatchQueue, BatchGameTitles, BATCH_QUEUE_LIMIT, RecentSettingsFile
    BatchQueue := []
    BatchGameTitles := Map()
    seen := Map()

    Loop BATCH_QUEUE_LIMIT {
        path := ""
        try path := IniRead(RecentSettingsFile, "Batch", "Path" A_Index, "")
        catch
            path := ""
        path := Trim(path, ' "')
        if path = "" || !FileExist(path) || !RegExMatch(path, "i)\.exe$")
            continue
        key := NormalizeExePath(path)
        if seen.Has(key)
            continue
        seen[key] := true
        BatchQueue.Push(path)
        title := ""
        try title := IniRead(RecentSettingsFile, "Batch", "Game" A_Index, "")
        catch
            title := ""
        BatchGameTitles[key] := title != "" ? title : FriendlyGameNameFromExe(path)
    }
}

SaveBatchQueue() {
    global BatchQueue, BatchGameTitles, BATCH_QUEUE_LIMIT, RecentSettingsDir, RecentSettingsFile
    try DirCreate(RecentSettingsDir)
    Loop BATCH_QUEUE_LIMIT {
        value := A_Index <= BatchQueue.Length ? BatchQueue[A_Index] : ""
        try IniWrite(value, RecentSettingsFile, "Batch", "Path" A_Index)
        title := ""
        if A_Index <= BatchQueue.Length {
            key := NormalizeExePath(BatchQueue[A_Index])
            title := BatchGameTitles.Has(key) ? BatchGameTitles[key] : FriendlyGameNameFromExe(BatchQueue[A_Index])
        }
        try IniWrite(title, RecentSettingsFile, "Batch", "Game" A_Index)
    }
}

ClearBatchTargetDetails(message := "Target details: select a Batch executable") {
    global BatchTargetLV, BatchTargetLabel
    if IsSet(BatchTargetLV) && IsObject(BatchTargetLV)
        BatchTargetLV.Delete()
    if IsSet(BatchTargetLabel) && IsObject(BatchTargetLabel)
        BatchTargetLabel.Value := message
}

BatchAddTargetDetailRow(resolver, result := "") {
    global BatchTargetLV
    if !IsSet(BatchTargetLV) || !IsObject(BatchTargetLV)
        return

    requirement := resolver.Required ? "Required" : "Optional"
    if !IsObject(result) {
        BatchTargetLV.Add("", resolver.File, requirement, "NOT SCANNED", "-", "-", "-", "-", "-")
        return
    }

    status := result.Status
    matchesText := result.MatchCount > 0 ? result.MatchCount : "-"
    rvaText := result.TargetRVA >= 0 ? Format("0x{:X}", result.TargetRVA) : "-"
    sourceText := HasProp(result, "Source") ? ShortSource(result.Source) : "-"
    tierText := HasProp(result, "TierLabel") ? result.TierLabel : "-"
    aobText := HasProp(result, "AOB") && result.AOB != "" ? result.AOB : "-"
    iconIndex := StatusIconFor(status)

    if iconIndex > 0
        BatchTargetLV.Add("Icon" iconIndex, resolver.File, requirement, status, tierText, matchesText, rvaText, sourceText, aobText)
    else
        BatchTargetLV.Add("", resolver.File, requirement, status, tierText, matchesText, rvaText, sourceText, aobText)
}

RefreshBatchTargetDetails(row := 0) {
    global BatchQueue, BatchLV, BatchTargetLV, BatchTargetLabel, BatchTargetResults, BatchTargetStates, ResolverDB
    if !IsSet(BatchTargetLV) || !IsObject(BatchTargetLV)
        return

    if row <= 0 && IsSet(BatchLV) && IsObject(BatchLV)
        row := BatchLV.GetNext(0)
    if row < 1 || row > BatchQueue.Length {
        ClearBatchTargetDetails()
        return
    }

    path := BatchQueue[row]
    key := NormalizeExePath(path)
    state := BatchTargetStates.Has(key) ? BatchTargetStates[key] : "Queued / not scanned"
    title := BatchGetGameTitle(path)
    SplitPath(path, &fileName)
    BatchTargetLabel.Value := "Target details: " title " — " fileName " — " state
    BatchTargetLV.Delete()

    if BatchTargetResults.Has(key) {
        for entry in BatchTargetResults[key]
            BatchAddTargetDetailRow(entry.Resolver, entry.Result)
        return
    }

    ; Always show the complete target inventory even before a scan finishes so
    ; selecting a queued/failed/skipped executable still explains what the 13
    ; checks are rather than presenting an empty details pane.
    for resolver in ResolverDB
        BatchAddTargetDetailRow(resolver)
}

BatchSelectionChanged(LV, row, selected) {
    if selected {
        RefreshBatchTargetDetails(row)
        return
    }
    selectedRow := LV.GetNext(0)
    if selectedRow > 0
        RefreshBatchTargetDetails(selectedRow)
    else
        ClearBatchTargetDetails()
}

BatchRefreshDetailsIfSelected(row) {
    global BatchLV
    if !IsSet(BatchLV) || !IsObject(BatchLV)
        return
    selectedRow := BatchLV.GetNext(0)
    if selectedRow = row
        RefreshBatchTargetDetails(row)
}

RefreshBatchQueueUI() {
    global BatchQueue, BatchLV, BatchStatusText, BatchTargetStates
    if !IsSet(BatchLV) || !IsObject(BatchLV)
        return

    BatchLV.Delete()
    for path in BatchQueue {
        key := NormalizeExePath(path)
        if !BatchTargetStates.Has(key)
            BatchTargetStates[key] := "Queued / not scanned"
        BatchLV.Add("", BatchGetGameTitle(path), path, "Not checked", "Queued", "-", "-", "-", "-", "-")
    }
    ClearBatchTargetDetails()

    if BatchQueue.Length > 0
        BatchStatusText.Value := BatchQueue.Length " executable(s) queued. Queue is saved between releases."
    else
        BatchStatusText.Value := "Add executables, use Add Recent, or drop EXEs onto this tab."
}

BatchAddExecutables(*) {
    global IsScanning
    if IsScanning
        return

    selected := FileSelect("M3", , "Select Win64 game executables", "Executables (*.exe)")
    if !IsObject(selected) {
        if selected != ""
            AddPathToBatch(selected)
        return
    }
    for path in selected
        AddPathToBatch(path)
}

BatchAddRecent(*) {
    global IsScanning, RecentPaths, APP_NAME
    if IsScanning
        return
    if RecentPaths.Length = 0 {
        MsgBox("No recent executable scans have been saved yet.", APP_NAME, "Icon!")
        return
    }

    added := 0
    for path in RecentPaths {
        if AddPathToBatch(path)
            added += 1
    }
    if added = 0
        MsgBox("Every recent executable is already in the Batch queue.", APP_NAME, "Iconi")
}

BatchAddSteamLibraryGames(*) {
    global IsScanning, BatchStatusText, APP_NAME
    if IsScanning
        return

    BatchStatusText.Value := "Inspecting installed Steam libraries for local Unreal Engine evidence..."
    Sleep(-1)
    discovery := SteamLibrary_DiscoverUnrealExecutables()
    if !discovery.Success {
        detail := discovery.Notes.Length > 0 ? "`n`n" discovery.Notes[1] : ""
        BatchStatusText.Value := "Steam library discovery could not locate Steam."
        MsgBox("Steam library discovery could not locate a local Steam installation." detail, APP_NAME, "Icon!")
        return
    }

    added := 0
    alreadyQueued := 0
    for candidate in discovery.Candidates {
        engineLabel := candidate.Engine " (" StrLower(candidate.Confidence) ")"
        if AddPathToBatch(candidate.Path, candidate.Name, engineLabel) {
            added += 1
            Log("[STEAM] Queued Unreal Engine: " candidate.Name " (App " candidate.AppId ") | " candidate.Path)
        } else {
            alreadyQueued += 1
        }
    }

    summary := Format(
        "Steam libraries: {} | installed apps: {} | confirmed Unreal: {} | added: {} | already queued: {}",
        discovery.Libraries.Length, discovery.InstalledApps, discovery.UnrealApps, added, alreadyQueued)
    BatchStatusText.Value := summary ". Click Scan Batch to scan the queue."
    Log("[STEAM] " summary)
    for note in discovery.Notes
        Log("[STEAM] " note)

    if discovery.UnrealApps = 0 {
        MsgBox(
            "No locally confirmed Unreal Engine game executables were found in the installed Steam libraries.`n`n"
            "This uses SteamDB-style filename/path evidence locally. Games with missing, mixed, or unknown evidence are not queued automatically and can still be added with Add EXEs...",
            APP_NAME,
            "Icon!"
        )
    }
}

BatchGetGameTitle(path) {
    global BatchGameTitles
    key := NormalizeExePath(path)
    if BatchGameTitles.Has(key) && BatchGameTitles[key] != ""
        return BatchGameTitles[key]

    title := FriendlyGameNameFromExe(path)
    BatchGameTitles[key] := title
    return title
}

AddPathToBatch(path, gameTitle := "", engineLabel := "Not checked") {
    global BatchQueue, BatchGameTitles, BatchLV, BatchStatusText, BatchTargetStates
    path := Trim(path, ' "')
    if path = "" || !FileExist(path) || !RegExMatch(path, "i)\.exe$")
        return false

    key := NormalizeExePath(path)
    for index, existing in BatchQueue {
        if NormalizeExePath(existing) = key {
            if gameTitle != ""
                BatchGameTitles[key] := gameTitle
            if IsSet(BatchLV) && IsObject(BatchLV)
                BatchLV.Modify(index, "", BatchGetGameTitle(path), path, engineLabel)
            SaveBatchQueue()
            return false
        }
    }

    BatchQueue.Push(path)
    BatchGameTitles[key] := gameTitle != "" ? gameTitle : FriendlyGameNameFromExe(path)
    BatchTargetStates[key] := "Queued / not scanned"
    BatchLV.Add("", BatchGetGameTitle(path), path, engineLabel, "Queued", "-", "-", "-", "-", "-")
    SaveBatchQueue()
    BatchStatusText.Value := BatchQueue.Length " executable(s) queued. Queue is saved between releases."
    return true
}

BatchRemoveSelected(*) {
    global IsScanning, BatchQueue, BatchGameTitles, BatchLV, BatchStatusText, BatchTargetResults, BatchTargetStates
    if IsScanning
        return

    selected := Map()
    row := 0
    while row := BatchLV.GetNext(row)
        selected[row] := true

    if selected.Count = 0
        return

    count := BatchLV.GetCount()
    Loop count {
        index := count - A_Index + 1
        if selected.Has(index) {
            path := BatchQueue[index]
            key := NormalizeExePath(path)
            if BatchTargetResults.Has(key)
                BatchTargetResults.Delete(key)
            if BatchTargetStates.Has(key)
                BatchTargetStates.Delete(key)
            if BatchGameTitles.Has(key)
                BatchGameTitles.Delete(key)
            BatchLV.Delete(index)
            BatchQueue.RemoveAt(index)
        }
    }
    SaveBatchQueue()
    ClearBatchTargetDetails()
    BatchStatusText.Value := BatchQueue.Length " executable(s) queued. Queue is saved between releases."
}

BatchClearQueue(*) {
    global IsScanning, BatchQueue, BatchGameTitles, BatchLV, BatchStatusText, BatchTargetResults, BatchTargetStates
    if IsScanning
        return
    BatchQueue := []
    BatchGameTitles := Map()
    BatchTargetResults := Map()
    BatchTargetStates := Map()
    BatchLV.Delete()
    ClearBatchTargetDetails()
    SaveBatchQueue()
    BatchStatusText.Value := "Add executables, use Add Recent, or drop EXEs onto this tab."
}

BatchOpenInSingle(LV, row) {
    global BatchQueue, ExeEdit, MainTabs, IsScanning
    if IsScanning || row < 1 || row > BatchQueue.Length
        return
    ExeEdit.Value := BatchQueue[row]
    InvalidateScanState()
    ScheduleEngineStatusRefresh()
    UE4SS_RefreshButtons()
    MainTabs.Choose(1)
}

BatchOpenSelectedReport(*) {
    global BatchQueue, BatchLV, IsScanning, APP_NAME
    if IsScanning
        return

    row := BatchLV.GetNext(0)
    if row < 1 || row > BatchQueue.Length {
        MsgBox("Select a Batch row first.", APP_NAME, "Icon!")
        return
    }

    path := BatchQueue[row]
    reportPath := BuildScanReportPath(path)
    if !FileExist(reportPath) {
        MsgBox("No scan report exists for the selected executable yet.`n`n" reportPath, APP_NAME, "Icon!")
        return
    }

    try Run('"' reportPath '"')
    catch as err
        MsgBox("The report exists, but Windows could not open it.`n`n" err.Message, APP_NAME, "Iconx")
}

BatchScanOrCancel(*) {
    global IsScanning, IsBatchScanning, BatchScanQueued

    if IsBatchScanning {
        RequestScanCancellation(true)
        return
    }
    if IsScanning || BatchScanQueued
        return

    ; As with the Single Scan button, defer the long-running batch worker until
    ; after this button callback returns. That makes a later click able to enter
    ; this handler and cancel the active batch immediately.
    BatchScanQueued := true
    SetTimer(RunQueuedBatchScan, -1)
}

RunQueuedBatchScan() {
    global BatchScanQueued
    BatchScanQueued := false
    StartBatchScan()
}

SetBatchQueueControlsEnabled(enabled) {
    global BatchAddBtn, BatchAddRecentBtn, BatchSteamLibraryBtn, BatchRemoveBtn, BatchClearBtn, BatchOpenReportBtn
    BatchAddBtn.Enabled := enabled
    BatchAddRecentBtn.Enabled := enabled
    BatchSteamLibraryBtn.Enabled := enabled
    BatchRemoveBtn.Enabled := enabled
    BatchClearBtn.Enabled := enabled
    BatchOpenReportBtn.Enabled := enabled
}

CaptureSingleScanState() {
    global LastOutputDir, LastScanPath, LastScanResults, LastScanReport, LastReportPath, LastLocalCorpus
    return {
        OutputDir: LastOutputDir,
        Path: LastScanPath,
        Results: LastScanResults,
        Report: LastScanReport,
        ReportPath: LastReportPath,
        Corpus: LastLocalCorpus
    }
}

RestoreSingleScanState(state) {
    global LastOutputDir, LastScanPath, LastScanResults, LastScanReport, LastReportPath, LastLocalCorpus, GenerateBtn, OpenReportBtn, ExeEdit
    LastOutputDir := state.OutputDir
    LastScanPath := state.Path
    LastScanResults := state.Results
    LastScanReport := state.Report
    LastReportPath := state.ReportPath
    LastLocalCorpus := state.Corpus
    samePath := LastScanPath != "" && NormalizeExePath(ExeEdit.Value) = NormalizeExePath(LastScanPath)
    GenerateBtn.Enabled := (samePath && CountGeneratable(LastScanResults) > 0)
    OpenReportBtn.Enabled := (samePath && LastReportPath != "" && FileExist(LastReportPath))
}

StartBatchScan() {
    global BatchQueue, BatchLV, BatchStatusText, BatchScanBtn, IsBatchScanning, ScanCancelled
    global BatchTargetResults, BatchTargetStates
    global LogEdit, StatusBar, ExeEdit, APP_NAME

    if BatchQueue.Length = 0 {
        MsgBox("Add at least one executable to the Batch queue first.", APP_NAME, "Icon!")
        return
    }

    preflight := EngineDetect_BatchPreflight(BatchQueue)
    if preflight.Cancelled {
        BatchStatusText.Value := "Batch cancelled at engine preflight."
        StatusBar.SetText("Batch engine preflight cancelled")
        return
    }

    ; Surface the local engine classification before expensive resolver work.
    Loop BatchQueue.Length {
        d := preflight.Detections[A_Index]
        path := BatchQueue[A_Index]
        BatchLV.Modify(A_Index, "", BatchGetGameTitle(path), path, EngineDetect_CompactLabel(d), "Queued", "-", "-", "-", "-", "-")
    }

    savedState := CaptureSingleScanState()
    originalPath := ExeEdit.Value
    IsBatchScanning := true
    ScanCancelled := false
    SetBatchScanButtonText("Cancel")
    SetBatchQueueControlsEnabled(false)
    LogEdit.Value := ""
    Log("Batch scan started: " BatchQueue.Length " executable(s).")
    Log("")

    total := BatchQueue.Length
    finished := 0
    failed := 0
    skipped := 0
    cancelled := false
    batchStart := A_TickCount

    ; Reset previous batch results before a rerun so stale target-coverage rows are never
    ; mistaken for the current pass while later entries are still queued.
    BatchTargetResults := Map()
    BatchTargetStates := Map()
    Loop total {
        path := BatchQueue[A_Index]
        key := NormalizeExePath(path)
        BatchTargetStates[key] := "Queued / not scanned"
        d := preflight.Detections[A_Index]
        BatchLV.Modify(A_Index, "", BatchGetGameTitle(path), path, EngineDetect_CompactLabel(d), "Queued", "-", "-", "-", "-", "-")
    }
    RefreshBatchTargetDetails()

    Loop total {
        if ScanCancelled {
            cancelled := true
            break
        }

        index := A_Index
        path := BatchQueue[index]
        d := preflight.Detections[index]
        engineLabel := EngineDetect_CompactLabel(d)
        key := NormalizeExePath(path)
        if preflight.Skip.Has(key) {
            skipped += 1
            BatchTargetStates[key] := "Skipped by engine preflight"
            BatchLV.Modify(index, "", BatchGetGameTitle(path), path, engineLabel, "Skipped", "-", "-", "-", "-", "-")
            BatchRefreshDetailsIfSelected(index)
            Log("[ENGINE] Batch skipped by preflight: " path " | " engineLabel)
            continue
        }

        BatchTargetStates[key] := "Scanning..."
        BatchLV.Modify(index, "", BatchGetGameTitle(path), path, engineLabel, "Scanning...", "-", "-", "-", "-", "-")
        BatchRefreshDetailsIfSelected(index)
        BatchStatusText.Value := Format("Scanning {} of {}: {}", index, total, path)
        StatusBar.SetText(Format("Batch scan {} of {}", index, total))
        Sleep(-1)
        if ScanCancelled {
            cancelled := true
            BatchTargetStates[key] := "Cancelled"
            BatchLV.Modify(index, "", BatchGetGameTitle(path), path, engineLabel, "Cancelled", "-", "-", "-", "-", "-")
            BatchRefreshDetailsIfSelected(index)
            break
        }

        summary := ScanExe(path, true)
        if IsObject(summary) && HasProp(summary, "Cancelled") && summary.Cancelled {
            cancelled := true
            BatchTargetStates[key] := "Cancelled"
            BatchLV.Modify(index, "", BatchGetGameTitle(path), path, engineLabel, "Cancelled", "-", "-", "-", "-", FormatResolverDuration(summary.ElapsedMs))
            BatchRefreshDetailsIfSelected(index)
            break
        }

        if !IsObject(summary) || !HasProp(summary, "Success") || !summary.Success {
            failed += 1
            BatchTargetStates[key] := "Scan failed"
            elapsed := IsObject(summary) && HasProp(summary, "ElapsedMs") ? FormatResolverDuration(summary.ElapsedMs) : "-"
            BatchLV.Modify(index, "", BatchGetGameTitle(path), path, engineLabel, "Failed", "-", "-", "-", "-", elapsed)
            BatchRefreshDetailsIfSelected(index)
            continue
        }

        finished += 1
        missCount := summary.NotFound + summary.Ambiguous
        stateText := summary.RequiredReady "/" summary.RequiredTotal " REQ | " summary.OptionalReady "/" summary.OptionalTotal " OPT"
        if summary.Strong > 0
            stateText .= " +" summary.Strong " STRONG"
        if HasProp(summary, "Entries")
            BatchTargetResults[key] := summary.Entries
        BatchTargetStates[key] := stateText
        BatchLV.Modify(index, "", BatchGetGameTitle(path), path, engineLabel, stateText, summary.Verified, summary.Strong, summary.Unverified, missCount, FormatResolverDuration(summary.ElapsedMs))
        BatchRefreshDetailsIfSelected(index)
    }

    IsBatchScanning := false
    SetBatchScanButtonText("Scan Batch")
    SetBatchQueueControlsEnabled(true)
    ExeEdit.Value := originalPath
    ScheduleEngineStatusRefresh()
    RestoreSingleScanState(savedState)

    elapsed := A_TickCount - batchStart
    if cancelled {
        BatchStatusText.Value := Format("Batch cancelled after {} completed scan(s).", finished)
        StatusBar.SetText("Batch scan cancelled")
        Log("")
        Log("Batch cancelled after " finished " completed scan(s).")
    } else {
        BatchStatusText.Value := Format("Batch complete: {} completed, {} skipped, {} failed | {}", finished, skipped, failed, FormatResolverDuration(elapsed))
        StatusBar.SetText(Format("Batch complete: {} scanned, {} skipped", finished, skipped))
        Log("")
        Log(Format("Batch complete: {} completed, {} skipped, {} failed | {}", finished, skipped, failed, FormatResolverDuration(elapsed)))
    }
}

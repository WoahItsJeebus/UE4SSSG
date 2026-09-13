; Progress layer for UE4SS Signature Generator.
; ETA intentionally omitted: resolver stage duration varies too much between builds.

StartScanProgress() {
    global ScanStartTick, ScanProgressPct, ScanProgressStage
    ScanStartTick := A_TickCount
    ScanProgressPct := 0.0
    ScanProgressStage := "Starting scan..."
    ProgressBar.Value := 0
    ProgressText.Value := "Elapsed: 00:00   |   0%   |   Starting scan..."
    SetTimer(ScanUiTick, 250)
}

StopScanProgress() {
    global ScanStartTick, ScanProgressPct, ScanProgressStage
    SetTimer(ScanUiTick, 0)
    if ScanStartTick <= 0
        return
    elapsed := (A_TickCount - ScanStartTick) / 1000.0
    pct := Min(100.0, Max(0.0, ScanProgressPct))
    suffix := pct >= 99.9 ? "Complete" : ScanProgressStage
    ProgressText.Value := "Elapsed: " FormatScanDuration(elapsed)
        . "   |   " Format("{:.0f}%", pct)
        . "   |   " suffix
}

SetScanProgress(percent, stage := "") {
    global ScanProgressPct, ScanProgressStage
    percent := Min(100.0, Max(0.0, percent + 0.0))
    ScanProgressPct := percent
    if stage != ""
        ScanProgressStage := stage
    ProgressBar.Value := Round(percent)
    ScanUiTick()
}

SetResolverProgressWindow(basePercent, spanPercent, resolverName) {
    global ActiveProgressBase, ActiveProgressSpan, ActiveResolverName
    ActiveProgressBase := basePercent + 0.0
    ActiveProgressSpan := spanPercent + 0.0
    ActiveResolverName := resolverName
    SetResolverProgress(0.0, "Scanning " resolverName "...")
}

SetResolverProgress(fraction, detail := "") {
    global ActiveProgressBase, ActiveProgressSpan, ActiveResolverName
    fraction := Min(1.0, Max(0.0, fraction + 0.0))
    stage := detail != "" ? detail : "Scanning " ActiveResolverName "..."
    SetScanProgress(ActiveProgressBase + ActiveProgressSpan * fraction, stage)
}

SetResolverProgressAtLeast(fraction, detail := "") {
    global ActiveProgressBase, ActiveProgressSpan, ScanProgressPct, ScanProgressStage, ActiveResolverName
    fraction := Min(1.0, Max(0.0, fraction + 0.0))
    target := ActiveProgressBase + ActiveProgressSpan * fraction
    stage := detail != "" ? detail : "Scanning " ActiveResolverName "..."
    if target > ScanProgressPct
        SetScanProgress(target, stage)
    else {
        ScanProgressStage := stage
        ScanUiTick()
    }
}

ResolverProgressWeight(name) {
    switch name {
        case "FName_Constructor": return 9
        case "FName_ToString": return 9
        case "StaticConstructObject": return 17
        case "GMalloc": return 7
        case "GUObjectArray": return 8
        case "FText_Constructor": return 8
        case "GUObjectHashTables": return 7
        case "GNatives": return 4
        case "ConsoleManager": return 5
        case "GameEngineTick": return 6
        case "ProcessLocalScriptFunction": return 5
        case "ProcessInternal": return 5
        case "CallFunctionByNameWithArguments": return 5
        default: return 7
    }
}

ScanUiTick() {
    global ScanStartTick, ScanProgressPct, ScanProgressStage
    if ScanStartTick <= 0
        return
    elapsed := Max(0.0, (A_TickCount - ScanStartTick) / 1000.0)
    pct := Min(100.0, Max(0.0, ScanProgressPct))
    ProgressText.Value := "Elapsed: " FormatScanDuration(elapsed)
        . "   |   " Format("{:.0f}%", pct)
        . "   |   " ScanProgressStage
}

FormatScanDuration(seconds) {
    seconds := Max(0, Floor(seconds))
    hours := Floor(seconds / 3600)
    minutes := Floor(Mod(seconds, 3600) / 60)
    secs := Mod(seconds, 60)
    if hours > 0
        return Format("{}:{:02}:{:02}", hours, minutes, secs)
    return Format("{:02}:{:02}", minutes, secs)
}

; Human-readable high-resolution duration for resolver/report timings.
; Examples: 432ms, 44.52s, 1m 12.06s, 8m 10.27s, 1h 03m 04.50s.
FormatResolverDuration(milliseconds) {
    milliseconds := Max(0.0, milliseconds + 0.0)
    if milliseconds < 1
        return "<1ms"
    if milliseconds < 1000
        return Format("{}ms", Max(1, Round(milliseconds)))

    seconds := milliseconds / 1000.0
    if seconds < 60
        return Format("{:.2f}s", seconds)

    hours := Floor(seconds / 3600)
    minutes := Floor(Mod(seconds, 3600) / 60)
    secs := Mod(seconds, 60)

    if hours > 0
        return Format("{}h {:02}m {:05.2f}s", hours, minutes, secs)
    return Format("{}m {:05.2f}s", minutes, secs)
}

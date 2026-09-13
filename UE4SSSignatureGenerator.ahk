#Requires AutoHotkey v2.0.19
#SingleInstance Force

#Include lib\Progress.ahk
#Include lib\NativeScanner.ahk
#Include lib\ScanIndex.ahk
#Include lib\ResolverDatabase.ahk
#Include lib\Evidence.ahk
#Include lib\Recent.ahk
#Include lib\EngineDetection.ahk
#Include lib\Batch.ahk
#Include lib\SteamLibrary.ahk
#Include lib\NativeUI.ahk
#Include lib\UE4SSManager.ahk
#Include lib\Resolvers\StaticConstructObject.ahk

; UE4SS Signature Generator v0.38.0
; Reads a Win64 Unreal Engine executable, validates common UE4SS compatibility
; targets, and lets the user explicitly generate Lua signatures from VERIFIED,
; STRONG, or UNVERIFIED scan results. Non-verified generation requires an explicit
; risk confirmation. The target executable is NEVER modified.

global APP_NAME := "UE4SS Signature Generator"
global APP_VERSION := "0.38.0"
global MainGui, MainTabs, ExeEdit, RecentDDL, ResultsLV, LogEdit, StatusBar, OpenFolderCheck, ProgressBar, ProgressText, EngineStatusText
global LogDestEdit, LogDestBrowseBtn, OpenExeFolderBtn
global StatusIL, StatusIconIndex, BrowseBtn, ScanBtn, GenerateBtn, OpenReportBtn, RuntimeDumpBtn, InstallUE4SSBtn, UpdateUE4SSBtn
global BatchLV, BatchAddBtn, BatchAddRecentBtn, BatchSteamLibraryBtn, BatchRemoveBtn, BatchClearBtn, BatchScanBtn, BatchOpenReportBtn, BatchStatusText, BatchTargetLV, BatchTargetLabel
global LastOutputDir := ""
global LastScanPath := ""
global LastScanResults := []
global LastScanReport := ""
global LastReportPath := ""
global LastLocalCorpus := Map()
global IsScanning := false
global ScanCancelled := false
global SingleScanQueued := false
global SingleScanDumpOverride := ""
global BatchScanQueued := false
global ScanStartTick := 0
global ScanProgressPct := 0.0
global ScanProgressStage := "Ready"
global ActiveProgressBase := 0.0
global ActiveProgressSpan := 100.0
global ActiveResolverName := ""
global PatternCache := Map()

global ResolverDB := BuildResolverDB()

; Confidence indicators are generated in memory with native Win32 GDI. No
; bundled PNG/ICO assets are required.
statusIconPack := NativeUI_CreateStatusImageList()
StatusIL := statusIconPack["Handle"]
StatusIconIndex := statusIconPack["Indices"]

LoadLogDestinationSetting()

MainGui := Gui(, APP_NAME " v" APP_VERSION)
MainGui.SetFont("s10", "Segoe UI")
MainGui.MarginX := 14
MainGui.MarginY := 14

; The scanning workflow now has a fast single-target tab and a sequential batch
; queue. The shared log/progress area remains visible on both tabs.
MainTabs := MainGui.AddTab3("xm ym w958 h425", ["Single", "Batch"])

MainTabs.UseTab("Single")
MainGui.AddText("x28 y48", "Game executable:")
EngineStatusText := MainGui.AddText("x560 y48 w398 Right c606060", "Engine: not checked")
ExeEdit := MainGui.AddEdit("x28 y70 w640", "")
BrowseBtn := MainGui.AddButton("x+8 yp-1 w90 h25", "Browse...")
OpenExeFolderBtn := MainGui.AddButton("x+8 yp w110 h25", "Open Folder")

MainGui.AddText("x28 y104", "Recent:")
RecentDDL := MainGui.AddDropDownList("x85 yp-3 w490", [])
InstallUE4SSBtn := MainGui.AddButton("x+8 yp-1 w112 h25", "Install UE4SS")
UpdateUE4SSBtn := MainGui.AddButton("x+8 yp w112 h25 Disabled", "Update UE4SS")

MainGui.AddText("x28 y137", "Log destination:")
LogDestEdit := MainGui.AddEdit("x135 yp-3 w573 r1 -Wrap -VScroll", LogDestination)
LogDestBrowseBtn := MainGui.AddButton("x+8 yp-1 w100 h25", "Browse...")
MainGui.AddText("x+8 yp+4 w138 c606060", "blank = script folder")

ScanBtn := MainGui.AddButton("x28 y170 w90 h30 Default", "Scan")
GenerateBtn := MainGui.AddButton("x+8 yp w100 h30 Disabled", "Generate")
OpenReportBtn := MainGui.AddButton("x+8 yp w105 h30 Disabled", "Open Report")
RuntimeDumpBtn := MainGui.AddButton("x+8 yp w118 h30", "Runtime Dump...")
OpenFolderCheck := MainGui.AddCheckBox("x+12 yp+6 Checked", "Open UE4SS_Signatures after Generate")

MainGui.AddText("x28 y211", "Resolver results:")
ResultsLV := MainGui.AddListView("x28 y231 w930 h148 Grid", ["Target", "Req.", "Status", "Tier", "Matches", "Resolved RVA", "Source", "Generated AOB"])
ResultsLV.SetImageList(StatusIL)
ResultsLV.ModifyCol(1, 155)
ResultsLV.ModifyCol(2, 55)
ResultsLV.ModifyCol(3, 88)
ResultsLV.ModifyCol(4, 125)
ResultsLV.ModifyCol(5, 52)
ResultsLV.ModifyCol(6, 95)
ResultsLV.ModifyCol(7, 145)
ResultsLV.ModifyCol(8, 205)

; Legend dots are native text/GDI colors as well, keeping the release entirely
; free of external UI image assets.
MainGui.SetFont("s12")
MainGui.AddText("x28 y385 w14 h20 c2EA043 Center", "●")
MainGui.SetFont("s10")
MainGui.AddText("x+3 yp+2 w180 c606060", "Verified / strong / consensus")
MainGui.SetFont("s12")
MainGui.AddText("x+4 yp-2 w14 h20 cD29922 Center", "●")
MainGui.SetFont("s10")
MainGui.AddText("x+3 yp+2 w130 c606060", "Unverified candidate")
MainGui.SetFont("s12")
MainGui.AddText("x+4 yp-2 w14 h20 c828282 Center", "●")
MainGui.SetFont("s10")
MainGui.AddText("x+3 yp+2 w70 c606060", "Not found")
MainGui.SetFont("s12")
MainGui.AddText("x+4 yp-2 w14 h20 cCF222E Center", "●")
MainGui.SetFont("s10")
MainGui.AddText("x+3 yp+2 w120 c606060", "Ambiguous / failed")

MainTabs.UseTab("Batch")
MainGui.AddText("x28 y48", "Executables to scan:")
BatchAddBtn := MainGui.AddButton("x28 y70 w105 h27", "Add EXEs...")
BatchAddRecentBtn := MainGui.AddButton("x+8 yp w105 h27", "Add Recent")
BatchSteamLibraryBtn := MainGui.AddButton("x+8 yp w145 h27", "Scan Steam Library")
BatchRemoveBtn := MainGui.AddButton("x+8 yp w90 h27", "Remove")
BatchClearBtn := MainGui.AddButton("x+8 yp w80 h27", "Clear")
BatchScanBtn := MainGui.AddButton("x+16 yp w110 h27", "Scan Batch")
BatchOpenReportBtn := MainGui.AddButton("x+8 yp w105 h27", "Open Report")

BatchLV := MainGui.AddListView("x28 y108 w930 h116 Grid", ["Game", "Executable", "Engine", "State", "Verified", "Strong", "Unverified", "Misses", "Time"])
BatchLV.ModifyCol(1, 170)
BatchLV.ModifyCol(2, 285)
BatchLV.ModifyCol(3, 120)
BatchLV.ModifyCol(4, 105)
BatchLV.ModifyCol(5, 58)
BatchLV.ModifyCol(6, 52)
BatchLV.ModifyCol(7, 70)
BatchLV.ModifyCol(8, 55)
BatchLV.ModifyCol(9, 58)

BatchTargetLabel := MainGui.AddText("x28 y234 w930 h18 c606060", "Target details: select a Batch executable")
BatchTargetLV := MainGui.AddListView("x28 y253 w930 h126 Grid", ["Target", "Req.", "Status", "Tier", "Matches", "Resolved RVA", "Source", "Generated AOB"])
BatchTargetLV.SetImageList(StatusIL)
BatchTargetLV.ModifyCol(1, 155)
BatchTargetLV.ModifyCol(2, 55)
BatchTargetLV.ModifyCol(3, 88)
BatchTargetLV.ModifyCol(4, 125)
BatchTargetLV.ModifyCol(5, 52)
BatchTargetLV.ModifyCol(6, 95)
BatchTargetLV.ModifyCol(7, 145)
BatchTargetLV.ModifyCol(8, 205)
BatchStatusText := MainGui.AddText("x28 y389 w930 h24 c606060", "Add executables, then click Scan Batch.")

MainTabs.UseTab()

MainGui.AddText("xm y445", "Log:")
LogEdit := MainGui.AddEdit("xm y467 w958 h170 ReadOnly Wrap VScroll", "Drop or browse to a Win64 Unreal Engine game executable, then click Scan.")
ProgressBar := MainGui.AddProgress("xm y645 w958 h14 Range0-100", 0)
ProgressText := MainGui.AddText("xm y665 w958 h20 c606060", "Elapsed: 00:00   |   0%   |   Ready")
StatusBar := MainGui.AddStatusBar()
StatusBar.SetText("Ready")

; Keep the scan action visually distinctive, but leave the rest of the UI as
; plain Windows-native buttons. Confidence/status dots remain generated in memory.
NativeUI_SetButtonStockIcon(ScanBtn, SIID_FIND)
NativeUI_SetButtonStockIcon(BatchScanBtn, SIID_FIND)

BrowseBtn.OnEvent("Click", BrowseExe)
OpenExeFolderBtn.OnEvent("Click", OpenSelectedExeFolder)
LogDestBrowseBtn.OnEvent("Click", BrowseLogDestination)
LogDestEdit.OnEvent("Change", LogDestinationChanged)
ScanBtn.OnEvent("Click", ScanOrCancel)
GenerateBtn.OnEvent("Click", GenerateSignatures)
OpenReportBtn.OnEvent("Click", OpenScanReport)
RuntimeDumpBtn.OnEvent("Click", ChooseRuntimeDumpAndScan)
InstallUE4SSBtn.OnEvent("Click", (*) => UE4SS_OpenManager("install"))
UpdateUE4SSBtn.OnEvent("Click", (*) => UE4SS_OpenManager("update"))
RecentDDL.OnEvent("Change", RecentSelectionChanged)
BatchAddBtn.OnEvent("Click", BatchAddExecutables)
BatchAddRecentBtn.OnEvent("Click", BatchAddRecent)
BatchSteamLibraryBtn.OnEvent("Click", BatchAddSteamLibraryGames)
BatchRemoveBtn.OnEvent("Click", BatchRemoveSelected)
BatchClearBtn.OnEvent("Click", BatchClearQueue)
BatchScanBtn.OnEvent("Click", BatchScanOrCancel)
BatchOpenReportBtn.OnEvent("Click", BatchOpenSelectedReport)
BatchLV.OnEvent("DoubleClick", BatchOpenInSingle)
BatchLV.OnEvent("ItemSelect", BatchSelectionChanged)
ExeEdit.OnEvent("Change", ExePathChanged)
MainGui.OnEvent("DropFiles", GuiDropFiles)
MainGui.OnEvent("Close", (*) => ExitApp())

LoadRecentPaths()
RefreshRecentDDL()
RestoreMostRecentExecutable()
ScheduleEngineStatusRefresh()
UE4SS_RefreshButtons()
LoadBatchQueue()
RefreshBatchQueueUI()

MainGui.Show("w986 h715")

BrowseExe(*) {
    global IsScanning
    if IsScanning
        return

    path := FileSelect(1, , "Select a Win64 game executable", "Executables (*.exe)")
    if path != "" {
        ExeEdit.Value := path
        InvalidateScanState()
        ScheduleEngineStatusRefresh()
        UE4SS_RefreshButtons()
    }
}

OpenSelectedExeFolder(*) {
    global IsScanning, APP_NAME
    if IsScanning
        return

    path := Trim(ExeEdit.Value, ' "')
    if path = "" || !FileExist(path) {
        MsgBox("Choose an existing game executable first.", APP_NAME, "Icon!")
        return
    }
    SplitPath(path, , &dir)
    try Run('explorer.exe "' dir '"')
    catch as err
        MsgBox("Windows could not open the executable folder.`n`n" err.Message, APP_NAME, "Iconx")
}

BrowseLogDestination(*) {
    global IsScanning, LogDestEdit
    if IsScanning
        return

    startDir := Trim(LogDestEdit.Value, ' "')
    if startDir = "" || !DirExist(startDir)
        startDir := A_ScriptDir
    selected := DirSelect(startDir, 0, "Select report/log base directory")
    if selected != "" {
        LogDestEdit.Value := selected
        SaveLogDestinationSetting(selected)
    }
}

LogDestinationChanged(*) {
    global LogDestEdit
    SaveLogDestinationSetting(Trim(LogDestEdit.Value, ' "'))
}

ResolveLogRoot() {
    global LogDestEdit
    base := ""
    if IsSet(LogDestEdit) && IsObject(LogDestEdit)
        base := Trim(LogDestEdit.Value, ' "')
    if base = ""
        base := A_ScriptDir
    return RTrim(base, "\/") "\log"
}

SanitizeLogFileName(text) {
    text := Trim(RegExReplace(text, '[<>:"/\\|?*]', "_"), " .")
    return text != "" ? text : "Unknown Game"
}

FriendlyGameNameFromExe(path) {
    ; Steam installs give us the cleanest user-facing game title directly from
    ; steamapps\common. Fall back to the usual Unreal <Game>\<Project>\Binaries\Win64 layout.
    if RegExMatch(path, "i)\\steamapps\\common\\([^\\]+)\\", &m)
        return m[1]

    SplitPath(path, &fileName, &exeDir, &ext, &stem)
    SplitPath(exeDir, &win64Name, &binariesDir)
    SplitPath(binariesDir, &binariesName, &projectDir)
    SplitPath(projectDir, &projectName, &gameDir)
    SplitPath(gameDir, &gameName)

    if StrLower(win64Name) = "win64" && StrLower(binariesName) = "binaries" && gameName != ""
        return gameName

    SplitPath(exeDir, &parentName)
    if parentName != ""
        return parentName
    return stem
}

BuildScanReportPath(exePath) {
    SplitPath(exePath, &fileName, , &ext, &stem)
    gameName := SanitizeLogFileName(FriendlyGameNameFromExe(exePath))
    exeStem := SanitizeLogFileName(stem)
    title := gameName
    if StrLower(gameName) != StrLower(exeStem)
        title .= " - " exeStem
    return ResolveLogRoot() "\" title " - scan-report.txt"
}

GuiDropFiles(GuiObj, GuiCtrlObj, FileArray, X, Y) {
    global IsScanning, MainTabs, APP_NAME, ExeEdit
    if IsScanning
        return

    if MainTabs.Value = 2 {
        added := 0
        for path in FileArray {
            if RegExMatch(path, "i)\.exe$") && AddPathToBatch(path)
                added += 1
        }
        if added = 0
            MsgBox("Drop one or more .exe files onto the Batch tab.", APP_NAME, "Icon!")
        return
    }

    for path in FileArray {
        if RegExMatch(path, "i)\.exe$") {
            ExeEdit.Value := path
            InvalidateScanState()
            ScheduleEngineStatusRefresh()
            UE4SS_RefreshButtons()
            return
        }
    }
    MsgBox("Drop a .exe file onto the window.", APP_NAME, "Icon!")
}

ExePathChanged(*) {
    global IsScanning, LastScanPath
    ScheduleEngineStatusRefresh()
    UE4SS_RefreshButtons()
    if IsScanning || LastScanPath = ""
        return

    if NormalizeExePath(ExeEdit.Value) != NormalizeExePath(LastScanPath)
        InvalidateScanState()
}

ScheduleEngineStatusRefresh() {
    ; Coalesce manual typing/path changes so the bounded directory preflight does
    ; not run for every keystroke in the executable field.
    SetTimer(RefreshEngineStatus, -250)
}

RefreshEngineStatus() {
    global ExeEdit, EngineStatusText
    if !IsSet(EngineStatusText) || !IsObject(EngineStatusText)
        return

    path := Trim(ExeEdit.Value, ' "')
    if path = "" || !FileExist(path) || !RegExMatch(path, "i)\.exe$") {
        EngineStatusText.SetFont("c606060")
        EngineStatusText.Value := "Engine: not checked"
        return
    }

    detection := EngineDetect_Get(path)
    EngineStatusText.SetFont("c" EngineDetect_StatusColor(detection))
    EngineStatusText.Value := "Engine: " EngineDetect_ShortLabel(detection)
}

NormalizeExePath(path) {
    return StrLower(Trim(path, ' "'))
}

InvalidateScanState(clearResults := true) {
    global LastOutputDir, LastScanPath, LastScanResults, LastScanReport, LastReportPath, LastLocalCorpus

    LastOutputDir := ""
    LastScanPath := ""
    LastScanResults := []
    LastScanReport := ""
    LastReportPath := ""
    LastLocalCorpus := Map()
    GenerateBtn.Enabled := false
    OpenReportBtn.Enabled := false

    if clearResults
        ResultsLV.Delete()
}

ScanOrCancel(*) {
    global IsScanning, IsBatchScanning, SingleScanQueued, SingleScanDumpOverride

    if IsScanning {
        RequestScanCancellation(false)
        return
    }
    if IsBatchScanning || SingleScanQueued
        return

    ; Do not run the scan inside this button callback. AutoHotkey serializes a
    ; GUI control's event callback, so a second click on the same Scan button
    ; cannot invoke this handler while ScanExe() is still on its call stack.
    ; Queue the scan onto a one-shot timer instead; this callback returns first,
    ; leaving the button free to receive a real Cancel click during the scan.
    SingleScanDumpOverride := ""
    SingleScanQueued := true
    SetTimer(RunQueuedSingleScan, -1)
}

ChooseRuntimeDumpAndScan(*) {
    global IsScanning, IsBatchScanning, SingleScanQueued, SingleScanDumpOverride, APP_NAME
    if IsScanning || IsBatchScanning || SingleScanQueued
        return

    dumpPath := FileSelect(1, , "Select a runtime dump or mapped image", "Runtime dumps (*.dmp; *.mdmp; *.bin; *.mem; *.exe);;All files (*.*)")
    if dumpPath = ""
        return
    if !FileExist(dumpPath) {
        MsgBox("The selected runtime dump does not exist.", APP_NAME, "Icon!")
        return
    }

    ; An explicitly selected dump is authoritative for this one scan. We still
    ; validate that the dump contains the selected executable's mapped module.
    SingleScanDumpOverride := dumpPath
    SingleScanQueued := true
    SetTimer(RunQueuedSingleScan, -1)
}

RunQueuedSingleScan() {
    global SingleScanQueued, SingleScanDumpOverride
    dumpPath := SingleScanDumpOverride
    SingleScanDumpOverride := ""
    SingleScanQueued := false
    ScanExe("", false, dumpPath)
}

SetSingleScanButtonText(text) {
    global ScanBtn, GenerateBtn, OpenReportBtn, RuntimeDumpBtn, OpenFolderCheck
    NativeUI_SetButtonTextAutoWidth(ScanBtn, text, "Scan", 90,
        [GenerateBtn, OpenReportBtn, RuntimeDumpBtn, OpenFolderCheck])
}

SetBatchScanButtonText(text) {
    global BatchScanBtn, BatchOpenReportBtn
    NativeUI_SetButtonTextAutoWidth(BatchScanBtn, text, "Scan Batch", 110, [BatchOpenReportBtn])
}

RequestScanCancellation(batchMode := false) {
    global ScanCancelled, ScanProgressPct, ScanBtn, BatchScanBtn, StatusBar

    ScanCancelled := true
    ; Cancellation is also a visual reset: empty the bar immediately rather
    ; than leaving stale resolver progress on screen while shutdown completes.
    ScanProgressPct := 0.0
    ; Immediately terminate ScannerCore if a native pass/runtime capture is in
    ; flight. AHK-only work observes ScanCancelled at cooperative yield points.
    StopNativeScanner()

    if batchMode {
        SetBatchScanButtonText("Cancelling...")
        StatusBar.SetText("Cancelling batch scan...")
        SetScanProgress(0, "Cancelling batch scan...")
    } else {
        SetSingleScanButtonText("Cancelling...")
        StatusBar.SetText("Cancelling scan...")
        SetScanProgress(0, "Cancelling scan...")
    }
}

BeginScanUi() {
    global IsScanning, ScanCancelled, RecentDDL, IsBatchScanning, RuntimeDumpBtn, InstallUE4SSBtn, UpdateUE4SSBtn
    IsScanning := true
    ; StartBatchScan owns the cancellation lifetime across its whole queue. Do
    ; not clear a Cancel click that arrived between two batch targets.
    if !IsBatchScanning
        ScanCancelled := false
    SetSingleScanButtonText("Cancel")
    ScanBtn.Enabled := true
    GenerateBtn.Enabled := false
    OpenReportBtn.Enabled := false
    BrowseBtn.Enabled := false
    OpenExeFolderBtn.Enabled := false
    LogDestBrowseBtn.Enabled := false
    LogDestEdit.Enabled := false
    ExeEdit.Enabled := false
    RecentDDL.Enabled := false
    RuntimeDumpBtn.Enabled := false
    InstallUE4SSBtn.Enabled := false
    UpdateUE4SSBtn.Enabled := false
    if IsBatchScanning
        SetBatchScanButtonText("Cancel")
    StartScanProgress()
}

EndScanUi() {
    global IsScanning, RecentDDL, OpenExeFolderBtn, LogDestBrowseBtn, LogDestEdit, RuntimeDumpBtn
    StopNativeScanner()
    IsScanning := false
    StopScanProgress()
    SetSingleScanButtonText("Scan")
    ScanBtn.Enabled := true
    BrowseBtn.Enabled := true
    OpenExeFolderBtn.Enabled := true
    LogDestBrowseBtn.Enabled := true
    LogDestEdit.Enabled := true
    ExeEdit.Enabled := true
    RecentDDL.Enabled := true
    RuntimeDumpBtn.Enabled := true
    UE4SS_RefreshButtons()
}

CheckScanCancelled(yieldToGui := false) {
    global ScanCancelled
    if yieldToGui
        Sleep(-1)
    if ScanCancelled
        throw Error("__SCAN_CANCELLED__")
}

ScanExe(pathOverride := "", batchMode := false, runtimeDumpOverride := "") {
    global LastOutputDir, LastScanPath, LastScanResults, LastScanReport, LastReportPath, LastLocalCorpus, ScanProgressPct, ScanStartTick

    path := pathOverride != "" ? Trim(pathOverride, ' "') : Trim(ExeEdit.Value, ' "')
    if !FileExist(path) {
        if !batchMode
            MsgBox("Choose an existing game executable first.", APP_NAME, "Icon!")
        return {Success: false, Cancelled: false, Error: "Executable does not exist.", ElapsedMs: 0}
    }
    if !RegExMatch(path, "i)\.exe$") {
        if !batchMode
            MsgBox("The selected file is not an .exe.", APP_NAME, "Icon!")
        return {Success: false, Cancelled: false, Error: "Selected file is not an .exe.", ElapsedMs: 0}
    }

    engineDetection := EngineDetect_Get(path)
    engineOverride := engineDetection.Decision != "UNREAL"
    if !batchMode && !EngineDetect_ConfirmSingle(engineDetection) {
        StatusBar.SetText("Scan cancelled by engine preflight")
        return {Success: false, Cancelled: false, Error: "Engine preflight declined.", ElapsedMs: 0, Engine: engineDetection.Engine}
    }

    if !batchMode {
        InvalidateScanState(false)
        ResultsLV.Delete()
        LogEdit.Value := ""
    } else {
        Log("===== Batch target: " path " =====")
    }
    Log("Opening: " path)
    Log("[ENGINE] " EngineDetect_ShortLabel(engineDetection) " | score " engineDetection.Score " | Unreal score " engineDetection.UnrealScore)
    Log("[ENGINE] Evidence: " engineDetection.EvidenceText)
    if engineOverride
        Log("[ENGINE] Scan Anyway override active; engine preflight is advisory and resolver confidence rules remain unchanged.")
    StatusBar.SetText("Reading executable...")
    BeginScanUi()
    SetScanProgress(1, "Reading executable...")
    Sleep(-1)

    scanEntries := []
    verifiedReady := 0
    strongReady := 0
    unverifiedReady := 0
    requiredFound := 0
    requiredTotal := 0
    optionalFound := 0
    optionalTotal := 0
    runtimeCapture := ""
    runtimeUsed := false
    runtimeSource := ""
    diskOpaqueImage := ""
    activeOpaqueImage := ""

    try {
        pe := LoadPE(path)
        SetScanProgress(3, "PE loaded; discovering reusable signature evidence...")
        CheckScanCancelled(true)

        localCorpus := DiscoverExistingSignatureCorpus(path)
        LastLocalCorpus := localCorpus

        Log(Format("PE32+ OK | ImageBase 0x{:X} | {} sections | file size {} MB", pe.ImageBase, pe.Sections.Length, Round(pe.Size / 1048576, 1)))
        if localCorpus.Count > 0
            Log("Loaded " localCorpus.Count " existing local UE4SS custom signature(s) for revalidation.")
        Log("Static analysis starts from the selected executable. Protected images can switch to a live read-only runtime snapshot or an imported runtime dump; the game executable itself is never changed.")
        Log("Scan mode only: existing generated Lua files are left untouched until Generate is clicked.")

        nativePrime := PrimeNativePatternCache(pe, localCorpus)
        if nativePrime.Available
            Log("Native ScannerCore active: " nativePrime.Detail)
        else
            Log("Native ScannerCore fallback: " nativePrime.Detail)

        diskOpaqueImage := DetectOpaqueDiskImage(pe)
        activeOpaqueImage := diskOpaqueImage
        if diskOpaqueImage.Likely || runtimeDumpOverride != "" {
            if diskOpaqueImage.Likely {
                Log("[OPAQUE] " diskOpaqueImage.Detail)
                Log("[OPAQUE] On-disk engine code appears packed/encrypted/virtualized. Automatic runtime-image capture will be attempted before resolver scanning.")
                SetScanProgress(5, "Opaque image detected; looking for runtime source...")
            } else {
                Log("[DUMP] Runtime Dump scan explicitly requested; the imported mapped image will be used even though the disk EXE was not classified opaque.")
                SetScanProgress(5, "Preparing runtime dump import...")
            }

            if runtimeDumpOverride != "" {
                Log("[DUMP] Explicit runtime dump selected: " runtimeDumpOverride)
                SetScanProgress(5, "Importing selected runtime dump...")
                runtimeCapture := ImportRuntimeDump(path, runtimeDumpOverride)
                if runtimeCapture.Success
                    runtimeSource := "dump"
            } else {
                runtimeCapture := CaptureRuntimeImage(path, 0)
                if runtimeCapture.Success
                    runtimeSource := "live"
                if !runtimeCapture.Success && runtimeCapture.Status = "NOT_RUNNING" && !batchMode {
                    choice := MsgBox(
                        "This executable needs a runtime image, but the selected game is not running yet.`n`n"
                        . "Launch the game normally and wait until it reaches the main menu or gameplay, then click Retry. The generator will read only the mapped main executable and will not modify the process.`n`n"
                        . "Cancel continues to the runtime-dump fallback.",
                        APP_NAME, "RetryCancel Icon! Default1")
                    if choice = "Retry" {
                        runtimeCapture := CaptureRuntimeImage(path, 60000)
                        if runtimeCapture.Success
                            runtimeSource := "live"
                    }
                }

                if !runtimeCapture.Success && !batchMode {
                    promptDump := runtimeCapture.Status = "ACCESS_DENIED" || runtimeCapture.Status = "NOT_RUNNING"
                    if promptDump {
                        choice := MsgBox(
                            "Automatic runtime capture is unavailable.`n`n"
                            . "Would you like to import a Windows process dump or mapped-image snapshot for this executable instead?`n`n"
                            . "Supported input: standard .dmp/.mdmp files with module + memory streams, or a mapped PE image whose file layout follows virtual addresses.",
                            APP_NAME, "YesNo Icon! Default1")
                        if choice = "Yes" {
                            dumpPath := FileSelect(1, , "Select a runtime dump or mapped image", "Runtime dumps (*.dmp; *.mdmp; *.bin; *.mem; *.exe);;All files (*.*)")
                            if dumpPath != "" {
                                SetScanProgress(5, "Importing runtime dump...")
                                runtimeCapture := ImportRuntimeDump(path, dumpPath)
                                if runtimeCapture.Success
                                    runtimeSource := "dump"
                                else
                                    MsgBox("The selected runtime dump could not be imported.`n`n" runtimeCapture.Status ": " runtimeCapture.Detail "`n`nThe scan will continue against the on-disk executable.", APP_NAME, "Icon!")
                            }
                        }
                    }
                }
            }

            if runtimeCapture.Success {
                if runtimeSource = "dump" {
                    Log(Format("[DUMP] Imported {} runtime image | module base 0x{:X} | image size {} MB | {} sections.",
                        runtimeCapture.Format, runtimeCapture.Base, Round(runtimeCapture.ImageSize / 1048576, 1), runtimeCapture.Sections))
                    if HasProp(runtimeCapture, "SourcePath") && runtimeCapture.SourcePath != ""
                        Log("[DUMP] Source: " runtimeCapture.SourcePath)
                } else {
                    Log(Format("[RUNTIME] Captured mapped image from PID {} | base 0x{:X} | image size {} MB | {} sections.",
                        runtimeCapture.PID, runtimeCapture.Base, Round(runtimeCapture.ImageSize / 1048576, 1), runtimeCapture.Sections))
                }
                if runtimeCapture.FailedBytes > 0
                    Log(Format("[RUNTIME] Warning: {} MB of mapped bytes are absent/unreadable in the normalized snapshot ({} MB executable).",
                        Round(runtimeCapture.FailedBytes / 1048576, 2), Round(runtimeCapture.FailedExecBytes / 1048576, 2)))

                ; Release the giant on-disk buffer before loading another giant
                ; image. The normalized snapshot remains on disk until every
                ; native semantic resolver has finished.
                pe := ""
                SetScanProgress(10, runtimeSource = "dump" ? "Loading imported runtime image..." : "Loading captured runtime image...")
                pe := LoadPE(runtimeCapture.Path)
                pe.OriginalPath := path
                runtimeUsed := true

                Log(Format("[RUNTIME] Runtime PE loaded | ImageBase 0x{:X} | {} sections | normalized snapshot {} MB",
                    pe.ImageBase, pe.Sections.Length, Round(pe.Size / 1048576, 1)))
                runtimePrime := PrimeNativePatternCache(pe, localCorpus, 10.2, 1.8)
                if runtimePrime.Available
                    Log("[RUNTIME] Native ScannerCore re-indexed runtime bytes: " runtimePrime.Detail)
                else
                    Log("[RUNTIME] Native ScannerCore runtime fallback: " runtimePrime.Detail)

                activeOpaqueImage := DetectOpaqueDiskImage(pe)
                if runtimeCapture.ExecSpanBytes > 0 {
                    execUnreadLimit := Max(4 * 1024 * 1024, runtimeCapture.ExecSpanBytes * 0.01)
                    if runtimeCapture.FailedExecBytes > execUnreadLimit {
                        activeOpaqueImage.Likely := true
                        activeOpaqueImage.Detail .= Format(" Runtime source is missing {} MB of {} MB mapped executable bytes; incomplete executable coverage is treated as protected/opaque.",
                            Round(runtimeCapture.FailedExecBytes / 1048576, 2), Round(runtimeCapture.ExecSpanBytes / 1048576, 2))
                    }
                }
                if activeOpaqueImage.Likely {
                    Log("[RUNTIME] The runtime image still looks opaque/protected: " activeOpaqueImage.Detail)
                    Log("[RUNTIME] Resolver scanning will continue without weakening confidence rules.")
                } else {
                    Log("[RUNTIME] Runtime image is statically analyzable. Resolvers will use runtime bytes instead of the protected disk payload.")
                }
            } else {
                Log("[RUNTIME] No usable runtime image (" runtimeCapture.Status "): " runtimeCapture.Detail)
                if runtimeCapture.Status = "ACCESS_DENIED" && !batchMode
                    MsgBox("The running game was found, but ordinary read-only process access is blocked. The generator will not bypass that protection.`n`nYou can use Runtime Dump... to supply a standard Windows dump or mapped-image snapshot if you can obtain one through a normal user-authorized tool.`n`nThe current scan will continue against the on-disk image.", APP_NAME, "Icon!")
                else if runtimeDumpOverride != "" && !batchMode
                    MsgBox("The selected runtime dump could not be imported.`n`n" runtimeCapture.Status ": " runtimeCapture.Detail "`n`nThe current scan will continue against the on-disk executable.", APP_NAME, "Icon!")
                if diskOpaqueImage.Likely
                    Log("[OPAQUE] Falling back to the protected on-disk image; a 0/13 result may remain expected.")
            }
        }
        Log("")

        SplitPath(path, &fileName, &fileDir, &ext, &nameNoExt)
        outRoot := UE4SS_ResolveSignatureDir(path)
        reportPath := BuildScanReportPath(path)

        report := "UE4SS Signature Generator v" APP_VERSION "`r`n"
            . "Executable: " path "`r`n"
            . "Engine preflight: " EngineDetect_ShortLabel(engineDetection) " | decision " engineDetection.Decision " | score " engineDetection.Score " | Unreal score " engineDetection.UnrealScore "`r`n"
            . "Engine evidence: " engineDetection.EvidenceText "`r`n"
            . (engineOverride ? "Engine preflight override: Scan Anyway / batch override was used.`r`n" : "")
            . Format("ImageBase: 0x{:X}`r`n", pe.ImageBase)
            . "Scanned: " FormatTime(, "yyyy-MM-dd HH:mm:ss") "`r`n"
            . "Analysis source: " (runtimeUsed ? (runtimeSource = "dump" ? "imported runtime dump/mapped image" : "captured runtime mapped image") : "on-disk executable") "`r`n"
            . "On-disk image classification: " (diskOpaqueImage.Likely ? "LIKELY OPAQUE / PROTECTED" : "ordinary/static-analysis-compatible") "`r`n"
        if diskOpaqueImage.Detail != ""
            report .= "On-disk layout evidence: " diskOpaqueImage.Detail "`r`n"
        if runtimeUsed {
            if runtimeSource = "dump" {
                report .= Format("Runtime dump import: {} | module base 0x{:X} | image size {} MB | missing bytes {} (executable {}) | normalized snapshot`r`n",
                    runtimeCapture.Format, runtimeCapture.Base, Round(runtimeCapture.ImageSize / 1048576, 1), runtimeCapture.FailedBytes, runtimeCapture.FailedExecBytes)
                if HasProp(runtimeCapture, "SourcePath") && runtimeCapture.SourcePath != ""
                    report .= "Runtime dump source: " runtimeCapture.SourcePath "`r`n"
            } else {
                report .= Format("Runtime capture: PID {} | module base 0x{:X} | image size {} MB | unreadable bytes {} (executable {}) | temporary normalized snapshot`r`n",
                    runtimeCapture.PID, runtimeCapture.Base, Round(runtimeCapture.ImageSize / 1048576, 1), runtimeCapture.FailedBytes, runtimeCapture.FailedExecBytes)
            }
            report .= "Runtime image classification: " (activeOpaqueImage.Likely ? "STILL OPAQUE / PROTECTED" : "runtime/static-analysis-compatible") "`r`n"
            if activeOpaqueImage.Detail != ""
                report .= "Runtime layout evidence: " activeOpaqueImage.Detail "`r`n"
        } else if diskOpaqueImage.Likely {
            report .= "Runtime capture: unavailable; " runtimeCapture.Status " | " runtimeCapture.Detail "`r`n"
        }
        report .= "`r`n"

        progressBase := runtimeUsed ? 12.0 : 5.0
        progressScale := runtimeUsed ? (88.0 / 95.0) : 1.0
        SetScanProgress(progressBase, "Resolver layers ready")
        for resolver in ResolverDB {
            CheckScanCancelled(true)
            activeResolver := MergeResolverWithExistingCorpus(resolver, localCorpus)
            span := ResolverProgressWeight(activeResolver.File) * progressScale
            SetResolverProgressWindow(progressBase, span, activeResolver.File)
            StatusBar.SetText("Scanning " activeResolver.File "...")

            resolverStartTick := A_TickCount
            result := ResolveTarget(pe, activeResolver)
            result := AttachTierMetadata(result, activeResolver)
            if runtimeUsed
                result.RuntimeImage := true
            if activeOpaqueImage.Likely && (result.Status = "NOT FOUND" || result.Status = "AMBIGUOUS") {
                opaqueDiag := (runtimeUsed ? "Captured runtime image remains opaque/protected: " : "On-disk image appears opaque/protected: ") activeOpaqueImage.Detail
                if HasProp(result, "Diagnostics") && result.Diagnostics != ""
                    result.Diagnostics .= " " opaqueDiag
                else
                    result.Diagnostics := opaqueDiag
            }
            resolverMs := A_TickCount - resolverStartTick
            result.ScanMs := resolverMs
            CheckScanCancelled(true)
            SetResolverProgress(1.0, activeResolver.File " complete")
            progressBase += span

            scanEntries.Push({Resolver: activeResolver, Result: result})

            if activeResolver.Required
                requiredTotal += 1
            else
                optionalTotal += 1
            if IsGeneratableResult(result) {
                if activeResolver.Required
                    requiredFound += 1
                else
                    optionalFound += 1
            }

            status := result.Status
            matchesText := result.MatchCount > 0 ? result.MatchCount : "-"
            rvaText := result.TargetRVA >= 0 ? Format("0x{:X}", result.TargetRVA) : "-"
            aobText := HasProp(result, "AOB") ? result.AOB : "-"

            iconIndex := StatusIconFor(status)
            sourceText := HasProp(result, "Source") ? ShortSource(result.Source) : "-"
            tierText := HasProp(result, "TierLabel") ? result.TierLabel : "-"
            if !batchMode {
                if iconIndex > 0
                    ResultsLV.Add("Icon" iconIndex, activeResolver.File, (activeResolver.Required ? "Required" : "Optional"), status, tierText, matchesText, rvaText, sourceText, aobText)
                else
                    ResultsLV.Add(, activeResolver.File, (activeResolver.Required ? "Required" : "Optional"), status, tierText, matchesText, rvaText, sourceText, aobText)
            }

            report .= activeResolver.File ": " status " | " (activeResolver.Required ? "REQUIRED" : "OPTIONAL")
            if HasProp(result, "MatchRVA") && result.MatchRVA >= 0
                report .= Format(" | Match RVA 0x{:X}", result.MatchRVA)
            if result.TargetRVA >= 0
                report .= Format(" | Target RVA 0x{:X}", result.TargetRVA)
            report .= " | matches " result.MatchCount " | scan time " FormatResolverDuration(result.ScanMs) "`r`n"
            if HasProp(result, "TierLabel")
                report .= "  Analysis tier: " result.TierLabel "`r`n"
            if HasProp(result, "Validation")
                report .= "  Validation: " result.Validation "`r`n"
            if HasProp(result, "MatchSection")
                report .= "  Match section: " result.MatchSection " | Target section: " result.TargetSection "`r`n"
            if HasProp(result, "ActualBytes")
                report .= "  Actual bytes: " result.ActualBytes "`r`n"
            if HasProp(result, "Source") {
                report .= "  Resolver source: " result.Source
                if HasProp(result, "Mode")
                    report .= " | mode: " result.Mode
                report .= "`r`n"
            }
            if HasProp(result, "Candidates")
                report .= "  Candidate targets: " result.Candidates "`r`n"
            if HasProp(result, "Consensus")
                report .= "  Consensus: " result.Consensus "`r`n"
            if HasProp(result, "Diagnostics")
                report .= "  Diagnostics: " result.Diagnostics "`r`n"
            if HasProp(result, "SecondaryProof")
                report .= "  Secondary proof: " result.SecondaryProof "`r`n"

            if IsGeneratableResult(result) {
                if status = "VERIFIED" {
                    verifiedReady += 1
                    Log("[VERIFY] " activeResolver.File " | target " Format("0x{:X}", result.TargetRVA) " | " result.TierLabel " | ready to generate | " FormatResolverDuration(result.ScanMs))
                } else if status = "STRONG" {
                    strongReady += 1
                    Log("[STRONG] " activeResolver.File " | target " Format("0x{:X}", result.TargetRVA) " | " result.TierLabel " | generatable with confirmation | " FormatResolverDuration(result.ScanMs))
                    if HasProp(result, "Diagnostics") && result.Diagnostics != ""
                        Log("[" (activeResolver.File = "GUObjectArray" ? "GUOBJ " : "INFO  ") "] " result.Diagnostics)
                } else if status = "UNVERIFIED" {
                    unverifiedReady += 1
                    Log("[WARN  ] " activeResolver.File " | candidate " Format("0x{:X}", result.TargetRVA) " | " result.TierLabel " | generatable with explicit risk confirmation | " FormatResolverDuration(result.ScanMs))
                }
            } else if (status = "AMBIGUOUS") {
                detail := HasProp(result, "Candidates") ? " | " result.Candidates : ""
                Log("[AMBIG] " activeResolver.File " resolved to multiple possible targets." detail " | " result.TierLabel " | " FormatResolverDuration(result.ScanMs))
            } else {
                Log("[MISS  ] " activeResolver.File " was not found by the current resolver set. | " result.TierLabel " | " FormatResolverDuration(result.ScanMs))
                if activeResolver.File = "StaticConstructObject" && HasProp(result, "Diagnostics") && result.Diagnostics != ""
                    Log("[SCO   ] " result.Diagnostics)
                else if activeResolver.File = "FName_ToString" && HasProp(result, "Diagnostics") && result.Diagnostics != ""
                    Log("[FNAME ] " result.Diagnostics)
                else if activeResolver.File = "GUObjectArray" && HasProp(result, "Diagnostics") && result.Diagnostics != ""
                    Log("[GUOBJ ] " result.Diagnostics)
            }
        }

        CheckScanCancelled(true)

        totalReady := verifiedReady + strongReady + unverifiedReady
        totalScanSeconds := Max(0.0, (A_TickCount - ScanStartTick) / 1000.0)
        report .= "`r`nUE4SS target coverage: Required " requiredFound "/" requiredTotal " | Optional " optionalFound "/" optionalTotal " | Total " totalReady "/" (requiredTotal + optionalTotal) "`r`n"
        report .= "Signatures available to generate: " totalReady "`r`n"
            . "  VERIFIED: " verifiedReady "`r`n"
            . "  STRONG: " strongReady "`r`n"
            . "  UNVERIFIED: " unverifiedReady "`r`n"
            . "  Total scan time: " FormatResolverDuration(totalScanSeconds * 1000.0) "`r`n"
        if diskOpaqueImage.Likely {
            report .= "`r`nOpaque/protected image note:`r`n"
            if runtimeUsed && !activeOpaqueImage.Likely
                report .= "  The on-disk executable is opaque, but " (runtimeSource = "dump" ? "an imported runtime dump" : "automatic runtime capture") " exposed a statically analyzable mapped image. All resolver evidence and generated AOBs in this scan come from those runtime bytes; confidence thresholds are unchanged.`r`n"
            else if runtimeUsed
                report .= "  " (runtimeSource = "dump" ? "The imported runtime dump" : "Automatic runtime capture") " was normalized successfully, but the mapped image still has strong opacity/protection signals. Resolver misses may therefore still reflect unavailable machine code rather than many unrelated Unreal target changes. Confidence thresholds remain unchanged.`r`n"
            else
                report .= "  The executable's on-disk code layout has strong signs of packing, encryption, or virtualization and no usable runtime image was captured. Static 0/13 results are therefore not equivalent to thirteen unsupported targets. Confidence thresholds remain unchanged.`r`n"
        }

        report .= "`r`nStatus meanings:`r`n"
            . "  VERIFIED   Resolver evidence plus an independent structural/addressing proof converged on the same target. Generates normally.`r`n"
            . "  STRONG     High-confidence structural resolver result. May be generated after acknowledging the risk warning.`r`n"
            . "  UNVERIFIED Plausible candidate whose symbol-identity evidence is incomplete. May be generated only after an explicit risk warning.`r`n"
            . "  NOT FOUND  No supported resolver pattern or semantic chain matched. Cannot be generated.`r`n"
            . "  AMBIGUOUS  Multiple possible targets without decisive evidence. Cannot be generated.`r`n"
            . "`r`nRequirement meanings:`r`n"
            . "  REQUIRED   Upstream UE4SS treats failure of this PatternSleuth target as a scan failure/core compatibility issue.`r`n"
            . "  OPTIONAL   Upstream UE4SS can continue without this target; related functionality or mods may still need it.`r`n"
            . "`r`nScanning never modifies the selected executable. Existing installed UE4SS custom signatures are imported when their resolver form is understood, rescanned against the selected EXE, and subjected to the same validation rules. Built-in known-good corpus entries are likewise reverified rather than blindly trusted. Generate includes VERIFIED/STRONG/UNVERIFIED rows; risky rows require confirmation.`r`n"

        SplitPath(reportPath, , &reportDir)
        DirCreate(reportDir)
        WriteUtf8Raw(reportPath, report)

        if !batchMode {
            LastOutputDir := outRoot
            LastScanPath := path
            LastScanResults := scanEntries
            LastScanReport := report
            LastReportPath := reportPath
        }

        AddRecentPath(path)
        SetScanProgress(100, "Scan complete")
        GenerateBtn.Enabled := !batchMode && totalReady > 0
        if !batchMode
            OpenReportBtn.Enabled := FileExist(reportPath)

        Log("")
        Log("Scan finished. Required " requiredFound "/" requiredTotal " | Optional " optionalFound "/" optionalTotal " | " totalReady " signature(s) available to generate (" verifiedReady " verified, " strongReady " strong, " unverifiedReady " unverified).")
        if activeOpaqueImage.Likely && totalReady = 0 {
            if runtimeUsed
                Log("[RUNTIME] 0/13 after " (runtimeSource = "dump" ? "runtime dump import" : "runtime capture") ": the mapped image still appears opaque/protected, so the engine code was not exposed in a statically analyzable form.")
            else
                Log("[OPAQUE] 0/13 is consistent with an unreadable on-disk engine-code image; automatic runtime capture was not available for this scan.")
        }
        Log("Report: " reportPath)
        StatusBar.SetText("Scan finished: " totalReady " signature(s) available")

        summary := SummarizeScanEntries(scanEntries)
        summary.Success := true
        summary.Cancelled := false
        summary.Path := path
        summary.OutputDir := outRoot
        summary.ReportPath := reportPath
        summary.ElapsedMs := A_TickCount - ScanStartTick
        summary.Engine := engineDetection.Engine
        summary.EngineDecision := engineDetection.Decision
        summary.EngineConfidence := engineDetection.Confidence
        summary.Entries := scanEntries
    } catch as err {
        cancelled := err.Message = "__SCAN_CANCELLED__"
        if cancelled {
            if !batchMode
                InvalidateScanState(false)
            Log("")
            Log("Scan cancelled. Partial results are not eligible for generation.")
            SetScanProgress(0, "Cancelled")
            StatusBar.SetText("Scan cancelled")
        } else {
            if !batchMode
                InvalidateScanState(false)
            SetScanProgress(ScanProgressPct, "Scan failed")
            StatusBar.SetText("Scan failed")
            Log("")
            Log("ERROR: " err.Message)
            if !batchMode
                MsgBox("The scan could not be completed.`n`n" err.Message, APP_NAME, "Iconx")
        }
        elapsedMs := A_TickCount - ScanStartTick
        CleanupRuntimeImageCapture(runtimeCapture)
        EndScanUi()
        return {Success: false, Cancelled: cancelled, Error: err.Message, ElapsedMs: elapsedMs}
    }

    CleanupRuntimeImageCapture(runtimeCapture)
    EndScanUi()
    return summary
}

SummarizeScanEntries(entries) {
    summary := {Verified: 0, Strong: 0, Unverified: 0, NotFound: 0, Ambiguous: 0,
        RequiredReady: 0, RequiredTotal: 0, OptionalReady: 0, OptionalTotal: 0}
    for entry in entries {
        isRequired := HasProp(entry.Resolver, "Required") && entry.Resolver.Required
        if isRequired
            summary.RequiredTotal += 1
        else
            summary.OptionalTotal += 1
        if IsGeneratableResult(entry.Result) {
            if isRequired
                summary.RequiredReady += 1
            else
                summary.OptionalReady += 1
        }
        status := entry.Result.Status
        switch status {
            case "VERIFIED": summary.Verified += 1
            case "STRONG": summary.Strong += 1
            case "UNVERIFIED": summary.Unverified += 1
            case "NOT FOUND": summary.NotFound += 1
            case "AMBIGUOUS": summary.Ambiguous += 1
        }
    }
    return summary
}

IsGeneratableResult(result) {
    return ((result.Status = "VERIFIED" || result.Status = "STRONG" || result.Status = "UNVERIFIED")
        && result.TargetRVA >= 0
        && HasProp(result, "AOB")
        && result.AOB != ""
        && HasProp(result, "Mode")
        && HasProp(result, "Validation"))
}

CountGeneratable(entries, status := "") {
    count := 0
    for entry in entries {
        result := entry.Result
        if !IsGeneratableResult(result)
            continue
        if status = "" || result.Status = status
            count += 1
    }
    return count
}

BuildRiskWarning(entries) {
    strongNames := []
    unverifiedNames := []
    for entry in entries {
        result := entry.Result
        if !IsGeneratableResult(result)
            continue
        if result.Status = "STRONG"
            strongNames.Push(entry.Resolver.File)
        else if result.Status = "UNVERIFIED"
            unverifiedNames.Push(entry.Resolver.File)
    }

    if strongNames.Length = 0 && unverifiedNames.Length = 0
        return ""

    text := "Some selected signatures are not fully VERIFIED.`n`n"
    if strongNames.Length > 0 {
        text .= "STRONG (" strongNames.Length "): " JoinText(strongNames, ", ") "`n"
            . "These have high-confidence structural evidence, but they have not passed every independent verification check.`n`n"
    }
    if unverifiedNames.Length > 0 {
        text .= "UNVERIFIED (" unverifiedNames.Length "): " JoinText(unverifiedNames, ", ") "`n"
            . "These are plausible candidates only. A wrong target can make UE4SS fail to initialize, crash the game, or behave unpredictably.`n`n"
    }
    text .= "The generated Lua files will preserve their confidence status in the header. Nothing will modify the game executable itself.`n`n"
        . "Generate these signatures anyway?"
    return text
}

JoinText(items, separator := ", ") {
    out := ""
    for index, item in items
        out .= (index > 1 ? separator : "") item
    return out
}

OpenScanReport(*) {
    global LastReportPath, IsScanning, APP_NAME
    if IsScanning
        return

    if LastReportPath = "" {
        MsgBox("Run a successful Single scan first. No report is currently available.", APP_NAME, "Icon!")
        return
    }

    if !FileExist(LastReportPath) {
        MsgBox("The scan report could not be found:`n`n" LastReportPath, APP_NAME, "Icon!")
        return
    }

    try Run('"' LastReportPath '"')
    catch as err
        MsgBox("The report exists, but Windows could not open it.`n`n" err.Message, APP_NAME, "Iconx")
}

GenerateSignatures(*) {
    global LastOutputDir, LastScanPath, LastScanResults, LastScanReport, LastReportPath, IsScanning

    if IsScanning
        return

    if LastScanPath = "" || LastScanResults.Length = 0 {
        GenerateBtn.Enabled := false
        MsgBox("Run a successful Scan first.", APP_NAME, "Icon!")
        return
    }

    if NormalizeExePath(ExeEdit.Value) != NormalizeExePath(LastScanPath) {
        InvalidateScanState()
        MsgBox("The executable path changed after the scan. Scan the currently selected executable again first.", APP_NAME, "Icon!")
        return
    }

    totalReady := CountGeneratable(LastScanResults)
    verifiedReady := CountGeneratable(LastScanResults, "VERIFIED")
    strongReady := CountGeneratable(LastScanResults, "STRONG")
    unverifiedReady := CountGeneratable(LastScanResults, "UNVERIFIED")

    if totalReady <= 0 {
        GenerateBtn.Enabled := false
        MsgBox("There are no VERIFIED, STRONG, or UNVERIFIED signatures available to generate.", APP_NAME, "Icon!")
        return
    }

    warning := BuildRiskWarning(LastScanResults)
    if warning != "" {
        answer := MsgBox(warning, APP_NAME " - Risk warning", "YesNo Icon! Default2")
        if answer != "Yes" {
            StatusBar.SetText("Generation cancelled")
            Log("")
            Log("Generation cancelled at the risk confirmation prompt. No signature files were changed.")
            return
        }
    }

    ; Resolve at generation time so an UE4SS install/update performed after the
    ; scan still redirects these files into the installation's live signature folder.
    outDir := UE4SS_ResolveSignatureDir(LastScanPath)
    if outDir = ""
        outDir := UE4SS_ExeDir(LastScanPath) "\UE4SS_Signatures"

    GenerateBtn.Enabled := false
    StatusBar.SetText("Generating signatures...")

    try {
        DirCreate(outDir)

        ; This is now the live UE4SS signature directory. Never clear it: the
        ; user may have custom signatures from other sources. We only overwrite
        ; the exact target files being generated by this scan.
        generated := 0
        genVerified := 0
        genStrong := 0
        genUnverified := 0
        Log("")
        Log("Generating eligible signatures...")

        for entry in LastScanResults {
            resolver := entry.Resolver
            result := entry.Result
            if !IsGeneratableResult(result)
                continue

            lua := BuildLua(resolver, result)
            luaPath := outDir "\" resolver.File ".lua"
            WriteUtf8Raw(luaPath, lua)
            generated += 1
            if result.Status = "VERIFIED"
                genVerified += 1
            else if result.Status = "STRONG"
                genStrong += 1
            else if result.Status = "UNVERIFIED"
                genUnverified += 1
            Log("[GEN " result.Status "] " resolver.File " | " result.TierLabel " -> " luaPath)
        }

        generationReport := LastScanReport
            . "`r`nGeneration:`r`n"
            . "  Generated: " FormatTime(, "yyyy-MM-dd HH:mm:ss") "`r`n"
            . "  Total Lua files: " generated "`r`n"
            . "  VERIFIED: " genVerified "`r`n"
            . "  STRONG: " genStrong "`r`n"
            . "  UNVERIFIED: " genUnverified "`r`n"
        if genStrong > 0 || genUnverified > 0
            generationReport .= "  Risk warning accepted: yes`r`n"
        if LastReportPath != ""
            WriteUtf8Raw(LastReportPath, generationReport)

        Log("")
        Log("Finished. Generated " generated " custom signature file(s): " genVerified " verified, " genStrong " strong, " genUnverified " unverified.")
        Log("UE4SS signature folder: " outDir)
        StatusBar.SetText("Generated: " generated " signature(s)")

        if OpenFolderCheck.Value
            Run('explorer.exe "' outDir '"')
    } catch as err {
        StatusBar.SetText("Generation failed")
        Log("ERROR while generating: " err.Message)
        MsgBox("The scan completed successfully, but signature generation failed.`n`n" err.Message, APP_NAME, "Iconx")
    }

    GenerateBtn.Enabled := CountGeneratable(LastScanResults) > 0
}

LoadPE(path) {
    file := FileOpen(path, "r")
    if !IsObject(file)
        throw Error("Unable to open file.")

    size := file.Length
    if size < 1024
        throw Error("File is too small to be a normal PE executable.")

    data := Buffer(size, 0)
    file.RawRead(data)
    file.Close()

    if NumGet(data, 0, "UShort") != 0x5A4D
        throw Error("Missing MZ header.")

    peOff := NumGet(data, 0x3C, "UInt")
    if (peOff + 0x108 > size)
        throw Error("Invalid PE header offset.")
    if NumGet(data, peOff, "UInt") != 0x00004550
        throw Error("Missing PE signature.")

    machine := NumGet(data, peOff + 4, "UShort")
    if machine != 0x8664
        throw Error(Format("Expected x64 machine type 0x8664, got 0x{:X}.", machine))

    sectionCount := NumGet(data, peOff + 6, "UShort")
    optionalSize := NumGet(data, peOff + 20, "UShort")
    optOff := peOff + 24
    magic := NumGet(data, optOff, "UShort")
    if magic != 0x20B
        throw Error(Format("Expected PE32+ optional header (0x20B), got 0x{:X}.", magic))

    imageBase := NumGet(data, optOff + 24, "UInt64")
    sizeOfImage := NumGet(data, optOff + 56, "UInt")

    ; PE32+ data directories begin at optional-header offset 0x70.
    ; IMAGE_DIRECTORY_ENTRY_EXCEPTION is entry #3 and is the authoritative
    ; Win64 RUNTIME_FUNCTION table. Do not require a section literally named
    ; .pdata: linkers may merge/rename that section while leaving the exception
    ; directory completely valid.
    numberOfRvaAndSizes := optionalSize >= 112 ? NumGet(data, optOff + 108, "UInt") : 0
    exceptionRVA := 0
    exceptionSize := 0
    if numberOfRvaAndSizes > 3 && optionalSize >= 144 {
        exceptionRVA := NumGet(data, optOff + 112 + (3 * 8), "UInt")
        exceptionSize := NumGet(data, optOff + 112 + (3 * 8) + 4, "UInt")
    }

    sectionOff := optOff + optionalSize
    sections := []

    Loop sectionCount {
        off := sectionOff + (A_Index - 1) * 40
        if (off + 40 > size)
            break

        name := ReadSectionName(data, off)
        virtualSize := NumGet(data, off + 8, "UInt")
        virtualAddress := NumGet(data, off + 12, "UInt")
        rawSize := NumGet(data, off + 16, "UInt")
        rawPtr := NumGet(data, off + 20, "UInt")
        characteristics := NumGet(data, off + 36, "UInt")

        if rawPtr >= size
            rawSize := 0
        else if (rawPtr + rawSize > size)
            rawSize := size - rawPtr

        sections.Push({
            Name: name,
            VA: virtualAddress,
            VirtualSize: virtualSize,
            RawPtr: rawPtr,
            RawSize: rawSize,
            Characteristics: characteristics,
            Executable: (characteristics & 0x20000000) != 0 || name = ".text"
        })
    }

    return {
        Path: path,
        Data: data,
        Size: size,
        ImageBase: imageBase,
        SizeOfImage: sizeOfImage,
        ExceptionRVA: exceptionRVA,
        ExceptionSize: exceptionSize,
        Sections: sections
    }
}

DetectOpaqueDiskImage(pe) {
    ; Some protected Shipping executables preserve plaintext Unreal strings and
    ; valid PE metadata while storing the engine code itself as high-entropy
    ; packed/encrypted/virtualized bytes. In that case broad resolver misses are
    ; a property of the disk image, not thirteen unrelated pattern gaps.
    ;
    ; This is deliberately a warning/classifier only. It never promotes a
    ; resolver result, supplies an address, or weakens any confidence rule.
    uniqueNames := Map()
    largestExec := ""
    execBytes := 0
    hasText := false
    for section in pe.Sections {
        uniqueNames[StrLower(section.Name)] := true
        if section.Name = ".text"
            hasText := true
        if !section.Executable || section.RawSize <= 0
            continue
        execBytes += section.RawSize
        if !IsObject(largestExec) || section.RawSize > largestExec.RawSize
            largestExec := section
    }

    if !IsObject(largestExec)
        return {Likely: false, Detail: "No executable PE section was available for image-layout classification."}

    largestEntropy := SampleSectionEntropy(pe, largestExec)
    exceptionEntries := pe.ExceptionSize >= 12 ? Floor(pe.ExceptionSize / 12) : 0
    duplicateHeavy := pe.Sections.Length >= 6 && uniqueNames.Count <= Max(2, Floor(pe.Sections.Length / 3))
    giantExecutable := largestExec.RawSize >= 128 * 1024 * 1024
    highEntropyExecutable := largestEntropy >= 7.85
    hugeRuntimeDirectory := exceptionEntries >= 500000

    nativeHitCount := -1
    if HasProp(pe, "NativePatternCache") {
        nativeHitCount := 0
        for patternText, hits in pe.NativePatternCache
            nativeHitCount += hits.Length
    }
    nativeFamiliesBlank := nativeHitCount = 0

    ; Require both a giant and near-random executable payload plus additional PE
    ; anomalies. Large normal Shipping builds alone must not trip this warning.
    supportingLayout := duplicateHeavy || !hasText || hugeRuntimeDirectory
    supportingEvidence := hugeRuntimeDirectory || nativeFamiliesBlank
    likely := giantExecutable && highEntropyExecutable && supportingLayout && supportingEvidence

    detail := Format(
        "largest executable section '{}' is {} MB with sampled entropy {:.3f}/8; section names {}/{} unique; .text={}; exception entries={}; native static-family hits={}.",
        largestExec.Name,
        Round(largestExec.RawSize / 1048576, 1),
        largestEntropy,
        uniqueNames.Count,
        pe.Sections.Length,
        hasText ? "present" : "absent",
        exceptionEntries,
        nativeHitCount >= 0 ? nativeHitCount : "unavailable")

    return {
        Likely: likely,
        Detail: detail,
        LargestExecSection: largestExec.Name,
        LargestExecBytes: largestExec.RawSize,
        LargestExecEntropy: largestEntropy,
        UniqueSectionNames: uniqueNames.Count,
        SectionCount: pe.Sections.Length,
        ExceptionEntries: exceptionEntries,
        NativeStaticHits: nativeHitCount
    }
}

SampleSectionEntropy(pe, section, sampleBytes := 16384, sampleCount := 6) {
    if !IsObject(section) || section.RawSize <= 0 || section.RawPtr < 0
        return 0.0

    sampleBytes := Min(sampleBytes, section.RawSize)
    sampleCount := Max(1, sampleCount)
    span := Max(0, section.RawSize - sampleBytes)
    entropySum := 0.0
    actualSamples := 0
    ln2 := Ln(2)

    Loop sampleCount {
        frac := sampleCount <= 1 ? 0.0 : (A_Index - 1) / (sampleCount - 1)
        startRaw := section.RawPtr + Floor(span * frac)
        if startRaw < 0 || startRaw + sampleBytes > pe.Size
            continue

        freq := []
        Loop 256
            freq.Push(0)
        Loop sampleBytes {
            b := NumGet(pe.Data, startRaw + A_Index - 1, "UChar")
            freq[b + 1] += 1
        }

        h := 0.0
        for count in freq {
            if count <= 0
                continue
            probability := count / sampleBytes
            h -= probability * (Ln(probability) / ln2)
        }
        entropySum += h
        actualSamples += 1
    }

    return actualSamples > 0 ? entropySum / actualSamples : 0.0
}

ReadSectionName(data, off) {
    s := ""
    Loop 8 {
        c := NumGet(data, off + A_Index - 1, "UChar")
        if c = 0
            break
        s .= Chr(c)
    }
    return s
}

ShortSource(source) {
    source := StrReplace(source, "Existing local custom signature: ", "Local: ")
    source := StrReplace(source, "Known custom corpus: ", "Corpus: ")
    if StrLen(source) > 38
        return SubStr(source, 1, 35) "..."
    return source
}

DiscoverExistingSignatureCorpus(exePath) {
    corpus := Map()
    SplitPath(exePath, , &exeDir)
    dirs := []
    seen := Map()

    preferredDir := UE4SS_ResolveSignatureDir(exePath)
    if preferredDir != "" {
        key := StrLower(preferredDir)
        seen[key] := true
        dirs.Push(preferredDir)
    }

    cur := exeDir
    Loop 4 {
        for suffix in ["\UE4SS_Signatures", "\UE4SS\UE4SS_Signatures"] {
            d := cur suffix
            key := StrLower(d)
            if !seen.Has(key) {
                seen[key] := true
                dirs.Push(d)
            }
        }
        parent := RegExReplace(cur, "\\[^\\]+$")
        if parent = cur || parent = ""
            break
        cur := parent
    }

    targets := ["FName_Constructor", "FName_ToString", "StaticConstructObject", "GMalloc", "GUObjectArray", "FText_Constructor", "GUObjectHashTables", "GNatives", "ConsoleManager", "GameEngineTick", "ProcessLocalScriptFunction", "ProcessInternal", "CallFunctionByNameWithArguments"]
    for dir in dirs {
        if !DirExist(dir)
            continue
        for target in targets {
            file := dir "\" target ".lua"
            if !FileExist(file) || corpus.Has(target)
                continue
            parsed := ParseExistingSignatureLua(file, target)
            if IsObject(parsed)
                corpus[target] := parsed
        }
    }

    ; Legacy compatibility: current UE4SS still accepts FMemory_Free.lua when
    ; GMalloc.lua is absent. Treat it as the same GMalloc target.
    if !corpus.Has("GMalloc") {
        for dir in dirs {
            legacy := dir "\FMemory_Free.lua"
            if !FileExist(legacy)
                continue
            parsed := ParseExistingSignatureLua(legacy, "GMalloc")
            if IsObject(parsed) {
                parsed.Source := "Existing legacy FMemory_Free signature (GMalloc alias): " legacy
                corpus["GMalloc"] := parsed
                break
            }
        }
    }
    return corpus
}

ParseExistingSignatureLua(path, target) {
    try text := FileRead(path, "UTF-8")
    catch {
        try text := FileRead(path)
        catch
            return ""
    }

    if !RegExMatch(text, 'is)return\s+"([^"]+)"', &m)
        return ""
    aob := Trim(m[1])
    if aob = ""
        return ""

    mode := ""
    marker := -1
    add := 0

    ; Standard generator-style RIP/rel32 resolver.
    if RegExMatch(text, "i)DerefToInt32\s*\(\s*MatchAddress\s*\+\s*0x([0-9A-F]+)\s*\)", &d) {
        marker := ("0x" d[1]) + 0
        mode := "rel32"
    } else if (RegExMatch(text, "i)leaInstruction\s*:?=\s*matchAddress\s*\+\s*0x([0-9A-F]+)", &l)
        && RegExMatch(text, "i)displacementAddress\s*:?=\s*leaInstruction\s*\+\s*0x([0-9A-F]+)", &dd)
        && RegExMatch(text, "i)nextInstruction\s*:?=\s*leaInstruction\s*\+\s*0x([0-9A-F]+)", &nn)) {
        leaBase := ("0x" l[1]) + 0
        dispDelta := ("0x" dd[1]) + 0
        nextDelta := ("0x" nn[1]) + 0
        marker := leaBase + dispDelta
        mode := "rel32"
        add := (leaBase + nextDelta) - (marker + 4)
    } else if RegExMatch(text, "i)return\s+MatchAddress(?:\s*([+-])\s*0x([0-9A-F]+))?", &dm) {
        mode := "direct"
        if dm.Count >= 2 && dm[2] != "" {
            add := ("0x" dm[2]) + 0
            if dm[1] = "-"
                add := -add
        }
    } else {
        return ""
    }

    pattern := aob
    if mode = "rel32" {
        tokens := StrSplit(RegExReplace(Trim(aob), "\s+", " "), " ")
        if marker < 0 || marker + 4 > tokens.Length
            return ""
        out := ""
        for i, token in tokens {
            if i = marker + 1
                out .= (out != "" ? " " : "") "|"
            out .= (out != "" ? " " : "") token
        }
        pattern := out
    }

    SplitPath(path, &name)
    return {
        Pattern: pattern,
        Mode: mode,
        Add: add,
        Source: "Existing local custom signature: " path
    }
}

MergeResolverWithExistingCorpus(resolver, corpus) {
    patterns := []
    seen := Map()

    if corpus.Has(resolver.File)
        AppendResolverEntryUnique(patterns, seen, resolver, corpus[resolver.File])
    for entry in resolver.Patterns
        AppendResolverEntryUnique(patterns, seen, resolver, entry)

    return {
        File: resolver.File,
        Required: HasProp(resolver, "Required") ? resolver.Required : false,
        Mode: resolver.Mode,
        Add: resolver.Add,
        Patterns: patterns
    }
}

AppendResolverEntryUnique(patterns, seen, resolver, entry) {
    if IsObject(entry) {
        patternText := entry.Pattern
        mode := entry.Mode
        add := HasProp(entry, "Add") ? entry.Add : 0
    } else {
        patternText := entry
        mode := resolver.Mode
        add := resolver.Add
    }
    key := StrUpper(RegExReplace(Trim(patternText), "\s+", " ")) "|" mode "|" add
    if seen.Has(key)
        return
    seen[key] := true
    patterns.Push(entry)
}

ResolveTarget(pe, resolver) {
    ; v0.11: always consume the already-batched native/static evidence first.
    ; Historical UE4SS logs are now a LAST-RESORT identity hint instead of sitting
    ; on the hot path. On large HDD installs, opening several multi-megabyte logs
    ; before a resolver that already has a unique cached AOB cost tens of seconds.
    SetResolverProgress(0.02, "Scanning " resolver.File " pattern families...")
    generic := ResolveTargetGeneric(pe, resolver)
    SetResolverProgressAtLeast(0.36, resolver.File " primary patterns complete")

    if resolver.File = "FName_Constructor" {
        ; v0.12: PatternSleuth's PE resolver itself treats either full direct
        ; FName(wchar_t const*, EFindName) prologue as a decisive constructor
        ; identity. When one of those long structural signatures is UNIQUE and
        ; lands exactly on an executable .pdata function start, there is no value
        ; in spending tens of seconds rediscovering the same target through the
        ; much slower UTF-16/XREF fallback. Shorter/legacy/inlined candidates still
        ; retain the independent semantic corroboration path below.
        if generic.Status = "STRONG" && generic.TargetRVA >= 0 {
            directProof := VerifyFNameConstructorDirectPatternFast(pe, generic)
            if directProof.Passed {
                generic.Status := "VERIFIED"
                generic.Validation := directProof.Detail
                generic.SecondaryProof := "The complete unique PatternSleuth constructor fingerprint itself supplies the structural identity proof; executable-section validation confirms the target is code."
                generic.Source .= " + direct-prologue fast verification"
                generic.Tier := 1
                generic.TierName := "Direct fingerprint"
                generic.TierLabel := "T1 - Direct fingerprint"
                generic.TierLocked := true
                return generic
            }

            ; For candidates that are not one of the full PatternSleuth direct
            ; prologues, preserve the stricter body/XREF verification chain.
            bodyProof := VerifyFNameConstructorBody(pe, generic.TargetRVA)
            generic.SecondaryProof := bodyProof.Detail
            if bodyProof.Passed {
                generic.Status := "VERIFIED"
                generic.Validation := "Unique constructor signature plus independent FName(wchar_t*, EFindName) target-body fingerprint converged on the same exact .pdata function start."
                generic.Source .= " + constructor-body fingerprint"
                return generic
            }

            ; Older/custom UE4 builds can expose the public wchar constructor as a
            ; compact delegating wrapper whose outer bytes resemble an ANSI sibling.
            ; Decode the wrapper, follow its helper, and prove that RDX is consumed
            ; as 16-bit wchar_t data. This is independent of the pattern/XREF that
            ; nominated the target and does not rely on game-specific RVAs.
            SetResolverProgressAtLeast(0.46, "FName_Constructor: checking native wchar-wrapper corroboration...")
            wrapperProof := CorroborateNativeFNameConstructor(pe, generic.TargetRVA)
            if wrapperProof.Passed {
                generic.Status := "VERIFIED"
                generic.Validation := "Primary constructor evidence and an independent decoded delegating-wrapper proof converged on the same FName(wchar_t*, EFindName) target."
                generic.SecondaryProof := wrapperProof.Detail
                generic.Source .= " + native wchar-wrapper corroboration"
                return generic
            }
            generic.SecondaryProof .= " " wrapperProof.Detail

            SetResolverProgressAtLeast(0.60, "FName_Constructor: seeking independent semantic corroboration...")
            corroboration := ResolveFNameConstructorXref(pe)
            if !IsUsableResolverResult(corroboration) || corroboration.TargetRVA != generic.TargetRVA
                corroboration := ResolveFNameConstructorModuleAnchors(pe)

            if IsUsableResolverResult(corroboration) && corroboration.TargetRVA = generic.TargetRVA {
                generic.Status := "VERIFIED"
                generic.Validation := "Unique PatternSleuth constructor prologue and an independent UTF-16/XREF semantic resolver converged on the same target."
                generic.SecondaryProof := HasProp(corroboration, "Validation") ? corroboration.Validation : "Independent semantic resolver converged on the same target."
                generic.Source .= " + independent semantic corroboration"
            } else if IsObject(corroboration) && HasProp(corroboration, "TargetRVA") && corroboration.TargetRVA >= 0 && corroboration.TargetRVA != generic.TargetRVA {
                generic.Diagnostics := Format("Independent semantic resolver disagreed: primary 0x{:X}, semantic 0x{:X}; retained STRONG rather than promoting.", generic.TargetRVA, corroboration.TargetRVA)
            }
            return generic
        }

        if generic.Status = "NOT FOUND" || generic.Status = "AMBIGUOUS" {
            special := ResolveFNameConstructorXref(pe)
            if IsUsableResolverResult(special)
                return special

            moduleFallback := ResolveFNameConstructorModuleAnchors(pe)
            if IsUsableResolverResult(moduleFallback)
                return moduleFallback

            ; Only touch historical log files after the native/static and semantic
            ; constructor paths have genuinely failed.
            historical := TryResolveHistoricalResolverHint(pe, resolver.File)
            if IsObject(historical)
                return historical

            if generic.Status = "AMBIGUOUS"
                return generic
            if HasProp(moduleFallback, "Diagnostics")
                return moduleFallback
            return special
        }
    }

    if resolver.File = "FName_ToString" {
        ; Decisive multi-pattern consensus can still be STRONG when .pdata has
        ; chained/overlapping entries. Use the independent DrivingBone semantic
        ; path as the second proof and promote only when it agrees exactly.
        if generic.Status = "STRONG" && generic.TargetRVA >= 0 {
            SetResolverProgressAtLeast(0.47, "FName_ToString: checking DrivingBone call corroboration...")
            callProof := CorroborateFNameToStringTarget(pe, generic.TargetRVA)
            if callProof.Passed {
                generic.Status := "VERIFIED"
                generic.Validation := "Dominant multi-pattern consensus and an independent DrivingBone UTF-16/XREF callsite both converged on the same FName::ToString target."
                generic.SecondaryProof := callProof.Detail
                generic.Source .= " + DrivingBone call corroboration"
                return generic
            }

            SetResolverProgressAtLeast(0.50, "FName_ToString: corroborating consensus with semantic XREF path...")
            special := ResolveFNameToStringXref(pe)
            if IsUsableResolverResult(special) && special.TargetRVA = generic.TargetRVA {
                generic.Status := "VERIFIED"
                generic.Validation := "Dominant multi-pattern consensus and the independent DrivingBone UTF-16/XREF resolver converged on the same FName::ToString target."
                generic.SecondaryProof := HasProp(special, "Validation") ? special.Validation : "DrivingBone semantic resolver converged on the same target."
                generic.Source .= " + independent semantic corroboration"
            }
            return generic
        }

        if generic.Status = "NOT FOUND" || generic.Status = "AMBIGUOUS" {
            special := ResolveFNameToStringXref(pe)
            if IsUsableResolverResult(special)
                return special

            SetResolverProgressAtLeast(0.52, "FName_ToString: checking legacy SetEnums callsite family...")
            setEnums := ResolveFNameToStringLegacySetEnums(pe)
            if IsUsableResolverResult(setEnums)
                return setEnums

            SetResolverProgressAtLeast(0.55, "FName_ToString: trying legacy engine semantic anchors...")
            legacy := ResolveFNameToStringLegacyAnchors(pe)
            if IsUsableResolverResult(legacy)
                return legacy

            ; Native old-engine path: identify the lazy GNames singleton by
            ; behavior rather than adjacency, then decode callers for invariant
            ; pre-FNamePool chunk math and FName Number suffix handling. This
            ; handles compiler-split/chained runtime functions that defeat the
            ; historical exact getter AOBs.
            SetResolverProgressAtLeast(0.59, "FName_ToString: decoding pre-4.23 GNames semantics natively...")
            nativeLegacy := TryResolveNativeLegacyFNameToString(pe)
            if IsUsableResolverResult(nativeLegacy)
                return nativeLegacy

            ; Retain the interpreted implementation as a compatibility fallback
            ; if ScannerCore is unavailable or its generalized proof does not
            ; converge on a particular build.
            SetResolverProgressAtLeast(0.84, "FName_ToString: trying interpreted pre-4.23 GNames fallback...")
            gnamesSemantic := ResolveFNameToStringGNamesSemantic(pe)
            if IsUsableResolverResult(gnamesSemantic)
                return gnamesSemantic

            historical := TryResolveHistoricalResolverHint(pe, resolver.File)
            if IsObject(historical)
                return historical

            ; A miss should tell us which resolver families actually existed,
            ; rather than only reporting whichever fallback happened to run last.
            diag := BuildFNameToStringFailureDiagnostics(pe, special, setEnums, legacy, nativeLegacy, gnamesSemantic)
            if generic.Status = "AMBIGUOUS" {
                generic.Diagnostics := diag
                return generic
            }
            return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1,
                Diagnostics: diag, Source: "FName_ToString layered fallback",
                Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
        }
    }

    if resolver.File = "StaticConstructObject" && generic.Status = "STRONG" && generic.TargetRVA >= 0 {
        ; v0.26: newer UE builds can expose StaticConstructObject_Internal through
        ; the FStaticConstructObjectParameters-style parameter-pack ABI. A local
        ; or corpus AOB can nominate the target, but it remains STRONG until an
        ; independent decoded data-flow proof confirms that the function unpacks
        ; Class/Outer/Name/ObjectFlags, tests the loaded UClass with the long-lived
        ; 0x10000080 Native/Intrinsic mask, and reconstructs the allocation-call
        ; quartet from those exact fields. This is candidate-only corroboration: it
        ; cannot invent a new target or turn a merely-similar function green.
        SetResolverProgressAtLeast(0.40, "StaticConstructObject: checking parameter-pack structural corroboration...")
        packedProof := CorroborateNativeStaticConstructObject(pe, generic.TargetRVA)
        generic.SecondaryProof := packedProof.Detail
        if packedProof.Passed {
            generic.Status := "VERIFIED"
            generic.Validation := "Primary StaticConstructObject evidence and an independent decoded parameter-pack/UClass/allocation-flow proof converged on the same target."
            generic.Source .= " + native parameter-pack corroboration"
        }
        return generic
    }

    if resolver.File = "StaticConstructObject" && (generic.Status = "NOT FOUND" || generic.Status = "AMBIGUOUS") {
        ; Existing PatternSleuth evidence is a very cheap, very strong hint when it
        ; exists. Revalidate it against THIS executable before paying for semantic
        ; graph analysis. The address is never trusted by itself.
        SetResolverProgressAtLeast(0.38, "StaticConstructObject: checking prior local PatternSleuth evidence...")
        historical := TryResolveHistoricalResolverHint(pe, resolver.File)
        if IsObject(historical)
            return historical

        SetResolverProgressAtLeast(0.40, "StaticConstructObject: no reusable evidence; trying native semantic layer...")
        nativeSpecial := TryResolveNativeStaticConstructObject(pe)
        if IsUsableResolverResult(nativeSpecial)
            return nativeSpecial

        ; If ScannerCore actually completed a semantic pass, do NOT repeat the
        ; same whole-image archaeology in interpreted AHK. v0.10 could spend an
        ; additional 5-8 minutes doing that and almost never learned anything the
        ; native pass had not already tested. The AHK implementation is retained
        ; solely as a compatibility fallback when ScannerCore is unavailable or
        ; fails to execute at all.
        if IsObject(nativeSpecial) && HasProp(nativeSpecial, "NativeAttempted") && nativeSpecial.NativeAttempted {
            if generic.Status = "AMBIGUOUS"
                return generic
            return nativeSpecial
        }

        SetResolverProgressAtLeast(0.44, "StaticConstructObject: native core unavailable; using AHK compatibility fallback...")
        special := ResolveStaticConstructObjectSemantic(pe)
        if IsUsableResolverResult(special)
            return special
        if generic.Status = "AMBIGUOUS"
            return generic
        return special
    }

    if resolver.File = "GUObjectArray" && (generic.Status = "NOT FOUND" || generic.Status = "AMBIGUOUS") {
        SetResolverProgressAtLeast(0.40, "GUObjectArray: checking inlined object-count field layout...")
        structural := ResolveGUObjectArrayStatLayout(pe)
        if IsUsableResolverResult(structural)
            return structural

        ; Optimized/PGO/LTO builds can outline the diagnostic branches while the
        ; hot UObject paths directly touch FUObjectArray fields. Reconstructing
        ; the struct base from multiple independent semantic families avoids the
        ; old nearest-LEA heuristic accidentally selecting an internal lock.
        SetResolverProgressAtLeast(0.48, "GUObjectArray: checking outlined/LTO field clusters...")
        outlined := TryResolveNativeGUObjectArrayOutlined(pe)
        if IsUsableResolverResult(outlined)
            return outlined

        SetResolverProgressAtLeast(0.70, "GUObjectArray: tracing Allocate/FreeUObjectIndex semantic callsites...")
        semantic := ResolveGUObjectArrayMethodCallsites(pe)
        if IsUsableResolverResult(semantic) {
            if semantic.Status = "STRONG" && semantic.TargetRVA >= 0 {
                ; String diagnostics disappear surprisingly often in older/custom
                ; UE4 branches. First try a fully structural second proof: find a
                ; decoded LEA RCX,&candidate -> CALL path whose callee initializes
                ; the characteristic early-FUObjectArray field layout. This proof
                ; cannot invent a target; it only corroborates the semantic one.
                SetResolverProgressAtLeast(0.76, "GUObjectArray: checking native constructor-layout corroboration...")
                ctorProof := CorroborateNativeGUObjectArrayStructure(pe, semantic.TargetRVA)
                if ctorProof.Passed {
                    semantic.Status := "VERIFIED"
                    semantic.Validation .= " Independent decoded constructor-layout evidence initializes the same GUObjectArray global."
                    semantic.SecondaryProof := ctorProof.Detail
                    semantic.Source .= " + constructor-layout corroboration"
                    semantic.Diagnostics := ctorProof.Detail
                } else {
                    SetResolverProgressAtLeast(0.84, "GUObjectArray: seeking UObjectBaseShutdown corroboration...")
                    shutdownProof := CorroborateGUObjectArrayShutdown(pe, semantic.TargetRVA)
                    if shutdownProof.Passed {
                        semantic.Status := "VERIFIED"
                        semantic.Validation .= " Independent UObjectBaseShutdown string/XREF evidence references the same GUObjectArray global."
                        semantic.SecondaryProof := shutdownProof.Detail
                        semantic.Source .= " + UObjectBaseShutdown corroboration"
                    } else {
                        ; UObjectBaseShutdown is a newer engine proof and simply does
                        ; not exist on some old UE4 branches. FUObjectArray::AllocateObjectPool
                        ; is much older, and its fatal Max-UObject diagnostic gives us
                        ; another independently identifiable member function. Its caller
                        ; must materialize &GUObjectArray as RCX before the call.
                        SetResolverProgressAtLeast(0.88, "GUObjectArray: checking legacy AllocateObjectPool corroboration...")
                        poolProof := CorroborateGUObjectArrayAllocateObjectPool(pe, semantic.TargetRVA)
                        if poolProof.Passed {
                            semantic.Status := "VERIFIED"
                            semantic.Validation .= " Independent legacy AllocateObjectPool string/XREF/caller evidence materializes the same GUObjectArray global."
                            semantic.SecondaryProof := poolProof.Detail
                            semantic.Source .= " + AllocateObjectPool corroboration"
                        } else {
                            details := ctorProof.Detail " " shutdownProof.Detail " " poolProof.Detail
                            if HasProp(semantic, "Diagnostics") && semantic.Diagnostics != ""
                                semantic.Diagnostics .= " " details
                            else
                                semantic.Diagnostics := details
                        }
                    }
                }
            }
            return semantic
        }

        ; If the familiar object-count and Allocate/Free diagnostics are absent,
        ; older/custom UE4 can still expose GUObjectArray through its singleton
        ; constructor. This native path discovers the constructor by field-layout
        ; semantics first, then derives the writable global from a decoded
        ; LEA RCX,&global -> CALL constructor site. No strings or game RVAs.
        SetResolverProgressAtLeast(0.90, "GUObjectArray: trying string-independent native constructor discovery...")
        nativeDiscovery := TryResolveNativeGUObjectArrayDiscovery(pe)
        if IsUsableResolverResult(nativeDiscovery)
            return nativeDiscovery

        ; Preserve a genuinely ambiguous primary result if neither generalized
        ; fallback improved it. Otherwise prefer the richest semantic/native miss.
        if generic.Status = "AMBIGUOUS"
            return generic
        if IsObject(nativeDiscovery) && HasProp(nativeDiscovery, "Diagnostics")
            return nativeDiscovery
        if IsObject(semantic) && HasProp(semantic, "Diagnostics")
            return semantic
        return structural
    }

    if resolver.File = "ConsoleManager" && (generic.Status = "NOT FOUND" || generic.Status = "AMBIGUOUS") {
        semantic := ResolveOptionalSemanticRoot(pe, resolver.File, ["r.DumpingMovie", "vr.pixeldensity"])
        if IsUsableResolverResult(semantic)
            return semantic
    }

    if resolver.File = "GameEngineTick" && (generic.Status = "NOT FOUND" || generic.Status = "AMBIGUOUS") {
        semantic := ResolveOptionalSemanticRoot(pe, resolver.File, ["causeevent=", "CAUSEEVENT "])
        if IsUsableResolverResult(semantic)
            return semantic
    }

    if (resolver.File = "ProcessLocalScriptFunction"
        || resolver.File = "ProcessInternal"
        || resolver.File = "CallFunctionByNameWithArguments")
        && (generic.Status = "NOT FOUND" || generic.Status = "AMBIGUOUS") {
        ; These hook overrides have no safe, generalized static resolver in
        ; PatternSleuth. A nearby UE4SS runtime log is different evidence: it
        ; records the address selected by a real UE4SS initialization for this
        ; exact game installation. It is still accepted only after the current
        ; EXE revalidates a unique executable AOB at that RVA, so a stale log or
        ; changed game build cannot be promoted by address alone.
        SetResolverProgressAtLeast(0.40, resolver.File ": checking prior local UE4SS runtime evidence...")
        historical := TryResolveHistoricalResolverHint(pe, resolver.File)
        if IsObject(historical)
            return historical

        generic.Source := "UE4SS rare hook override"
        generic.Tier := 5
        generic.TierName := "Override-only target"
        generic.TierLabel := "T5 - Override-only target"
        generic.TierLocked := true
        note := "UE4SS recognizes this custom-signature override, but current upstream PatternSleuth does not expose a generalized resolver for it. Existing installed/custom signatures are imported and revalidated when present; the generator will not invent a weak AOB."
        if HasProp(generic, "Diagnostics") && generic.Diagnostics != ""
            generic.Diagnostics .= " " note
        else
            generic.Diagnostics := note
        return generic
    }

    return generic
}

ResolveOptionalSemanticRoot(pe, targetName, anchors) {
    roots := Map()
    anchorRoots := Map()
    hitCount := 0
    for anchor in anchors {
        info := FindSemanticStringRoots(pe, anchor, true)
        hitCount += info.StringCount
        for key, fn in info.Roots {
            roots[key] := fn
            if !anchorRoots.Has(key)
                anchorRoots[key] := 0
            anchorRoots[key] += 1
        }
    }
    if roots.Count = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1,
            Diagnostics: targetName " semantic anchors produced no containing runtime function.",
            Source: "PatternSleuth semantic string/XREF"}
    if roots.Count > 1 {
        bestKey := ""
        bestScore := 0
        tie := false
        for key, score in anchorRoots {
            if score > bestScore {
                bestKey := key
                bestScore := score
                tie := false
            } else if score = bestScore {
                tie := true
            }
        }
        if tie || bestScore < 2
            return {Status: "AMBIGUOUS", MatchCount: hitCount, TargetRVA: -1,
                Candidates: DescribeTargetCounts(anchorRoots),
                Diagnostics: targetName " anchors referenced multiple root functions without decisive consensus.",
                Source: "PatternSleuth semantic string/XREF"}
        targetRVA := ("0x" bestKey) + 0
    } else {
        targetRVA := -1
        bestScore := 0
        for key, fn in roots {
            targetRVA := fn.BeginRVA
            bestScore := anchorRoots.Get(key, 1)
        }
    }
    result := BuildUniqueDirectResult(pe, targetRVA, "PatternSleuth semantic string/XREF",
        targetName " was identified from Unreal diagnostic/console string XREFs and a unique executable root-function AOB.")
    result.MatchCount := hitCount
    result.Diagnostics := Format("{} anchor string hit(s); {} unique root function(s); winner support {} anchor family/families.", hitCount, roots.Count, bestScore)
    if result.Status = "STRONG" && bestScore >= 2 {
        result.Status := "VERIFIED"
        result.Validation := targetName " was independently identified by both upstream semantic anchor families and its generated function-entry AOB is unique."
    }
    return result
}

TryResolvePrioritySignature(pe, resolver) {
    for patternEntry in resolver.Patterns {
        if !IsObject(patternEntry) || !HasProp(patternEntry, "Source")
            continue

        source := patternEntry.Source
        isPriority := InStr(source, "Existing local custom signature:") = 1
            || InStr(source, "Known custom corpus:") = 1
        if !isPriority
            continue

        patternText := patternEntry.Pattern
        mode := patternEntry.Mode
        add := HasProp(patternEntry, "Add") ? patternEntry.Add : 0
        parsed := ParsePattern(patternText)
        matches := ScanPE(pe, parsed, 2)
        if matches.Length != 1
            continue

        match := matches[1]
        targetRVA := -1
        if mode = "direct" {
            targetRVA := match.RVA + add
        } else if mode = "rel32" {
            if parsed.Marker < 0
                continue
            dispRaw := match.Raw + parsed.Marker
            if dispRaw < 0 || dispRaw + 4 > pe.Size
                continue
            disp := NumGet(pe.Data, dispRaw, "Int")
            targetRVA := match.RVA + parsed.Marker + 4 + disp + add
        }

        if targetRVA < 0 || !RvaInImage(pe, targetRVA)
            continue

        candidate := {
            TargetRVA: targetRVA,
            Pattern: patternText,
            Parsed: parsed,
            PatternMatches: 1,
            MatchRaw: match.Raw,
            MatchRVA: match.RVA,
            MatchSection: match.Section,
            Mode: mode,
            Add: add,
            Source: source
        }
        validation := ValidateCandidate(pe, resolver, candidate)
        if validation.Status != "VERIFIED"
            continue

        return {
            Status: "VERIFIED",
            MatchCount: 1,
            TargetRVA: targetRVA,
            AOB: PatternForUE4SS(patternText),
            Pattern: patternText,
            Marker: parsed.Marker,
            MatchRVA: match.RVA,
            MatchSection: match.Section,
            TargetSection: SectionForRVA(pe, targetRVA),
            Validation: validation.Detail " Existing known signature revalidated uniquely before generic fallbacks were scanned.",
            ActualBytes: BytesAt(pe, match.Raw, parsed.Length),
            Mode: mode,
            Add: add,
            Source: source " (revalidated fast path)"
        }
    }
    return ""
}

ResolveTargetGeneric(pe, resolver) {
    priority := TryResolvePrioritySignature(pe, resolver)
    if IsObject(priority)
        return priority

    targetCounts := Map()
    candidates := []
    totalMatches := 0

    for patternIndex, patternEntry in resolver.Patterns {
        if resolver.Patterns.Length > 0
            SetResolverProgress(0.04 + (patternIndex / resolver.Patterns.Length) * 0.28, "Scanning " resolver.File " pattern " patternIndex "/" resolver.Patterns.Length "...")
        if IsObject(patternEntry) {
            patternText := patternEntry.Pattern
            mode := patternEntry.Mode
            add := HasProp(patternEntry, "Add") ? patternEntry.Add : 0
            source := HasProp(patternEntry, "Source") ? patternEntry.Source : "database"
        } else {
            patternText := patternEntry
            mode := resolver.Mode
            add := resolver.Add
            source := "legacy database"
        }

        parsed := ParsePattern(patternText)
        matches := ScanPE(pe, parsed, 32)
        if matches.Length = 0
            continue

        for match in matches {
            totalMatches += 1
            targetRVA := -1

            if (mode = "direct") {
                targetRVA := match.RVA + add
            } else if (mode = "rel32") {
                if parsed.Marker < 0
                    continue
                dispRaw := match.Raw + parsed.Marker
                if (dispRaw < 0 || dispRaw + 4 > pe.Size)
                    continue
                disp := NumGet(pe.Data, dispRaw, "Int")
                targetRVA := match.RVA + parsed.Marker + 4 + disp + add
            }

            if targetRVA < 0 || !RvaInImage(pe, targetRVA)
                continue

            key := Format("{:X}", targetRVA)
            targetCounts[key] := targetCounts.Get(key, 0) + 1
            candidates.Push({
                TargetRVA: targetRVA,
                Pattern: patternText,
                Parsed: parsed,
                PatternMatches: matches.Length,
                MatchRaw: match.Raw,
                MatchRVA: match.RVA,
                MatchSection: match.Section,
                Mode: mode,
                Add: add,
                Source: source
            })
        }
    }

    if targetCounts.Count = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    if targetCounts.Count > 1 {
        ; v0.5: FName::ToString often produces several valid callsites that mostly
        ; converge on one function plus a small number of optimizer-shaped outliers.
        ; Treat a dominant, structurally validated target as consensus rather than
        ; throwing away all evidence simply because one alternate target exists.
        if resolver.File = "FName_ToString" {
            consensus := TryBuildFNameToStringConsensus(pe, resolver, candidates, targetCounts, totalMatches)
            if IsObject(consensus)
                return consensus
        }
        return {Status: "AMBIGUOUS", MatchCount: totalMatches, TargetRVA: -1, Candidates: DescribeTargetCounts(targetCounts)}
    }

    targetRVA := candidates[1].TargetRVA

    ; Prefer the candidate pattern with the fewest matches in this EXE.
    best := ""
    bestCount := 0x7FFFFFFF
    for candidate in candidates {
        if (candidate.TargetRVA = targetRVA && candidate.PatternMatches < bestCount) {
            best := candidate
            bestCount := candidate.PatternMatches
        }
    }

    if !IsObject(best)
        return {Status: "AMBIGUOUS", MatchCount: totalMatches, TargetRVA: -1}

    validation := ValidateCandidate(pe, resolver, best)
    aob := PatternForUE4SS(best.Pattern)
    return {
        Status: validation.Status,
        MatchCount: best.PatternMatches,
        TargetRVA: targetRVA,
        AOB: aob,
        Pattern: best.Pattern,
        Marker: best.Parsed.Marker,
        MatchRVA: best.MatchRVA,
        MatchSection: best.MatchSection,
        TargetSection: SectionForRVA(pe, targetRVA),
        Validation: validation.Detail,
        ActualBytes: BytesAt(pe, best.MatchRaw, best.Parsed.Length),
        Mode: best.Mode,
        Add: best.Add,
        Source: best.Source
    }
}


DescribeTargetCounts(targetCounts) {
    out := ""
    shown := 0
    for key, count in targetCounts {
        if out != ""
            out .= ", "
        out .= "0x" key " (" count ")"
        shown += 1
        if shown >= 16 {
            if targetCounts.Count > shown
                out .= ", ..."
            break
        }
    }
    return out
}

TryBuildFNameToStringConsensus(pe, resolver, candidates, targetCounts, totalMatches) {
    topKey := ""
    topCount := 0
    secondCount := 0

    for key, count in targetCounts {
        if count > topCount {
            secondCount := topCount
            topCount := count
            topKey := key
        } else if count > secondCount {
            secondCount := count
        }
    }

    if topKey = "" || totalMatches <= 0
        return ""

    ratio := topCount / totalMatches

    ; Require meaningful independent support and a decisive lead. The Double
    ; Exposure v0.4 case is 8/9 (88.9%) against a single outlier.
    if topCount < 3 || ratio < 0.75
        return ""
    if secondCount > 0 && topCount < secondCount * 2
        return ""

    targetRVA := ("0x" topKey) + 0
    if !IsExecutableRVA(pe, targetRVA)
        return ""

    fn := FindRuntimeFunction(pe, targetRVA)
    exactPdataStart := fn.BeginRVA = targetRVA
    if !exactPdataStart {
        ; Chained/overlapping unwind ranges are common enough that .pdata is not a
        ; universal function-start oracle. For a >=90% consensus, independently
        ; prove that several distinct E8 callsites land on the exact address and
        ; that the address begins with a normal x64 function-entry shape.
        verifiedConsensus := VerifyFNameToStringConsensusWithoutPdata(pe, targetRVA, candidates, topCount, totalMatches, secondCount)
        if IsObject(verifiedConsensus)
            return verifiedConsensus

        ; If the stronger proof does not pass, preserve the old STRONG behavior.
        if topCount < 5 || ratio < 0.90
            return ""
        result := BuildUniqueDirectResult(pe, targetRVA,
            "PatternSleuth multi-pattern consensus (no exact .pdata entry)",
            Format("Consensus {}/{} resolver hits ({}%) converged on one executable target; exact .pdata entry could not be independently confirmed.", topCount, totalMatches, Round(ratio * 100, 1)))
        if result.Status = "STRONG" {
            result.MatchCount := totalMatches
            result.Consensus := Format("0x{:X}: {} of {} hits; runner-up support {}.", targetRVA, topCount, totalMatches, secondCount)
            return result
        }
        return ""
    }

    ; Manufacture a unique callsite signature from one of the winning E8
    ; callsites instead of returning the broad database pattern that matched
    ; several places.
    for candidate in candidates {
        if candidate.TargetRVA != targetRVA || candidate.Mode != "rel32"
            continue

        marker := candidate.Parsed.Marker
        if marker < 1
            continue

        opcodeRaw := candidate.MatchRaw + marker - 1
        if ByteAt(pe, opcodeRaw) != 0xE8
            continue

        callRVA := candidate.MatchRVA + marker - 1
        detail := Format(
            "Consensus {}/{} resolver hits ({}%) converged on one .pdata function start; the remaining {} hit(s) were outliers.",
            topCount, totalMatches, Round(ratio * 100, 1), totalMatches - topCount)

        result := BuildUniqueCallResult(
            pe,
            callRVA,
            targetRVA,
            "PatternSleuth multi-pattern consensus",
            detail
        )

        if result.Status = "VERIFIED" {
            result.MatchCount := totalMatches
            result.Consensus := Format("0x{:X}: {} of {} hits; runner-up support {}.", targetRVA, topCount, totalMatches, secondCount)
            result.Validation := detail " Generated callsite AOB is unique and the selected E8 rel32 target is structurally validated."
            return result
        }
    }

    ; A direct target-entry AOB is still useful if no winning callsite can be
    ; safely isolated, but keep it STRONG instead of claiming rel32 validation.
    result := BuildUniqueDirectResult(
        pe,
        targetRVA,
        "PatternSleuth multi-pattern consensus",
        Format("Consensus {}/{} resolver hits ({}%) converged on one .pdata function start.", topCount, totalMatches, Round(ratio * 100, 1))
    )
    if result.Status = "STRONG" {
        result.MatchCount := totalMatches
        result.Consensus := Format("0x{:X}: {} of {} hits; runner-up support {}.", targetRVA, topCount, totalMatches, secondCount)
        return result
    }

    return ""
}

VerifyFNameToStringConsensusWithoutPdata(pe, targetRVA, candidates, topCount, totalMatches, secondCount) {
    ratio := totalMatches > 0 ? topCount / totalMatches : 0
    if topCount < 5 || ratio < 0.90
        return ""

    callsites := Map()
    for candidate in candidates {
        if candidate.TargetRVA != targetRVA || candidate.Mode != "rel32"
            continue
        marker := candidate.Parsed.Marker
        if marker < 1
            continue
        opcodeRaw := candidate.MatchRaw + marker - 1
        if opcodeRaw < 0 || ByteAt(pe, opcodeRaw) != 0xE8
            continue
        if ResolveRel32AtRaw(pe, opcodeRaw) != targetRVA
            continue
        callRVA := RawToRva(pe, opcodeRaw)
        if callRVA >= 0
            callsites[Format("{:X}", callRVA)] := true
    }

    ; Multiple distinct callers are a substantially stronger signal than several
    ; pattern families rediscovering one callsite.
    if callsites.Count < 3
        return ""

    entryProof := CommonX64FunctionEntryProof(pe, targetRVA)
    if !entryProof.Passed
        return ""

    result := BuildUniqueDirectResult(pe, targetRVA,
        "PatternSleuth multi-pattern consensus + direct-call corroboration",
        Format("Consensus {}/{} resolver hits ({}%) converged on one executable address; {} distinct E8 rel32 callsites independently land on that exact address. {}",
            topCount, totalMatches, Round(ratio * 100, 1), callsites.Count, entryProof.Detail))

    if result.Status = "STRONG" {
        result.Status := "VERIFIED"
        result.MatchCount := totalMatches
        result.Consensus := Format("0x{:X}: {} of {} hits; {} unique direct callsites; runner-up support {}.", targetRVA, topCount, totalMatches, callsites.Count, secondCount)
        result.Validation := Format("Dominant multi-pattern consensus plus {} independent direct E8 callsites and a normal function-entry shape verify the target without relying on an exact .pdata start.", callsites.Count)
        return result
    }
    return ""
}

CommonX64FunctionEntryProof(pe, targetRVA) {
    raw := RvaToRaw(pe, targetRVA)
    if raw < 0 || !IsExecutableRVA(pe, targetRVA)
        return {Passed: false, Detail: "Target is not executable."}

    ; Common MSVC/Clang Win64 entry shapes. This is deliberately structural, not
    ; tied to one game or one Unreal version.
    shapes := [
        [0x48,0x89,0x5C,0x24],
        [0x48,0x8B,0xC4],
        [0x48,0x83,0xEC],
        [0x40,0x53],
        [0x40,0x55],
        [0x53,0x48,0x83,0xEC],
        [0x56,0x57,0x48,0x83,0xEC],
        [0x41,0x57,0x41,0x56],
        [0x41,0x56,0x41,0x55],
        [0x41,0x55,0x41,0x54]
    ]
    for shape in shapes {
        if BytesEqual(pe, raw, shape)
            return {Passed: true, Detail: "Target begins with a recognized Win64 function-entry/prologue shape."}
    }
    return {Passed: false, Detail: "Target does not begin with one of the recognized Win64 function-entry shapes."}
}

ResolveFNameConstructorXref(pe) {
    strings := ["TGPUSkinVertexFactoryUnlimited", "MovementComponent0"]
    candidates := Map()
    evidence := []

    for text in strings {
        stringRVAs := FindUtf16Rvas(pe, text, true)
        for stringRVA in stringRVAs {
            refs := FindRipLeaRefs(pe, stringRVA, 0x15)
            for ref in refs {
                xraw := ref.Raw

                ; PatternSleuth Direct:
                ; 48 8D 15 <string> 48 8D 0D <disp32> E8 <ctor>
                if BytesEqual(pe, xraw + 7, [0x48,0x8D,0x0D]) && ByteAt(pe, xraw + 14) = 0xE8 {
                    target := ResolveRel32AtRaw(pe, xraw + 14)
                    AddFNameEvidence(pe, candidates, evidence, target, "PatternSleuth UTF-16/XREF direct CALL")
                }

                ; PatternSleuth Direct tail-jump variant:
                ; 41 B8 01 00 00 00 48 8D 15 <string> 48 8D 0D <disp32> E9 <ctor>
                if (xraw >= 6
                    && BytesEqual(pe, xraw - 6, [0x41,0xB8,0x01,0x00,0x00,0x00])
                    && BytesEqual(pe, xraw + 7, [0x48,0x8D,0x0D])
                    && ByteAt(pe, xraw + 14) = 0xE9) {
                    target := ResolveRel32AtRaw(pe, xraw + 14)
                    AddFNameEvidence(pe, candidates, evidence, target, "PatternSleuth UTF-16/XREF direct JMP")
                }

                ; PatternSleuth FirstCall:
                ; 48 8D 15 <string> 4C 8D 05 <disp32> 41 B1 01 E8 <helper>
                ; Resolve the helper, then take its first CALL target.
                if (BytesEqual(pe, xraw + 7, [0x4C,0x8D,0x05])
                    && BytesEqual(pe, xraw + 14, [0x41,0xB1,0x01])
                    && ByteAt(pe, xraw + 17) = 0xE8) {
                    helper := ResolveRel32AtRaw(pe, xraw + 17)
                    firstCall := FindFirstCallTarget(pe, helper, 0x200)
                    if firstCall.TargetRVA >= 0
                        AddFNameEvidence(pe, candidates, evidence, firstCall.TargetRVA, "PatternSleuth UTF-16/XREF FirstCall")
                }
            }
        }
    }

    if candidates.Count = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}
    if candidates.Count > 1
        return {Status: "AMBIGUOUS", MatchCount: evidence.Length, TargetRVA: -1, Candidates: DescribeTargetCounts(candidates)}

    targetRVA := -1
    source := "PatternSleuth UTF-16/XREF fallback"
    for key, count in candidates
        targetRVA := ("0x" key) + 0
    for ev in evidence {
        if ev.TargetRVA = targetRVA {
            source := ev.Source
            break
        }
    }

    result := BuildUniqueDirectResult(pe, targetRVA, source,
        "UTF-16 anchor + RIP-relative XREF chain resolved one constructor target; generated target-entry AOB is unique in executable code.")

    ; v0.5.2: A semantic XREF chain tells us where the constructor should be,
    ; while this second, independent proof inspects the target function body.
    ; Only promote STRONG -> VERIFIED when both forms of evidence converge.
    if result.Status = "STRONG" {
        bodyProof := VerifyFNameConstructorBody(pe, targetRVA)
        if bodyProof.Passed {
            result.Status := "VERIFIED"
            result.Validation := "Independent constructor proofs converged: semantic UTF-16/RIP-relative XREF resolution selected this target, and the target body matches an FName(wchar_t*, EFindName)-shaped x64 constructor fingerprint at an exact .pdata function start. Generated target-entry AOB is unique."
            result.SecondaryProof := bodyProof.Detail
            result.Source := source " + constructor-body fingerprint"
        } else {
            result.SecondaryProof := bodyProof.Detail
            SetResolverProgressAtLeast(0.48, "FName_Constructor: checking native wchar-wrapper corroboration...")
            wrapperProof := CorroborateNativeFNameConstructor(pe, targetRVA)
            if wrapperProof.Passed {
                result.Status := "VERIFIED"
                result.Validation := "Independent constructor proofs converged: semantic UTF-16/RIP-relative XREF resolution selected this target, and native decoded wrapper/helper analysis proved FName(wchar_t*, EFindName) argument forwarding plus wchar_t consumption. Generated target-entry AOB is unique."
                result.SecondaryProof := wrapperProof.Detail
                result.Source := source " + native wchar-wrapper corroboration"
            } else {
                result.SecondaryProof .= " " wrapperProof.Detail
                result.Validation .= " Secondary constructor-body and native wchar-wrapper proofs did not pass, so the result remains STRONG rather than VERIFIED."
            }
        }
    }

    return result
}


VerifyFNameConstructorDirectPatternFast(pe, result) {
    if !IsObject(result) || result.TargetRVA < 0
        return {Passed: false, Detail: "No usable constructor candidate."}
    if !HasProp(result, "Pattern") || !HasProp(result, "Source") || !HasProp(result, "Mode")
        return {Passed: false, Detail: "Constructor candidate lacks direct-pattern metadata."}
    if result.Mode != "direct" || result.MatchCount != 1
        return {Passed: false, Detail: "Constructor fast verification requires one unique direct match."}
    if InStr(result.Source, "PatternSleuth direct prologue") != 1
        return {Passed: false, Detail: "Candidate is not a full PatternSleuth direct constructor prologue."}

    ; Keep this tied to PatternSleuth's two current PE FNameCtorWchar prologues,
    ; not merely to the human-readable Source label. Both signatures encode the
    ; constructor's Win64 entry, EFindName preservation, incoming wchar_t* test,
    ; 16-bit read, and zero test in one long structural fingerprint.
    normalized := StrUpper(RegExReplace(Trim(result.Pattern), "\s+", " "))
    p1 := "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 41 8B F8 33 C9 4C 8B DA 44 8B D1 4C 8B CA 48 85 D2 74 ?? 0F B7 02 66 85 C0"
    p2 := "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 48 89 54 24 20 33 C9 41 8B F8 4C 8B D2 44 8B C9 48 85 D2 74 ?? 0F B7 02 66 85 C0"
    if normalized != p1 && normalized != p2
        return {Passed: false, Detail: "Candidate source is direct-prologue-like, but its AOB is not one of the full PatternSleuth PE constructor fingerprints."}

    if !IsExecutableRVA(pe, result.TargetRVA)
        return {Passed: false, Detail: "Direct constructor candidate is not executable."}

    ; PatternSleuth's own PE resolver accepts either complete constructor prologue
    ; directly and does not require .pdata to agree. Chained/overlapping Win64
    ; unwind records can make a real function entry fail our exact-start test,
    ; which was forcing Reunion down the ~44 second semantic path for no gain.
    return {
        Passed: true,
        Detail: "Unique full PatternSleuth FName(wchar_t const*, EFindName) direct prologue matched at an executable address; the long fingerprint itself encodes EFindName preservation plus wchar_t null/read/test behavior, so .pdata corroboration and the expensive semantic XREF fallback are unnecessary."
    }
}

VerifyFNameConstructorBody(pe, targetRVA) {
    if !IsExecutableRVA(pe, targetRVA)
        return {Passed: false, Detail: "Target is not in an executable PE section."}
    if !IsRuntimeFunctionStart(pe, targetRVA)
        return {Passed: false, Detail: "Target is not an exact .pdata runtime-function start."}

    raw := RvaToRaw(pe, targetRVA)
    if raw < 0
        return {Passed: false, Detail: "Target RVA could not be mapped to file bytes."}

    ; Both current PatternSleuth PE constructor prologues begin with this
    ; non-trivial Win64 shape: save RBX, PUSH RDI, reserve 0x30 bytes, and
    ; preserve the object pointer from RCX in RBX.
    commonPrefix := [0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x30,0x48,0x8B,0xD9]
    if !BytesEqual(pe, raw, commonPrefix)
        return {Passed: false, Detail: "Target does not match the known FName constructor common prologue."}

    ; Verify constructor-specific argument handling independently of the XREF:
    ;   RDX  = wchar_t* name
    ;   R8D  = EFindName
    ; and the body checks the incoming wide string. Compiler revisions can
    ; reorder a few moves, so look for semantic opcode fragments in a bounded
    ; window rather than demanding one byte-for-byte full prologue.
    hasSaveName := ContainsBytes(pe, raw + 13, 28, [0x48,0x89,0x54,0x24,0x20])
    hasFindName := ContainsBytes(pe, raw + 13, 36, [0x41,0x8B,0xF8])
    hasNameTest := ContainsBytes(pe, raw + 13, 48, [0x48,0x85,0xD2])
    hasWideRead := ContainsBytes(pe, raw + 13, 64, [0x0F,0xB7,0x02])
    hasWideTest := ContainsBytes(pe, raw + 13, 68, [0x66,0x85,0xC0])

    ; PatternSleuth's other known constructor layout can omit the stack save
    ; above while still preserving R8D and performing the same wchar checks.
    variantA := hasFindName && hasNameTest && hasWideRead && hasWideTest
    variantB := hasSaveName && hasFindName && hasNameTest && hasWideRead && hasWideTest

    if !(variantA || variantB) {
        detail := Format(
            "Body fingerprint incomplete: save-name={}, EFindName={}, name-test={}, wchar-read={}, wchar-test={}.",
            hasSaveName ? "yes" : "no", hasFindName ? "yes" : "no", hasNameTest ? "yes" : "no", hasWideRead ? "yes" : "no", hasWideTest ? "yes" : "no")
        return {Passed: false, Detail: detail}
    }

    variant := variantB ? "PatternSleuth PE constructor layout B" : "PatternSleuth PE constructor layout A"
    return {
        Passed: true,
        Detail: variant " verified independently at target entry: common prologue + EFindName preservation + wchar_t null/read/test behavior; target is an exact executable .pdata function start."
    }
}

ContainsBytes(pe, startRaw, maxBytes, needle) {
    if startRaw < 0 || maxBytes <= 0 || needle.Length = 0
        return false
    endRaw := Min(pe.Size, startRaw + maxBytes)
    raw := startRaw
    while raw + needle.Length <= endRaw {
        if BytesEqual(pe, raw, needle)
            return true
        raw += 1
    }
    return false
}


ResolveFNameConstructorModuleAnchors(pe) {
    ; Additional PatternSleuth-inspired fallback. Its ELF resolver identifies
    ; FEngineLoop::LoadPreInitModules from a cluster of common module FNames.
    ; On PE we can use the same semantic anchors, .pdata boundaries, and the
    ; Windows x64 calling convention (EFindName in R8D) to locate constructor calls.
    anchors := ["Engine", "Renderer", "AnimGraphRuntime", "Landscape", "RenderCore"]
    rootAnchors := Map()
    anchorHits := Map()

    for anchor in anchors {
        rootsSeen := Map()
        stringRVAs := FindUtf16Rvas(pe, anchor, true)
        anchorHits[anchor] := stringRVAs.Length

        for stringRVA in stringRVAs {
            for ref in FindRipLeaRefsAny(pe, stringRVA) {
                fn := FindRuntimeFunction(pe, ref.RVA)
                if fn.BeginRVA < 0
                    continue
                key := Format("{:X}", fn.BeginRVA)
                rootsSeen[key] := true
            }
        }

        for key, dummy in rootsSeen {
            if !rootAnchors.Has(key)
                rootAnchors[key] := Map()
            rootAnchors[key][anchor] := true
        }
    }

    bestAnchorCount := 0
    candidateRoots := []
    for key, set in rootAnchors {
        count := set.Count
        if count > bestAnchorCount {
            bestAnchorCount := count
            candidateRoots := [("0x" key) + 0]
        } else if count = bestAnchorCount {
            candidateRoots.Push(("0x" key) + 0)
        }
    }

    diag := "UTF-16 anchor occurrences: "
    for i, anchor in anchors {
        if i > 1
            diag .= ", "
        diag .= anchor "=" anchorHits.Get(anchor, 0)
    }
    diag .= Format("; best common .pdata root references {}/5 anchors.", bestAnchorCount)

    if bestAnchorCount < 3 || candidateRoots.Length = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, Diagnostics: diag}

    evidence := []
    targetCounts := Map()

    for rootRVA in candidateRoots {
        fn := FindRuntimeFunction(pe, rootRVA)
        if fn.BeginRVA < 0
            continue

        calls := FindFNameCtorStyleCalls(pe, fn.BeginRVA, fn.EndRVA)
        for call in calls {
            key := Format("{:X}", call.TargetRVA)
            targetCounts[key] := targetCounts.Get(key, 0) + 1
            evidence.Push(call)
        }
    }

    if targetCounts.Count = 0 {
        diag .= " No R8D=1 -> CALL rel32 constructor-shaped call was found in the anchor-rich root function(s)."
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1, Diagnostics: diag}
    }

    topKey := ""
    topCount := 0
    secondCount := 0
    for key, count in targetCounts {
        if count > topCount {
            secondCount := topCount
            topCount := count
            topKey := key
        } else if count > secondCount {
            secondCount := count
        }
    }

    targetRVA := ("0x" topKey) + 0
    if !IsExecutableRVA(pe, targetRVA) || !IsRuntimeFunctionStart(pe, targetRVA) {
        diag .= " Best target was not an executable .pdata function start."
        return {Status: "AMBIGUOUS", MatchCount: evidence.Length, TargetRVA: -1, Candidates: DescribeTargetCounts(targetCounts), Diagnostics: diag}
    }

    ; If several constructor-shaped calls exist, demand a real lead.
    if targetCounts.Count > 1 && (topCount < 2 || topCount < secondCount * 2) {
        return {Status: "AMBIGUOUS", MatchCount: evidence.Length, TargetRVA: -1, Candidates: DescribeTargetCounts(targetCounts), Diagnostics: diag}
    }

    for call in evidence {
        if call.TargetRVA != targetRVA
            continue

        detail := Format(
            "Module-name semantic fallback: a .pdata function referencing {}/5 common engine module FNames contains an R8D=1 constructor-shaped CALL to this target.",
            bestAnchorCount)

        result := BuildUniqueCallResult(
            pe,
            call.CallRVA,
            targetRVA,
            "Engine-module UTF-16/.pdata semantic fallback",
            detail
        )

        if result.Status = "VERIFIED" {
            result.MatchCount := evidence.Length
            result.Consensus := Format("Target 0x{:X} received {} constructor-shaped call evidence hit(s); runner-up support {}.", targetRVA, topCount, secondCount)
            result.Diagnostics := diag

            ; Four or five semantic anchors is strong enough for green. Three
            ; anchors remains yellow because the identity evidence is thinner.
            if bestAnchorCount < 4 {
                result.Status := "UNVERIFIED"
                result.Validation := detail " Address decoding is valid, but only three semantic anchors converged, so symbol identity remains provisional."
            } else {
                result.Validation := detail " Generated callsite AOB is unique and E8 rel32 decoding is validated."
            }
            return result
        }
    }

    diag .= " Constructor target was plausible, but a unique generated callsite AOB could not be manufactured."
    return {Status: "NOT FOUND", MatchCount: evidence.Length, TargetRVA: -1, Candidates: DescribeTargetCounts(targetCounts), Diagnostics: diag}
}

FindRipLeaRefsAny(pe, targetRVA) {
    return FindIndexedRipLeaRefs(pe, targetRVA)
}

FindFNameCtorStyleCalls(pe, beginRVA, endRVA) {
    beginRaw := RvaToRaw(pe, beginRVA)
    endRaw := RvaToRaw(pe, endRVA - 1)
    out := []
    if beginRaw < 0 || endRaw < 0 || endRaw <= beginRaw
        return out
    endRaw += 1

    raw := beginRaw
    lastYield := A_TickCount
    while raw + 11 <= endRaw {
        CooperativeScanYield(&lastYield)

        ; Windows x64 member call: RCX=this, RDX=wchar*, R8D=EFindName.
        ; PatternSleuth's PE fallbacks commonly materialize FNAME_Add as
        ; "41 B8 01 00 00 00" before the constructor CALL.
        if BytesEqual(pe, raw, [0x41,0xB8,0x01,0x00,0x00,0x00]) {
            searchEnd := Min(endRaw, raw + 64)
            p2 := raw + 6
            while p2 + 5 <= searchEnd {
                if ByteAt(pe, p2) = 0xE8 {
                    callRVA := RawToRva(pe, p2)
                    target := ResolveRel32AtRaw(pe, p2)
                    if target >= 0 && IsExecutableRVA(pe, target) && IsRuntimeFunctionStart(pe, target) {
                        out.Push({CallRVA: callRVA, TargetRVA: target})
                        break
                    }
                }
                p2 += 1
            }
        }
        raw += 1
    }
    return out
}

ResolveFNameToStringXref(pe) {
    ; Current PatternSleuth PE fallback anchors GatherDebugData with this UTF-16 text,
    ; finds its root function, then resolves the last CALL above the string reference.
    stringRVAs := FindUtf16Rvas(pe, "  DrivingBone: %s`nDrivenParamet", false)
    if stringRVAs.Length = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    rootCounts := Map()
    refs := []
    for stringRVA in stringRVAs {
        for ref in FindRipLeaRefs(pe, stringRVA, 0x15) {
            fn := FindRuntimeFunction(pe, ref.RVA)
            if fn.BeginRVA < 0
                continue
            key := Format("{:X}", fn.BeginRVA)
            rootCounts[key] := rootCounts.Get(key, 0) + 1
            refs.Push({Ref: ref, Fn: fn})
        }
    }

    if rootCounts.Count = 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}
    if rootCounts.Count > 1
        return {Status: "AMBIGUOUS", MatchCount: refs.Length, TargetRVA: -1, Candidates: DescribeTargetCounts(rootCounts)}

    rootRVA := -1
    for key, count in rootCounts
        rootRVA := ("0x" key) + 0

    targetCounts := Map()
    callEvidence := []
    for item in refs {
        if item.Fn.BeginRVA != rootRVA
            continue
        call := FindLastCallTarget(pe, item.Fn.BeginRVA, item.Ref.RVA)
        if call.TargetRVA < 0
            continue
        key := Format("{:X}", call.TargetRVA)
        targetCounts[key] := targetCounts.Get(key, 0) + 1
        callEvidence.Push(call)
    }

    if targetCounts.Count = 0
        return {Status: "NOT FOUND", MatchCount: refs.Length, TargetRVA: -1}
    if targetCounts.Count > 1
        return {Status: "AMBIGUOUS", MatchCount: callEvidence.Length, TargetRVA: -1, Candidates: DescribeTargetCounts(targetCounts)}

    targetRVA := -1
    for key, count in targetCounts
        targetRVA := ("0x" key) + 0

    for call in callEvidence {
        if call.TargetRVA = targetRVA {
            result := BuildUniqueCallResult(pe, call.CallRVA, targetRVA,
                "PatternSleuth DrivingBone UTF-16/XREF fallback",
                "UTF-16 anchor + .pdata root function + last CALL above XREF converged on one executable target.")
            if result.Status != "NOT FOUND"
                return result
        }
    }

    return BuildUniqueDirectResult(pe, targetRVA,
        "PatternSleuth DrivingBone UTF-16/XREF fallback",
        "UTF-16 anchor + .pdata root function + last CALL above XREF converged on one target; target-entry AOB is unique.")
}

CorroborateFNameToStringTarget(pe, targetRVA) {
    stringRVAs := FindUtf16Rvas(pe, "  DrivingBone: %s`nDrivenParamet", false)
    if stringRVAs.Length = 0
        return {Passed: false, Detail: "DrivingBone UTF-16 anchor was not present."}

    for stringRVA in stringRVAs {
        for ref in FindRipLeaRefs(pe, stringRVA, 0x15) {
            fn := FindRuntimeFunction(pe, ref.RVA)
            if fn.BeginRVA < 0
                continue

            beginRaw := RvaToRaw(pe, fn.BeginRVA)
            refRaw := RvaToRaw(pe, ref.RVA)
            if beginRaw < 0 || refRaw <= beginRaw
                continue

            raw := beginRaw
            lastYield := A_TickCount
            while raw + 5 <= refRaw {
                CooperativeScanYield(&lastYield)
                if ByteAt(pe, raw) = 0xE8 {
                    siteRVA := RawToRva(pe, raw)
                    disp := NumGet(pe.Data, raw + 1, "Int")
                    if siteRVA + 5 + disp = targetRVA {
                        return {
                            Passed: true,
                            Detail: Format("DrivingBone UTF-16 anchor resolves to .pdata root 0x{:X}, which contains an E8 rel32 CALL directly to consensus target 0x{:X} before the string XREF.", fn.BeginRVA, targetRVA)
                        }
                    }
                }
                raw += 1
            }
        }
    }
    return {Passed: false, Detail: "DrivingBone semantic root did not contain a direct rel32 call to the consensus target."}
}

AddFNameEvidence(pe, candidates, evidence, targetRVA, source) {
    if targetRVA < 0 || !RvaInImage(pe, targetRVA) || !IsExecutableRVA(pe, targetRVA)
        return
    key := Format("{:X}", targetRVA)
    candidates[key] := candidates.Get(key, 0) + 1
    evidence.Push({TargetRVA: targetRVA, Source: source})
}

FindUtf16Rvas(pe, text, includeNull := true) {
    if !HasProp(pe, "Utf16RvaCache")
        pe.Utf16RvaCache := Map()
    cacheKey := (includeNull ? "1|" : "0|") text
    if pe.Utf16RvaCache.Has(cacheKey)
        return pe.Utf16RvaCache[cacheKey]

    patternText := Utf16PatternText(text, includeNull)
    parsed := ParsePattern(patternText)
    matches := ScanPEAll(pe, parsed, 64)
    out := []
    for match in matches
        out.Push(match.RVA)
    pe.Utf16RvaCache[cacheKey] := out
    return out
}

Utf16PatternText(text, includeNull := true) {
    out := ""
    Loop StrLen(text) {
        code := Ord(SubStr(text, A_Index, 1))
        if out != ""
            out .= " "
        out .= Format("{:02X} {:02X}", code & 0xFF, (code >> 8) & 0xFF)
    }
    if includeNull {
        if out != ""
            out .= " "
        out .= "00 00"
    }
    return out
}

ScanPEAll(pe, parsed, maxMatches := 64) {
    if !HasProp(pe, "AllScanCache")
        pe.AllScanCache := Map()
    cacheKey := parsed.CacheKey "|" maxMatches
    if pe.AllScanCache.Has(cacheKey)
        return pe.AllScanCache[cacheKey]

    results := []
    for section in pe.Sections {
        if section.RawSize < parsed.Length
            continue
        sectionResults := ScanSection(pe, section, parsed, maxMatches - results.Length)
        for item in sectionResults
            results.Push(item)
        if results.Length >= maxMatches
            break
    }
    pe.AllScanCache[cacheKey] := results
    return results
}

FindRipLeaRefs(pe, targetRVA, modrm := 0x15) {
    return FindIndexedRipLeaRefs(pe, targetRVA, modrm, 0x48)
}

GetPdataSection(pe) {
    if HasProp(pe, "PdataSectionCache")
        return pe.PdataSectionCache
    for section in pe.Sections {
        if section.Name = ".pdata" {
            pe.PdataSectionCache := section
            return section
        }
    }
    pe.PdataSectionCache := ""
    return ""
}

GetRuntimeDirectory(pe) {
    if HasProp(pe, "RuntimeDirectoryCache")
        return pe.RuntimeDirectoryCache

    ; Preferred: IMAGE_DIRECTORY_ENTRY_EXCEPTION from the PE32+ optional header.
    if HasProp(pe, "ExceptionRVA") && HasProp(pe, "ExceptionSize")
        && pe.ExceptionRVA > 0 && pe.ExceptionSize >= 12 {
        pe.RuntimeDirectoryCache := {
            Mode: "exception",
            RVA: pe.ExceptionRVA,
            Size: pe.ExceptionSize,
            Entries: Floor(pe.ExceptionSize / 12)
        }
        return pe.RuntimeDirectoryCache
    }

    ; Compatibility fallback for unusual/malformed images that omit the data
    ; directory but still expose a conventional .pdata section.
    section := GetPdataSection(pe)
    if IsObject(section) && section.RawSize >= 12 {
        pe.RuntimeDirectoryCache := {
            Mode: "section",
            Section: section,
            Entries: Floor(section.RawSize / 12)
        }
        return pe.RuntimeDirectoryCache
    }

    pe.RuntimeDirectoryCache := ""
    return ""
}

ReadRuntimeFunctionEntry(pe, runtimeDir, index) {
    if !IsObject(runtimeDir) || index < 1 || index > runtimeDir.Entries
        return {BeginRVA: -1, EndRVA: -1, UnwindRVA: -1}

    if runtimeDir.Mode = "exception" {
        entryRVA := runtimeDir.RVA + (index - 1) * 12
        raw := RvaToRaw(pe, entryRVA)
        if raw < 0 || raw + 12 > pe.Size
            return {BeginRVA: -1, EndRVA: -1, UnwindRVA: -1}
    } else {
        raw := runtimeDir.Section.RawPtr + (index - 1) * 12
        if raw < 0 || raw + 12 > pe.Size
            return {BeginRVA: -1, EndRVA: -1, UnwindRVA: -1}
    }

    beginRVA := NumGet(pe.Data, raw, "UInt")
    endRVA := NumGet(pe.Data, raw + 4, "UInt")
    unwindRVA := NumGet(pe.Data, raw + 8, "UInt")
    if beginRVA = 0 || endRVA <= beginRVA
        return {BeginRVA: -1, EndRVA: -1, UnwindRVA: -1}
    return {BeginRVA: beginRVA, EndRVA: endRVA, UnwindRVA: unwindRVA}
}

CanonicalRuntimeFunction(pe, fn) {
    if !IsObject(fn) || fn.BeginRVA < 0
        return fn

    seen := Map()
    Loop 8 {
        key := Format("{:X}", fn.BeginRVA)
        if seen.Has(key) || !HasProp(fn, "UnwindRVA") || fn.UnwindRVA <= 0
            break
        seen[key] := true

        unwindRVA := fn.UnwindRVA & ~3
        raw := RvaToRaw(pe, unwindRVA)
        if raw < 0 || raw + 4 > pe.Size
            break

        ; UNWIND_INFO VersionAndFlags: upper five bits are Flags. CHAININFO=4.
        flags := NumGet(pe.Data, raw, "UChar") >> 3
        if (flags & 0x4) = 0
            break

        codeCount := NumGet(pe.Data, raw + 2, "UChar")
        off := 4 + codeCount * 2
        if Mod(off, 4) != 0
            off += 2
        if raw + off + 12 > pe.Size
            break

        chained := {
            BeginRVA: NumGet(pe.Data, raw + off, "UInt"),
            EndRVA: NumGet(pe.Data, raw + off + 4, "UInt"),
            UnwindRVA: NumGet(pe.Data, raw + off + 8, "UInt")
        }
        if chained.BeginRVA = 0 || chained.EndRVA <= chained.BeginRVA
            break
        fn := chained
    }
    return fn
}

FindRuntimeFunction(pe, rva) {
    ; Binary-search the authoritative PE exception directory. This mirrors the
    ; Win64 ownership semantics PatternSleuth uses and works even when the
    ; runtime-function table is not in a section literally called .pdata.
    runtimeDir := GetRuntimeDirectory(pe)
    if !IsObject(runtimeDir) || runtimeDir.Entries <= 0
        return {BeginRVA: -1, EndRVA: -1, UnwindRVA: -1}

    lo := 1
    hi := runtimeDir.Entries
    best := 0
    while lo <= hi {
        mid := Floor((lo + hi) / 2)
        fn := ReadRuntimeFunctionEntry(pe, runtimeDir, mid)
        if fn.BeginRVA >= 0 && fn.BeginRVA <= rva {
            best := mid
            lo := mid + 1
        } else
            hi := mid - 1
    }

    if best <= 0
        return {BeginRVA: -1, EndRVA: -1, UnwindRVA: -1}

    idx := best
    checked := 0
    while idx >= 1 && checked < 256 {
        fn := ReadRuntimeFunctionEntry(pe, runtimeDir, idx)
        if fn.BeginRVA >= 0 {
            if rva >= fn.BeginRVA && rva < fn.EndRVA
                return CanonicalRuntimeFunction(pe, fn)
            if rva > fn.BeginRVA && rva - fn.BeginRVA > 0x100000
                break
        }
        idx -= 1
        checked += 1
    }
    return {BeginRVA: -1, EndRVA: -1, UnwindRVA: -1}
}

IsRuntimeFunctionStart(pe, rva) {
    fn := FindRuntimeFunction(pe, rva)
    return fn.BeginRVA = rva
}

FindLastCallTarget(pe, beginRVA, endRVA) {
    beginRaw := RvaToRaw(pe, beginRVA)
    endRaw := RvaToRaw(pe, endRVA)
    if beginRaw < 0 || endRaw < 0 || endRaw <= beginRaw
        return {CallRVA: -1, TargetRVA: -1}

    fallback := {CallRVA: -1, TargetRVA: -1}
    preferred := {CallRVA: -1, TargetRVA: -1}
    raw := beginRaw
    lastYield := A_TickCount
    while raw + 5 <= endRaw {
        CooperativeScanYield(&lastYield)

        if ByteAt(pe, raw) = 0xE8 {
            callRVA := beginRVA + (raw - beginRaw)
            disp := NumGet(pe.Data, raw + 1, "Int")
            target := callRVA + 5 + disp
            if RvaInImage(pe, target) && IsExecutableRVA(pe, target) {
                fallback := {CallRVA: callRVA, TargetRVA: target}
                if IsRuntimeFunctionStart(pe, target)
                    preferred := fallback
            }
        }
        raw += 1
    }
    return preferred.TargetRVA >= 0 ? preferred : fallback
}

FindFirstCallTarget(pe, beginRVA, maxBytes := 0x200) {
    fn := FindRuntimeFunction(pe, beginRVA)
    endRVA := beginRVA + maxBytes
    if fn.BeginRVA >= 0
        endRVA := Min(endRVA, fn.EndRVA)
    beginRaw := RvaToRaw(pe, beginRVA)
    endRaw := RvaToRaw(pe, endRVA - 1)
    if beginRaw < 0 || endRaw < 0
        return {CallRVA: -1, TargetRVA: -1}
    endRaw += 1

    fallback := {CallRVA: -1, TargetRVA: -1}
    raw := beginRaw
    lastYield := A_TickCount
    while raw + 5 <= endRaw {
        CooperativeScanYield(&lastYield)

        if ByteAt(pe, raw) = 0xE8 {
            callRVA := beginRVA + (raw - beginRaw)
            disp := NumGet(pe.Data, raw + 1, "Int")
            target := callRVA + 5 + disp
            if RvaInImage(pe, target) && IsExecutableRVA(pe, target) {
                if IsRuntimeFunctionStart(pe, target)
                    return {CallRVA: callRVA, TargetRVA: target}
                if fallback.TargetRVA < 0
                    fallback := {CallRVA: callRVA, TargetRVA: target}
            }
        }
        raw += 1
    }
    return fallback
}


FindAnsiRvas(pe, text, includeNull := true) {
    if !HasProp(pe, "AnsiRvaCache")
        pe.AnsiRvaCache := Map()
    cacheKey := (includeNull ? "1|" : "0|") text
    if pe.AnsiRvaCache.Has(cacheKey)
        return pe.AnsiRvaCache[cacheKey]

    patternText := ""
    Loop StrLen(text) {
        if patternText != ""
            patternText .= " "
        patternText .= Format("{:02X}", Ord(SubStr(text, A_Index, 1)) & 0xFF)
    }
    if includeNull
        patternText .= (patternText = "" ? "" : " ") "00"
    matches := ScanPEAll(pe, ParsePattern(patternText), 64)
    out := []
    for match in matches
        out.Push(match.RVA)
    pe.AnsiRvaCache[cacheKey] := out
    return out
}

FindStringRvasBoth(pe, text, includeNull := true) {
    out := []
    seen := Map()
    for rva in FindUtf16Rvas(pe, text, includeNull) {
        key := Format("{:X}", rva)
        if !seen.Has(key) {
            seen[key] := true
            out.Push(rva)
        }
    }
    for rva in FindAnsiRvas(pe, text, includeNull) {
        key := Format("{:X}", rva)
        if !seen.Has(key) {
            seen[key] := true
            out.Push(rva)
        }
    }
    return out
}

FindSemanticStringRoots(pe, text, includeNull := true) {
    roots := Map()
    stringRVAs := FindStringRvasBoth(pe, text, includeNull)
    for stringRVA in stringRVAs {
        targets := Map()
        targets[Format("{:X}", stringRVA)] := stringRVA
        for absRef in FindAbsolute64Refs(pe, pe.ImageBase + stringRVA, 256)
            targets[Format("{:X}", absRef.RVA)] := absRef.RVA

        for key, targetRVA in targets {
            for ref in FindIndexedRipLeaRefs(pe, targetRVA) {
                fn := FindRuntimeFunction(pe, ref.RVA)
                if fn.BeginRVA >= 0
                    roots[Format("{:X}", fn.BeginRVA)] := fn
            }
        }
    }
    return {Roots: roots, StringCount: stringRVAs.Length}
}

ResolveFNameToStringLegacySetEnums(pe) {
    ; Older PatternSleuth carried a UEnum::SetEnums callsite family that is not
    ; expressible as a normal single-marker DB pattern because the useful
    ; FName::ToString call is the SECOND E8 in the structure. The first call
    ; returns a bool and is immediately TESTed via `84 C0`.
    patternText := "0F 84 ?? ?? ?? ?? 48 8B ?? E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 48 8D ?? 24 ?? 48 8B ?? E8 ?? ?? ?? ??"
    parsed := ParsePattern(patternText)
    matches := NativeAdHocPatternScan(pe, patternText, 128)
    if !IsObject(matches)
        matches := ScanPE(pe, parsed, 128)

    if matches.Length = 0 {
        return {
            Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1,
            Diagnostics: "Legacy SetEnums FName::ToString callsite family was not present.",
            Source: "PatternSleuth legacy SetEnums ToString family",
            Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true
        }
    }

    targetCounts := Map()
    evidence := []
    for match in matches {
        ; Second E8 begins 30 bytes into this fixed structural family.
        callRaw := match.Raw + 30
        if ByteAt(pe, callRaw) != 0xE8
            continue
        targetRVA := ResolveRel32AtRaw(pe, callRaw)
        if targetRVA < 0 || !IsExecutableRVA(pe, targetRVA)
            continue
        callRVA := RawToRva(pe, callRaw)
        key := Format("{:X}", targetRVA)
        targetCounts[key] := targetCounts.Get(key, 0) + 1
        evidence.Push({CallRVA: callRVA, TargetRVA: targetRVA})
    }

    if targetCounts.Count = 0 {
        return {
            Status: "NOT FOUND", MatchCount: matches.Length, TargetRVA: -1,
            Diagnostics: Format("Legacy SetEnums family matched {} time(s), but its second E8 did not resolve to executable code.", matches.Length),
            Source: "PatternSleuth legacy SetEnums ToString family",
            Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true
        }
    }

    topKey := "", topCount := 0, second := 0
    for key, count in targetCounts {
        if count > topCount {
            second := topCount
            topCount := count
            topKey := key
        } else if count > second
            second := count
    }
    targetRVA := ("0x" topKey) + 0

    if targetCounts.Count > 1 && topCount <= second {
        return {
            Status: "AMBIGUOUS", MatchCount: evidence.Length, TargetRVA: -1,
            Candidates: DescribeTargetCounts(targetCounts),
            Diagnostics: "Legacy SetEnums callsites did not converge on one ToString target.",
            Source: "PatternSleuth legacy SetEnums ToString family",
            Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true
        }
    }

    for ev in evidence {
        if ev.TargetRVA != targetRVA
            continue
        result := BuildUniqueCallResult(pe, ev.CallRVA, targetRVA,
            "PatternSleuth legacy SetEnums ToString family",
            "The legacy UEnum::SetEnums structural family uniquely matched and its second direct CALL resolves to one executable FName::ToString candidate.")
        if IsUsableResolverResult(result) {
            result.MatchCount := topCount
            result.Consensus := Format("Legacy SetEnums second-call target 0x{:X} received {} supporting hit(s); runner-up support {}.", targetRVA, topCount, second)
            result.Tier := 3
            result.TierName := "Structural / callsite"
            result.TierLabel := "T3 - Structural / callsite"
            result.TierLocked := true
            return result
        }
    }

    return {
        Status: "NOT FOUND", MatchCount: topCount, TargetRVA: -1,
        Diagnostics: Format("Legacy SetEnums evidence converged on RVA 0x{:X}, but a unique relocatable callsite AOB could not be manufactured.", targetRVA),
        Source: "PatternSleuth legacy SetEnums ToString family",
        Tier: 3, TierName: "Structural / callsite", TierLabel: "T3 - Structural / callsite", TierLocked: true
    }
}

ResolveFNameToStringLegacyAnchors(pe) {
    ; Older UE4 builds can lack the DrivingBone diagnostic used by the modern
    ; PE resolver. PatternSleuth also uses SkySphereMesh as an FName ToString
    ; semantic anchor on older targets, so apply the same root/XREF/last-call idea.
    targetCounts := Map()
    evidence := []
    anchorHits := 0

    for anchor in ["SkySphereMesh"] {
        strings := FindStringRvasBoth(pe, anchor, true)
        anchorHits += strings.Length
        for stringRVA in strings {
            targets := Map()
            targets[Format("{:X}", stringRVA)] := stringRVA
            for absRef in FindAbsolute64Refs(pe, pe.ImageBase + stringRVA, 128)
                targets[Format("{:X}", absRef.RVA)] := absRef.RVA

            for key, targetRVA in targets {
                for ref in FindIndexedRipLeaRefs(pe, targetRVA) {
                    fn := FindRuntimeFunction(pe, ref.RVA)
                    if fn.BeginRVA < 0
                        continue
                    call := FindLastCallTarget(pe, fn.BeginRVA, ref.RVA)
                    if call.TargetRVA < 0 || !IsExecutableRVA(pe, call.TargetRVA)
                        continue
                    k := Format("{:X}", call.TargetRVA)
                    targetCounts[k] := targetCounts.Get(k, 0) + 1
                    evidence.Push({CallRVA: call.CallRVA, TargetRVA: call.TargetRVA})
                }
            }
        }
    }

    if targetCounts.Count = 0 {
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1,
            Diagnostics: Format("Legacy FName_ToString semantic anchor produced no call target (SkySphereMesh hits: {}).", anchorHits),
            Source: "Legacy FName_ToString semantic anchor",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    topKey := "", topCount := 0, second := 0
    for key, count in targetCounts {
        if count > topCount {
            second := topCount
            topCount := count
            topKey := key
        } else if count > second
            second := count
    }
    targetRVA := ("0x" topKey) + 0
    if targetCounts.Count > 1 && topCount <= second {
        return {Status: "AMBIGUOUS", MatchCount: evidence.Length, TargetRVA: -1,
            Candidates: DescribeTargetCounts(targetCounts), Diagnostics: "Legacy FName_ToString anchors disagreed on the last-call target.",
            Source: "Legacy FName_ToString semantic anchor",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    for ev in evidence {
        if ev.TargetRVA != targetRVA
            continue
        result := BuildUniqueCallResult(pe, ev.CallRVA, targetRVA,
            "Legacy SkySphereMesh FName_ToString semantic anchor",
            "Legacy engine string XREF, owning runtime function, and last CALL above the anchor converged on one executable target.")
        if IsUsableResolverResult(result) {
            result.Status := "VERIFIED"
            result.MatchCount := evidence.Length
            result.Consensus := Format("Legacy semantic target 0x{:X} received {} supporting call hit(s); runner-up support {}.", targetRVA, topCount, second)
            result.Tier := 4
            result.TierName := "Semantic XREF"
            result.TierLabel := "T4 - Semantic XREF"
            result.TierLocked := true
            return result
        }
    }

    direct := BuildUniqueDirectResult(pe, targetRVA, "Legacy SkySphereMesh FName_ToString semantic anchor",
        "Legacy engine string/XREF evidence converged on one executable target; target-entry AOB is unique.")
    if IsUsableResolverResult(direct) {
        direct.Status := "STRONG"
        direct.Tier := 4
        direct.TierName := "Semantic XREF"
        direct.TierLabel := "T4 - Semantic XREF"
        direct.TierLocked := true
        return direct
    }
    return {Status: "NOT FOUND", MatchCount: evidence.Length, TargetRVA: -1,
        Diagnostics: "Legacy ToString target was plausible but no unique relocatable AOB could be manufactured.",
        Source: "Legacy FName_ToString semantic anchor"}
}


ResolvePre423GNames(pe) {
    ; PatternSleuth's pre-4.23 FName storage resolver. The lazy GNames getter
    ; differs only in the historical indirect-array allocation size (0x408 / 0x808).
    patterns := [
        "48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? B9 08 04 00 00",
        "48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? B9 08 08 00 00"
    ]
    targets := Map()
    totalHits := 0
    for patternText in patterns {
        hits := ScanPE(pe, ParsePattern(patternText), 32)
        totalHits += hits.Length
        for hit in hits {
            dispRaw := hit.Raw + 7
            if dispRaw + 4 > pe.Size
                continue
            disp := NumGet(pe.Data, dispRaw, "Int")
            targetRVA := hit.RVA + 11 + disp
            section := SectionObjectForRVA(pe, targetRVA)
            if !IsObject(section) || section.Executable
                continue
            targets[Format("{:X}", targetRVA)] := targetRVA
        }
    }

    if targets.Count = 1 {
        for key, targetRVA in targets
            return {Found: true, TargetRVA: targetRVA, MatchCount: totalHits,
                Detail: Format("Pre-4.23 GNames getter resolved one writable global at RVA 0x{:X} from {} getter hit(s).", targetRVA, totalHits)}
    }
    if targets.Count > 1
        return {Found: false, TargetRVA: -1, MatchCount: totalHits,
            Detail: Format("Pre-4.23 GNames getter produced {} distinct global candidates from {} hit(s).", targets.Count, totalHits)}
    return {Found: false, TargetRVA: -1, MatchCount: totalHits,
        Detail: "Pre-4.23 GNames getter families were not present."}
}

ResolveFNameToStringGNamesSemantic(pe) {
    gnames := ResolvePre423GNames(pe)
    if !gnames.Found {
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1,
            Diagnostics: gnames.Detail,
            Source: "Pre-4.23 GNames FName_ToString semantic fallback",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    refs := FindRipDataRefsAny(pe, gnames.TargetRVA)
    roots := Map()
    for ref in refs {
        fn := FindRuntimeFunction(pe, ref.RVA)
        if fn.BeginRVA >= 0
            roots[Format("{:X}", fn.BeginRVA)] := fn
    }

    if roots.Count = 0 {
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1,
            Diagnostics: gnames.Detail " No executable runtime function directly referenced the resolved GNames global.",
            Source: "Pre-4.23 GNames FName_ToString semantic fallback",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    candidates := []
    for key, fn in roots {
        scored := ScoreFNameToStringGNamesConsumer(pe, fn, gnames.TargetRVA)
        if scored.Score > 0
            candidates.Push(scored)
    }
    if candidates.Length = 0 {
        return {Status: "NOT FOUND", MatchCount: roots.Count, TargetRVA: -1,
            Diagnostics: Format("{} {} GNames-referencing root function(s) were found, but none had an FName::ToString-shaped body.", gnames.Detail, roots.Count),
            Source: "Pre-4.23 GNames FName_ToString semantic fallback",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    ; Sort descending by structural score without depending on Array.Sort (AHK v2.0).
    best := candidates[1]
    secondScore := -1
    for item in candidates {
        if item.Score > best.Score {
            secondScore := best.Score
            best := item
        } else if item.Fn.BeginRVA != best.Fn.BeginRVA && item.Score > secondScore
            secondScore := item.Score
    }
    ; Recompute runner-up in case the initial best was replaced late.
    secondScore := -1
    for item in candidates {
        if item.Fn.BeginRVA != best.Fn.BeginRVA && item.Score > secondScore
            secondScore := item.Score
    }

    if best.Score < 6 || (secondScore >= 0 && best.Score < secondScore + 2) {
        return {Status: "AMBIGUOUS", MatchCount: candidates.Length, TargetRVA: -1,
            Diagnostics: Format("{} GNames consumer scoring was not decisive: best score {}, runner-up {}, candidates {}. Best evidence: {}",
                gnames.Detail, best.Score, secondScore, candidates.Length, best.Detail),
            Source: "Pre-4.23 GNames FName_ToString semantic fallback",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    result := BuildUniqueDirectResult(pe, best.Fn.BeginRVA,
        "Pre-4.23 GNames FName_ToString semantic fallback",
        Format("A function directly consumes the resolved GNames singleton and has the expected FName input/output body shape. Structural score {} (runner-up {}). {}", best.Score, secondScore, best.Detail))
    if !IsUsableResolverResult(result) {
        return {Status: "NOT FOUND", MatchCount: candidates.Length, TargetRVA: -1,
            Diagnostics: Format("GNames semantic analysis selected RVA 0x{:X} (score {}), but a unique target-entry AOB could not be manufactured.", best.Fn.BeginRVA, best.Score),
            Source: "Pre-4.23 GNames FName_ToString semantic fallback",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    result.Status := "STRONG"
    result.MatchCount := candidates.Length
    result.Tier := 4
    result.TierName := "Semantic XREF"
    result.TierLabel := "T4 - Semantic XREF"
    result.TierLocked := true
    result.Consensus := Format("Pre-4.23 GNames consumer score {} beat runner-up {} across {} candidate root function(s).", best.Score, secondScore, candidates.Length)

    kismetProof := CorroborateFNameToStringKismet(pe, result.TargetRVA)
    if kismetProof.Passed {
        result.Status := "VERIFIED"
        result.Validation .= " Independent Kismet Conv_NameToString semantic evidence calls the same target."
        result.SecondaryProof := kismetProof.Detail
        result.Source .= " + Kismet corroboration"
    } else
        result.Diagnostics := kismetProof.Detail
    return result
}

ScoreFNameToStringGNamesConsumer(pe, fn, gnamesRVA) {
    beginRaw := RvaToRaw(pe, fn.BeginRVA)
    endRaw := RvaToRaw(pe, fn.EndRVA - 1)
    if beginRaw < 0 || endRaw < beginRaw
        return {Fn: fn, Score: 0, Detail: "invalid runtime range"}
    endRaw := Min(endRaw + 1, beginRaw + 0x700)

    score := 2 ; already proven direct GNames reference
    comparisonRead := false
    numberRead := false
    preservesOut := false
    hasCall := false
    raw := beginRaw
    while raw + 4 < endRaw {
        b0 := ByteAt(pe, raw)
        b1 := ByteAt(pe, raw + 1)
        b2 := ByteAt(pe, raw + 2)

        if b0 = 0xE8
            hasCall := true

        ; Common x64 compiler forms preserving FString& (RDX) in a nonvolatile register.
        if (BytesEqual(pe, raw, [0x48,0x8B,0xDA])
            || BytesEqual(pe, raw, [0x48,0x8B,0xF2])
            || BytesEqual(pe, raw, [0x48,0x8B,0xFA]))
            preservesOut := true

        ; MOV r32,[RCX] / MOV r32,[RCX+4] catch ComparisonIndex and Number reads.
        opRaw := raw
        if (b0 >= 0x40 && b0 <= 0x4F) {
            if b1 != 0x8B {
                raw += 1
                continue
            }
            modrm := b2
            dispPos := raw + 3
        } else if b0 = 0x8B {
            modrm := b1
            dispPos := raw + 2
        } else {
            raw += 1
            continue
        }
        mod := (modrm >> 6) & 3
        rm := modrm & 7
        if rm = 1 && mod != 3 {
            if mod = 0
                comparisonRead := true
            else if mod = 1 && dispPos < endRaw {
                disp8 := NumGet(pe.Data, dispPos, "Char")
                if disp8 = 0
                    comparisonRead := true
                else if disp8 = 4
                    numberRead := true
            }
        }
        raw += 1
    }

    if comparisonRead
        score += 2
    if numberRead
        score += 2
    if preservesOut
        score += 1
    if hasCall
        score += 1

    detail := Format("GNames ref=yes, ComparisonIndex read={}, Number read={}, FString/RDX preservation={}, contains CALL={}.",
        comparisonRead ? "yes" : "no", numberRead ? "yes" : "no", preservesOut ? "yes" : "no", hasCall ? "yes" : "no")
    return {Fn: fn, Score: score, Detail: detail}
}

CorroborateFNameToStringKismet(pe, targetRVA) {
    ; UE4SS itself now offers UKismetStringLibrary::Conv_NameToString as an
    ; alternative FName conversion path. On builds where its reflected name is
    ; retained, a registration/debug root that directly calls our candidate is
    ; useful independent evidence. We only corroborate an already-selected target;
    ; this routine never invents a ToString address by itself.
    info := FindSemanticStringRoots(pe, "Conv_NameToString", true)
    if info.StringCount = 0
        return {Passed: false, Detail: "Kismet corroboration unavailable (Conv_NameToString string hits: 0)."}

    for key, fn in info.Roots {
        beginRaw := RvaToRaw(pe, fn.BeginRVA)
        endRaw := RvaToRaw(pe, fn.EndRVA - 1)
        if beginRaw < 0 || endRaw < beginRaw
            continue
        endRaw := Min(endRaw + 1, beginRaw + 0x800)
        raw := beginRaw
        while raw + 5 <= endRaw {
            if ByteAt(pe, raw) = 0xE8 {
                dest := ResolveRel32AtRaw(pe, raw)
                if dest = targetRVA {
                    return {Passed: true,
                        Detail: Format("A runtime function rooted from Conv_NameToString reflection text directly CALLs candidate FName::ToString RVA 0x{:X}.", targetRVA)}
                }
            }
            raw += 1
        }
    }
    return {Passed: false,
        Detail: Format("Kismet corroboration found {} Conv_NameToString string hit(s) / {} root function(s), but none directly called candidate RVA 0x{:X}.", info.StringCount, info.Roots.Count, targetRVA)}
}

BuildFNameToStringFailureDiagnostics(pe, special, setEnums, legacy, nativeLegacy, gnamesSemantic) {
    summary := SummarizeFNameToStringLegacyFamilies(pe)
    parts := []
    parts.Push("FName_ToString layered diagnostics: " summary)
    for item in [special, setEnums, legacy, nativeLegacy, gnamesSemantic] {
        if IsObject(item) && HasProp(item, "Diagnostics") && item.Diagnostics != ""
            parts.Push(item.Diagnostics)
    }
    return JoinText(parts, " ")
}

SummarizeFNameToStringLegacyFamilies(pe) {
    global ResolverDB
    families := []
    for resolver in ResolverDB {
        if resolver.File != "FName_ToString"
            continue
        for entry in resolver.Patterns {
            patternText := IsObject(entry) ? entry.Pattern : entry
            source := IsObject(entry) && HasProp(entry, "Source") ? entry.Source : "legacy family"
            hits := ScanPE(pe, ParsePattern(patternText), 64)
            if hits.Length > 0
                families.Push(source ":" hits.Length)
        }
        break
    }
    if families.Length = 0
        return "direct/legacy pattern families with hits=0."
    return "pattern-family hits => " JoinText(families, ", ") "."
}

FindLeaRcxGlobalBeforeCall(pe, callRVA, callerBeginRVA, maxBack := 0x80) {
    callRaw := RvaToRaw(pe, callRVA)
    beginRaw := RvaToRaw(pe, callerBeginRVA)
    if callRaw < 0 || beginRaw < 0
        return []
    startRaw := Max(beginRaw, callRaw - maxBack)
    out := []
    raw := startRaw
    while raw + 7 <= callRaw {
        if BytesEqual(pe, raw, [0x48,0x8D,0x0D]) {
            siteRVA := RawToRva(pe, raw)
            disp := NumGet(pe.Data, raw + 3, "Int")
            target := siteRVA + 7 + disp
            section := SectionObjectForRVA(pe, target)
            if IsObject(section) && !section.Executable
                out.Push({LeaRVA: siteRVA, TargetRVA: target, Distance: callRVA - siteRVA})
        }
        raw += 1
    }
    return out
}

ResolveGUObjectArrayMethodCallsites(pe) {
    allocInfo := FindSemanticStringRoots(pe, "Unable to add more objects to disregard for GC pool (Max: %d)", true)
    freeRoots := Map()
    freeStringHits := 0
    for text in [
        "Removing object (0x%016llx) at index %d but the index points to a different object (0x%016llx)!",
        "Unexpected concurency while adding new object"
    ] {
        info := FindSemanticStringRoots(pe, text, true)
        freeStringHits += info.StringCount
        for key, fn in info.Roots
            freeRoots[key] := fn
    }

    targetCounts := Map()
    sourceKinds := Map()
    evidence := []
    CollectGUObjectArrayCallerEvidence(pe, allocInfo.Roots, "AllocateUObjectIndex", targetCounts, sourceKinds, evidence)
    CollectGUObjectArrayCallerEvidence(pe, freeRoots, "FreeUObjectIndex", targetCounts, sourceKinds, evidence)

    if targetCounts.Count = 0 {
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1,
            Diagnostics: Format("FUObjectArray semantic fallback: allocate strings={}, allocate roots={}, free strings={}, free roots={}; no caller loaded one writable global into RCX shortly before the member call.", allocInfo.StringCount, allocInfo.Roots.Count, freeStringHits, freeRoots.Count),
            Source: "FUObjectArray Allocate/Free semantic callsites",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    topKey := "", topCount := 0, second := 0
    for key, count in targetCounts {
        if count > topCount {
            second := topCount
            topCount := count
            topKey := key
        } else if count > second
            second := count
    }
    targetRVA := ("0x" topKey) + 0
    kinds := sourceKinds.Has(topKey) ? sourceKinds[topKey] : Map()
    independentKinds := kinds.Count

    if targetCounts.Count > 1 && (topCount < 2 || topCount < second * 2) {
        return {Status: "AMBIGUOUS", MatchCount: evidence.Length, TargetRVA: -1,
            Candidates: DescribeTargetCounts(targetCounts),
            Diagnostics: Format("FUObjectArray member-call evidence was not decisive; best support {}, runner-up {}.", topCount, second),
            Source: "FUObjectArray Allocate/Free semantic callsites",
            Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
    }

    for ev in evidence {
        if ev.TargetRVA != targetRVA
            continue
        callRaw := RvaToRaw(pe, ev.CallRVA)
        leaRaw := RvaToRaw(pe, ev.LeaRVA)
        if callRaw < 0 || leaRaw < 0 || callRaw <= leaRaw
            continue
        coreLen := callRaw + 5 - leaRaw
        if coreLen > 0x90
            continue
        callDispOff := (ev.CallRVA - ev.LeaRVA) + 1
        result := BuildUniqueRipRelativeResult(pe, ev.LeaRVA, targetRVA, 3, 0,
            [[3,4], [callDispOff,4]], coreLen,
            "FUObjectArray Allocate/Free semantic callsite",
            Format("A {} caller materializes one writable global as RCX with LEA shortly before calling the semantically identified FUObjectArray member function.", ev.Kind))
        if IsUsableResolverResult(result) {
            result.MatchCount := topCount
            result.Tier := 4
            result.TierName := "Semantic XREF"
            result.TierLabel := "T4 - Semantic XREF"
            result.TierLocked := true
            result.Consensus := Format("Writable global RVA 0x{:X} received {} member-call evidence hit(s) from {} independent FUObjectArray method family/families; runner-up support {}.", targetRVA, topCount, independentKinds, second)
            if independentKinds >= 2 || topCount >= 2 {
                result.Status := "VERIFIED"
                result.Validation .= " Independent member-call evidence converged on the same global, and the generated RIP-relative AOB uniquely re-resolves it."
            } else {
                result.Status := "STRONG"
                result.Validation .= " Only one semantic member-call path was available, so identity remains STRONG rather than fully VERIFIED."
            }
            return result
        }
    }

    return {Status: "NOT FOUND", MatchCount: topCount, TargetRVA: -1,
        Diagnostics: Format("FUObjectArray semantic evidence converged on RVA 0x{:X}, but no safe unique generated AOB could be produced.", targetRVA),
        Source: "FUObjectArray Allocate/Free semantic callsites",
        Tier: 4, TierName: "Semantic XREF", TierLabel: "T4 - Semantic XREF", TierLocked: true}
}

CollectGUObjectArrayCallerEvidence(pe, roots, kind, targetCounts, sourceKinds, evidence) {
    if roots.Count = 0
        return 0
    targets := Map()
    for key, fn in roots
        targets[Format("{:X}", fn.BeginRVA)] := fn.BeginRVA
    edges := FindInboundEdgesForTargets(pe, targets, 2048)
    added := 0
    for edge in edges {
        if edge.Opcode != 0xE8
            continue
        leas := FindLeaRcxGlobalBeforeCall(pe, edge.SiteRVA, edge.CallerBeginRVA, 0x80)
        if leas.Length = 0
            continue
        best := leas[1]
        for lea in leas {
            if lea.Distance < best.Distance
                best := lea
        }
        key := Format("{:X}", best.TargetRVA)
        targetCounts[key] := targetCounts.Get(key, 0) + 1
        if !sourceKinds.Has(key)
            sourceKinds[key] := Map()
        sourceKinds[key][kind] := true
        evidence.Push({Kind: kind, CallRVA: edge.SiteRVA, LeaRVA: best.LeaRVA, TargetRVA: best.TargetRVA})
        added += 1
    }
    return added
}



CorroborateGUObjectArrayAllocateObjectPool(pe, targetRVA) {
    ; Old UE4 branches may predate the UObjectBaseShutdown listener diagnostic.
    ; AllocateObjectPool is much older and contains a distinctive fatal string.
    ; Resolve that member function semantically, find real inbound CALLs, and
    ; verify that a caller independently loads the exact candidate global as RCX.
    anchors := [
        "Max UObject count is invalid. It must be a number that is greater than 0.",
        "Max UObject count is invalid"
    ]
    roots := Map()
    stringHits := 0
    for idx, text in anchors {
        info := FindSemanticStringRoots(pe, text, idx = 1)
        stringHits += info.StringCount
        for key, fn in info.Roots
            roots[key] := fn
        if roots.Count > 0
            break
    }

    if roots.Count = 0 {
        return {Passed: false,
            Detail: Format("Legacy AllocateObjectPool corroboration unavailable (Max-UObject diagnostic hits: {}, root functions: 0).", stringHits)}
    }

    targets := Map()
    for key, fn in roots
        targets[Format("{:X}", fn.BeginRVA)] := fn.BeginRVA
    edges := FindInboundEdgesForTargets(pe, targets, 1024)
    checkedCalls := 0
    for edge in edges {
        if edge.Opcode != 0xE8
            continue
        checkedCalls += 1
        leas := FindLeaRcxGlobalBeforeCall(pe, edge.SiteRVA, edge.CallerBeginRVA, 0xA0)
        for lea in leas {
            if lea.TargetRVA = targetRVA {
                return {Passed: true,
                    Detail: Format("Legacy AllocateObjectPool root 0x{:X} is called from 0x{:X}; that caller independently materializes candidate GUObjectArray RVA 0x{:X} into RCX via LEA at 0x{:X}.",
                        edge.TargetRVA, edge.CallerBeginRVA, targetRVA, lea.LeaRVA)}
            }
        }
    }

    return {Passed: false,
        Detail: Format("Legacy AllocateObjectPool was semantically identified from {} diagnostic hit(s) / {} root function(s), but {} inbound CALL(s) did not independently materialize candidate GUObjectArray RVA 0x{:X} as RCX.",
            stringHits, roots.Count, checkedCalls, targetRVA)}
}

CorroborateGUObjectArrayShutdown(pe, targetRVA) {
    ; Independent semantic proof for older/custom UE4 builds. PatternSleuth can
    ; identify UObjectBaseShutdown from this engine diagnostic. If that exact
    ; semantically identified function independently materializes the same
    ; GUObjectArray global with a real RIP-relative LEA/MOV, that is strong
    ; enough to corroborate a one-path Allocate/Free candidate.
    info := FindSemanticStringRoots(pe,
        "All UObject delete listeners should be unregistered when shutting down the UObject array", true)

    if info.Roots.Count = 0 {
        return {
            Passed: false,
            Detail: Format("UObjectBaseShutdown corroboration unavailable (diagnostic strings: {}, root functions: 0).", info.StringCount)
        }
    }

    for key, fn in info.Roots {
        beginRaw := RvaToRaw(pe, fn.BeginRVA)
        endRaw := RvaToRaw(pe, fn.EndRVA - 1)
        if beginRaw < 0 || endRaw < beginRaw
            continue
        endRaw += 1

        raw := beginRaw
        lastYield := A_TickCount
        while raw + 7 <= endRaw {
            CooperativeScanYield(&lastYield)
            rex := ByteAt(pe, raw)
            opcode := ByteAt(pe, raw + 1)
            modrm := ByteAt(pe, raw + 2)

            ; REX.W + LEA/MOV r64,[RIP+disp32]. Limiting this check to the
            ; already-proven UObjectBaseShutdown runtime function makes it a
            ; separate semantic proof without a whole-image XREF scan.
            if (rex = 0x48 || rex = 0x4C)
                && (opcode = 0x8D || opcode = 0x8B)
                && ((modrm & 0xC7) = 0x05) {
                siteRVA := RawToRva(pe, raw)
                if siteRVA >= 0 {
                    disp := NumGet(pe.Data, raw + 3, "Int")
                    resolved := siteRVA + 7 + disp
                    if resolved = targetRVA {
                        opName := opcode = 0x8D ? "LEA" : "MOV"
                        return {
                            Passed: true,
                            RefRVA: siteRVA,
                            RootRVA: fn.BeginRVA,
                            Detail: Format("UObjectBaseShutdown root 0x{:X} independently references GUObjectArray RVA 0x{:X} via RIP-relative {} at 0x{:X}.",
                                fn.BeginRVA, targetRVA, opName, siteRVA)
                        }
                    }
                }
            }
            raw += 1
        }
    }

    return {
        Passed: false,
        Detail: Format("UObjectBaseShutdown was semantically identified ({} root function(s)), but none directly referenced candidate GUObjectArray RVA 0x{:X}.",
            info.Roots.Count, targetRVA)
    }
}

ResolveGUObjectArrayStatLayout(pe) {
    ; PatternSleuth's compiler-resistant GUObjectArray fallback. UE inlines a
    ; stat expression equivalent to:
    ;   ObjObjects.Num() - ObjFirstGCIndex - <available count>
    ; as three RIP-relative dword accesses. Their field spacing identifies the
    ; FUObjectArray base even when the usual constructor/init callsites change.
    patternText := "8B 05 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 2B 05 ?? ?? ?? ??"
    parsed := ParsePattern(patternText)
    matches := ScanPE(pe, parsed, 128)
    if matches.Length = 0 {
        return {
            Status: "NOT FOUND",
            MatchCount: 0,
            TargetRVA: -1,
            Diagnostics: "PatternSleuth object-count stat triple was not present.",
            Source: "PatternSleuth GUObjectArray object-count layout"
        }
    }

    targetCounts := Map()
    candidates := []
    validLayouts := 0

    for match in matches {
        CheckScanCancelled()
        operands := []
        validMatch := true
        for dispOffset in [2, 8, 14] {
            dispRaw := match.Raw + dispOffset
            if dispRaw < 0 || dispRaw + 4 > pe.Size {
                validMatch := false
                break
            }
            disp := NumGet(pe.Data, dispRaw, "Int")
            target := match.RVA + dispOffset + 4 + disp
            if !RvaInImage(pe, target) {
                validMatch := false
                break
            }
            operands.Push({TargetRVA: target, DispOffset: dispOffset})
        }
        if !validMatch || operands.Length != 3
            continue

        ordered := SortThreeNumbers(operands[1].TargetRVA, operands[2].TargetRVA, operands[3].TargetRVA)
        base := -1
        layoutName := ""
        layout := ""
        for testLayout in [[0x00, 0x24, 0x60], [0x00, 0x24, 0x68], [0x08, 0x20, 0x68]] {
            maybeBase := ordered[1] - testLayout[1]
            if maybeBase < 0
                continue
            if ordered[2] = maybeBase + testLayout[2] && ordered[3] = maybeBase + testLayout[3] {
                base := maybeBase
                layout := testLayout
                layoutName := Format("[0x{:X}, 0x{:X}, 0x{:X}]", testLayout[1], testLayout[2], testLayout[3])
                break
            }
        }
        if base < 0 || !RvaInImage(pe, base)
            continue

        ; Pick whichever of the three instructions references the smallest
        ; field offset. Two known layouts reference the base directly; the third
        ; starts at base+8 and therefore needs Add=-8 in OnMatchFound().
        chosen := ""
        chosenOffset := 0x7FFFFFFF
        for operand in operands {
            fieldOffset := operand.TargetRVA - base
            if fieldOffset >= 0 && fieldOffset < chosenOffset {
                chosenOffset := fieldOffset
                chosen := operand
            }
        }
        if !IsObject(chosen)
            continue

        validLayouts += 1
        key := Format("{:X}", base)
        targetCounts[key] := targetCounts.Get(key, 0) + 1
        candidates.Push({
            TargetRVA: base,
            MatchRVA: match.RVA,
            MatchRaw: match.Raw,
            MatchSection: match.Section,
            DispOffset: chosen.DispOffset,
            Add: -chosenOffset,
            Layout: layoutName,
            Support: targetCounts[key]
        })
    }

    if candidates.Length = 0 {
        return {
            Status: "NOT FOUND",
            MatchCount: matches.Length,
            TargetRVA: -1,
            Diagnostics: Format("Found {} object-count-shaped triple(s), but none matched a known FUObjectArray field spacing.", matches.Length),
            Source: "PatternSleuth GUObjectArray object-count layout"
        }
    }

    if targetCounts.Count > 1 {
        return {
            Status: "AMBIGUOUS",
            MatchCount: validLayouts,
            TargetRVA: -1,
            Candidates: DescribeTargetCounts(targetCounts),
            Diagnostics: "Multiple PatternSleuth object-count field layouts reconstructed different FUObjectArray bases.",
            Source: "PatternSleuth GUObjectArray object-count layout"
        }
    }

    targetRVA := candidates[1].TargetRVA
    best := ""
    for candidate in candidates {
        if candidate.TargetRVA = targetRVA {
            best := candidate
            break
        }
    }
    if !IsObject(best)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    validation := Format(
        "Three RIP-relative object-count operands reconstruct one FUObjectArray base using PatternSleuth's known field layout {}. All operands map inside the current PE image.",
        best.Layout)
    result := BuildUniqueRipRelativeResult(
        pe,
        best.MatchRVA,
        targetRVA,
        best.DispOffset,
        best.Add,
        [[2, 4], [8, 4], [14, 4]],
        18,
        "PatternSleuth GUObjectArray object-count field layout",
        validation)

    if IsObject(result) && IsUsableResolverResult(result) {
        result.Status := "VERIFIED"
        result.MatchCount := targetCounts[Format("{:X}", targetRVA)]
        result.Validation := validation " Generated RIP-relative AOB is unique and resolves back to the reconstructed FUObjectArray base."
        result.Consensus := Format("{} valid object-count layout hit(s) converged on FUObjectArray RVA 0x{:X}.", result.MatchCount, targetRVA)
        result.Diagnostics := Format("Object-count layout fallback selected displacement +0x{:X} with resolver adjustment {}.", best.DispOffset, FormatSignedHex(best.Add))
        result.Tier := 3
        result.TierName := "Structural / callsite"
        result.TierLabel := "T3 - Structural / callsite"
        result.TierLocked := true
        return result
    }

    return {
        Status: "NOT FOUND",
        MatchCount: targetCounts[Format("{:X}", targetRVA)],
        TargetRVA: -1,
        Validation: validation " The FUObjectArray base was structurally reconstructed, but no unique relocatable AOB could be manufactured automatically, so generation was withheld.",
        Diagnostics: Format("Structural reconstruction pointed to RVA 0x{:X}, but AOB uniqueness failed.", targetRVA),
        Source: "PatternSleuth GUObjectArray object-count field layout",
        Tier: 3,
        TierName: "Structural / callsite",
        TierLabel: "T3 - Structural / callsite",
        TierLocked: true
    }
}

SortThreeNumbers(a, b, c) {
    if a > b {
        tmp := a
        a := b
        b := tmp
    }
    if b > c {
        tmp := b
        b := c
        c := tmp
    }
    if a > b {
        tmp := a
        a := b
        b := tmp
    }
    return [a, b, c]
}

BuildUniqueRipRelativeResult(pe, coreRVA, targetRVA, markerInCore, add, wildcardRanges, coreLength, source, validation) {
    coreRaw := RvaToRaw(pe, coreRVA)
    if coreRaw < 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    section := SectionObjectForRVA(pe, coreRVA)
    if !IsObject(section) || !section.Executable
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    ; First try the portable structural core by itself, then progressively add
    ; stable bytes around it if this compiler emitted the same expression more
    ; than once. Only the three RIP displacements remain wildcarded.
    windows := [[0, 0], [8, 8], [16, 16], [24, 24], [32, 32]]
    for win in windows {
        before := win[1]
        after := win[2]
        startRaw := coreRaw - before
        length := before + coreLength + after
        if startRaw < section.RawPtr || startRaw + length > section.RawPtr + section.RawSize
            continue

        shifted := []
        for r in wildcardRanges
            shifted.Push([before + r[1], r[2]])
        marker := before + markerInCore
        pattern := PatternWindowRanges(pe, startRaw, length, marker, shifted)
        parsed := ParsePattern(pattern)
        hits := NativeAdHocPatternScan(pe, pattern, 8)
        if !IsObject(hits)
            hits := ScanPE(pe, parsed, 8)
        expectedRVA := coreRVA - before
        if hits.Length != 1 || hits[1].RVA != expectedRVA
            continue

        ; Re-decode the selected displacement from the concrete current match.
        dispRaw := startRaw + marker
        disp := NumGet(pe.Data, dispRaw, "Int")
        resolved := expectedRVA + marker + 4 + disp + add
        if resolved != targetRVA
            continue

        return {
            Status: "VERIFIED",
            MatchCount: 1,
            TargetRVA: targetRVA,
            AOB: PatternForUE4SS(pattern),
            Pattern: pattern,
            Marker: marker,
            MatchRVA: expectedRVA,
            MatchSection: section.Name,
            TargetSection: SectionForRVA(pe, targetRVA),
            Validation: validation,
            ActualBytes: BytesAt(pe, startRaw, length),
            Mode: "rel32",
            Add: add,
            Source: source
        }
    }
    return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}
}

PatternWindowRanges(pe, startRaw, length, marker, wildcardRanges) {
    out := ""
    Loop length {
        idx := A_Index - 1
        if out != ""
            out .= " "
        if idx = marker
            out .= "| "

        wildcard := false
        for r in wildcardRanges {
            if idx >= r[1] && idx < r[1] + r[2] {
                wildcard := true
                break
            }
        }
        out .= wildcard ? "??" : Format("{:02X}", ByteAt(pe, startRaw + idx))
    }
    return out
}

FormatSignedHex(value) {
    if value > 0
        return "+0x" Format("{:X}", value)
    if value < 0
        return "-0x" Format("{:X}", Abs(value))
    return "+0x0"
}

LuaAddressAdjustment(value) {
    if value > 0
        return " + 0x" Format("{:X}", value)
    if value < 0
        return " - 0x" Format("{:X}", Abs(value))
    return ""
}

BuildUniqueDirectResult(pe, targetRVA, source, validation) {
    raw := RvaToRaw(pe, targetRVA)
    if raw < 0
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    section := SectionObjectForRVA(pe, targetRVA)
    if !IsObject(section) || !section.Executable
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    for length in [16, 24, 32, 40, 48, 64] {
        if raw + length > section.RawPtr + section.RawSize
            continue
        pattern := BytesAt(pe, raw, length)
        parsed := ParsePattern(pattern)
        matches := NativeAdHocPatternScan(pe, pattern, 8)
        if !IsObject(matches)
            matches := ScanPE(pe, parsed, 8)
        if matches.Length = 1 && matches[1].RVA = targetRVA {
            return {
                Status: "STRONG",
                MatchCount: 1,
                TargetRVA: targetRVA,
                AOB: pattern,
                Pattern: pattern,
                Marker: -1,
                MatchRVA: targetRVA,
                MatchSection: section.Name,
                TargetSection: section.Name,
                Validation: validation,
                ActualBytes: pattern,
                Mode: "direct",
                Add: 0,
                Source: source
            }
        }
    }
    return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}
}

BuildUniqueCallResult(pe, callRVA, targetRVA, source, validation) {
    callRaw := RvaToRaw(pe, callRVA)
    if callRaw < 0 || ByteAt(pe, callRaw) != 0xE8
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    section := SectionObjectForRVA(pe, callRVA)
    if !IsObject(section)
        return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}

    windows := [[8,12], [12,16], [16,24], [24,32], [32,48]]
    for win in windows {
        before := win[1]
        after := win[2]
        startRaw := callRaw - before
        length := before + 5 + after
        if startRaw < section.RawPtr || startRaw + length > section.RawPtr + section.RawSize
            continue
        marker := before + 1
        pattern := PatternWindow(pe, startRaw, length, marker, 4)
        parsed := ParsePattern(pattern)
        matches := NativeAdHocPatternScan(pe, pattern, 8)
        if !IsObject(matches)
            matches := ScanPE(pe, parsed, 8)
        startRVA := callRVA - before
        if matches.Length = 1 && matches[1].RVA = startRVA {
            return {
                Status: "VERIFIED",
                MatchCount: 1,
                TargetRVA: targetRVA,
                AOB: PatternForUE4SS(pattern),
                Pattern: pattern,
                Marker: marker,
                MatchRVA: startRVA,
                MatchSection: section.Name,
                TargetSection: SectionForRVA(pe, targetRVA),
                Validation: validation " Generated callsite AOB is unique and retains a validated E8 rel32 resolver.",
                ActualBytes: BytesAt(pe, startRaw, length),
                Mode: "rel32",
                Add: 0,
                Source: source
            }
        }
    }
    return {Status: "NOT FOUND", MatchCount: 0, TargetRVA: -1}
}

PatternWindow(pe, startRaw, length, wildcardStart, wildcardLength) {
    out := ""
    Loop length {
        idx := A_Index - 1
        if out != ""
            out .= " "
        if idx = wildcardStart
            out .= "| "
        if (idx >= wildcardStart && idx < wildcardStart + wildcardLength)
            out .= "??"
        else
            out .= Format("{:02X}", ByteAt(pe, startRaw + idx))
    }
    return out
}

ResolveRel32AtRaw(pe, opcodeRaw) {
    if opcodeRaw < 0 || opcodeRaw + 5 > pe.Size
        return -1
    op := ByteAt(pe, opcodeRaw)
    if op != 0xE8 && op != 0xE9
        return -1
    opcodeRVA := RawToRva(pe, opcodeRaw)
    if opcodeRVA < 0
        return -1
    disp := NumGet(pe.Data, opcodeRaw + 1, "Int")
    target := opcodeRVA + 5 + disp
    return RvaInImage(pe, target) ? target : -1
}

ByteAt(pe, raw) {
    if raw < 0 || raw >= pe.Size
        return -1
    return NumGet(pe.Data, raw, "UChar")
}

BytesEqual(pe, raw, expected) {
    if raw < 0 || raw + expected.Length > pe.Size
        return false
    for i, b in expected {
        if ByteAt(pe, raw + i - 1) != b
            return false
    }
    return true
}

SectionObjectForRVA(pe, rva) {
    for section in pe.Sections {
        span := Max(section.VirtualSize, section.RawSize)
        if (rva >= section.VA && rva < section.VA + span)
            return section
    }
    return ""
}

IsExecutableRVA(pe, rva) {
    section := SectionObjectForRVA(pe, rva)
    return IsObject(section) && section.Executable
}

RvaToRaw(pe, rva) {
    for section in pe.Sections {
        if (rva >= section.VA && rva < section.VA + section.RawSize)
            return section.RawPtr + (rva - section.VA)
    }
    return -1
}

RawToRva(pe, raw) {
    for section in pe.Sections {
        if (raw >= section.RawPtr && raw < section.RawPtr + section.RawSize)
            return section.VA + (raw - section.RawPtr)
    }
    return -1
}

ValidateCandidate(pe, resolver, candidate) {
    if (candidate.Mode = "direct")
        return {Status: "STRONG", Detail: "Unique direct signature match; no address-decoding step required."}

    marker := candidate.Parsed.Marker
    if marker < 0
        return {Status: "UNVERIFIED", Detail: "Pattern has no displacement marker."}

    ; A rel32 CALL is E8 followed by a signed 32-bit displacement.
    if marker >= 1 {
        prior := NumGet(pe.Data, candidate.MatchRaw + marker - 1, "UChar")
        if prior = 0xE8
            return {Status: "VERIFIED", Detail: "Actual bytes confirm CALL rel32 (E8 + disp32)."}

        ; For x64 RIP-relative memory addressing, ModRM must have mod=00 and r/m=101.
        ; This validates signatures such as LEA RCX,[RIP+disp32] and also catches
        ; GMalloc candidates where the database intentionally wildcards the ModRM byte.
        if ((prior & 0xC7) = 0x05)
            return {Status: "VERIFIED", Detail: Format("Actual ModRM 0x{:02X} confirms RIP-relative disp32 addressing.", prior)}
    }

    return {Status: "UNVERIFIED", Detail: "Unique target, but the bytes before disp32 are not a recognized CALL rel32 or RIP-relative ModRM shape."}
}

BytesAt(pe, raw, count) {
    count := Min(count, 96)
    out := ""
    Loop count {
        pos := raw + A_Index - 1
        if pos >= pe.Size
            break
        if out != ""
            out .= " "
        out .= Format("{:02X}", NumGet(pe.Data, pos, "UChar"))
    }
    return out
}

SectionForRVA(pe, rva) {
    for section in pe.Sections {
        span := Max(section.VirtualSize, section.RawSize)
        if (rva >= section.VA && rva < section.VA + span)
            return section.Name
    }
    return "?"
}


AttachTierMetadata(result, resolver) {
    ; Explicit resolver-selected tiers take precedence over text inference.
    ; This prevents words in a validation explanation (for example, saying that
    ; semantic XREF was *not* needed) from incorrectly promoting a T1 result to T4.
    if HasProp(result, "TierLocked") && result.TierLocked
        return result

    ; expose the deepest analysis layer actually required by a result.
    ; Tier is stored explicitly on the result object from this point onward so
    ; the UI/report/log do not need to reinterpret resolver details themselves.
    tier := 3
    name := "Structural / callsite"

    source := HasProp(result, "Source") ? result.Source : ""
    validation := HasProp(result, "Validation") ? result.Validation : ""
    secondary := HasProp(result, "SecondaryProof") ? result.SecondaryProof : ""
    consensus := HasProp(result, "Consensus") ? result.Consensus : ""
    combined := source " " validation " " secondary

    ; Deep graph analysis is the most expensive/final resolver layer.
    if resolver.File = "StaticConstructObject" {
        tier := 5
        name := "Deep call graph"
    ; Semantic string/XREF corroboration outranks the structural layer.
    } else if (InStr(combined, "semantic") || InStr(combined, "UTF-16")
        || InStr(combined, "XREF") || InStr(combined, "DrivingBone")) {
        tier := 4
        name := "Semantic XREF"
    ; Existing local and bundled known-good signatures are rescanned/reverified
    ; before generic families. This is deliberately its own provenance tier.
    } else if (InStr(source, "Existing local custom signature:") = 1
        || InStr(source, "Known custom corpus:") = 1
        || InStr(source, "Corpus:") = 1
        || InStr(source, "Existing UE4SS/PatternSleuth log") = 1) {
        tier := 2
        name := "Known / corpus signature"
    ; A unique full direct fingerprint is the cheapest decisive identity path.
    } else if (InStr(source, "PatternSleuth direct prologue") = 1
        && HasProp(result, "Mode") && result.Mode = "direct"
        && !InStr(combined, "constructor-body fingerprint")
        && !InStr(combined, "independent semantic")) {
        tier := 1
        name := "Direct fingerprint"
    } else if consensus != "" {
        tier := 3
        name := "Structural / consensus"
    }

    ; Failed rows still reveal how deep the scanner actually had to go.
    if (result.Status = "NOT FOUND" || result.Status = "AMBIGUOUS") {
        if resolver.File = "FName_Constructor" || resolver.File = "FName_ToString" {
            if tier < 4 {
                tier := 4
                name := "Semantic XREF"
            }
        }
    }

    result.Tier := tier
    result.TierName := name
    result.TierLabel := "T" tier " - " name
    return result
}

StatusIconFor(status) {
    global StatusIconIndex
    if (status = "VERIFIED" || status = "STRONG")
        return StatusIconIndex["GREEN"]
    if (status = "UNVERIFIED")
        return StatusIconIndex["YELLOW"]
    if (status = "NOT FOUND")
        return StatusIconIndex["GRAY"]
    return StatusIconIndex["RED"]
}

RvaInImage(pe, rva) {
    for section in pe.Sections {
        span := Max(section.VirtualSize, section.RawSize)
        if (rva >= section.VA && rva < section.VA + span)
            return true
    }
    return false
}

ScanPE(pe, parsed, maxMatches := 32) {
    nativeResults := NativeCachedScan(pe, parsed, maxMatches)
    if IsObject(nativeResults)
        return nativeResults

    if !HasProp(pe, "ExecScanCache")
        pe.ExecScanCache := Map()
    cacheKey := parsed.CacheKey "|" maxMatches
    if pe.ExecScanCache.Has(cacheKey)
        return pe.ExecScanCache[cacheKey]

    results := []
    for section in pe.Sections {
        if !section.Executable || section.RawSize < parsed.Length
            continue
        sectionResults := ScanSection(pe, section, parsed, maxMatches - results.Length)
        for item in sectionResults
            results.Push(item)
        if results.Length >= maxMatches
            break
    }
    pe.ExecScanCache[cacheKey] := results
    return results
}

ScanSection(pe, section, parsed, maxMatches) {
    out := []
    if maxMatches <= 0
        return out

    anchor := PickAnchorRun(parsed)
    if anchor.SearchIndex < 0
        return out

    secStart := section.RawPtr
    secEnd := section.RawPtr + section.RawSize
    searchPtr := pe.Data.Ptr + secStart + anchor.SearchIndex
    searchEndPtr := pe.Data.Ptr + secEnd

    lastYield := A_TickCount
    while searchPtr < searchEndPtr && out.Length < maxMatches {
        CooperativeScanYield(&lastYield)
        remaining := searchEndPtr - searchPtr
        foundPtr := DllCall("msvcrt\memchr", "Ptr", searchPtr, "Int", anchor.Value, "UPtr", remaining, "Ptr")
        if !foundPtr
            break

        anchorRaw := foundPtr - pe.Data.Ptr
        candidateRaw := anchorRaw - anchor.SearchIndex
        if candidateRaw >= secStart && candidateRaw + parsed.Length <= secEnd {
            runMatches := true
            if anchor.Length > 1 {
                cmp := DllCall("msvcrt\memcmp",
                    "Ptr", pe.Data.Ptr + candidateRaw + anchor.RunStart,
                    "Ptr", anchor.Buffer.Ptr,
                    "UPtr", anchor.Length,
                    "Int")
                runMatches := cmp = 0
            }

            if runMatches && (parsed.AllFixed || PatternMatchesAt(pe.Data, candidateRaw, parsed)) {
                rva := section.VA + (candidateRaw - section.RawPtr)
                out.Push({Raw: candidateRaw, RVA: rva, Section: section.Name})
            }
        }
        searchPtr := foundPtr + 1
    }
    return out
}

PickAnchorRun(parsed) {
    if HasProp(parsed, "AnchorRun")
        return parsed.AnchorRun

    bestStart := -1
    bestLength := 0
    bestSearchOffset := 0
    bestSearchScore := -999
    i := 1

    while i <= parsed.Length {
        if parsed.Masks[i] != 0xFF {
            i += 1
            continue
        }

        runStart1 := i
        while i <= parsed.Length && parsed.Masks[i] = 0xFF
            i += 1
        runLength := i - runStart1

        rareOffset := 0
        rareScore := -999
        Loop runLength {
            idx2 := runStart1 + A_Index - 1
            score := AnchorScore(parsed.Bytes[idx2])
            if score > rareScore {
                rareScore := score
                rareOffset := A_Index - 1
            }
        }

        if runLength > bestLength || (runLength = bestLength && rareScore > bestSearchScore) {
            bestStart := runStart1 - 1
            bestLength := runLength
            bestSearchOffset := rareOffset
            bestSearchScore := rareScore
        }
    }

    if bestStart < 0 {
        parsed.AnchorRun := {RunStart: -1, Length: 0, SearchIndex: -1, Value: 0, Buffer: Buffer(1, 0)}
        return parsed.AnchorRun
    }

    buf := Buffer(bestLength, 0)
    Loop bestLength
        NumPut("UChar", parsed.Bytes[bestStart + A_Index], buf, A_Index - 1)

    parsed.AnchorRun := {
        RunStart: bestStart,
        Length: bestLength,
        SearchIndex: bestStart + bestSearchOffset,
        Value: parsed.Bytes[bestStart + bestSearchOffset + 1],
        Buffer: buf
    }
    return parsed.AnchorRun
}

PickAnchor(parsed) {
    bestIndex := -1
    bestScore := -999
    for i, mask in parsed.Masks {
        if mask != 0xFF
            continue
        value := parsed.Bytes[i]
        score := AnchorScore(value)
        if score > bestScore {
            bestScore := score
            bestIndex := i - 1
        }
    }
    if bestIndex < 0
        return {Index: -1, Value: 0}
    return {Index: bestIndex, Value: parsed.Bytes[bestIndex + 1]}
}

AnchorScore(value) {
    ; Common x64 instruction bytes receive lower scores so memchr lands on fewer candidates.
    static VeryCommon := Map(0x00,1, 0x48,1, 0x8B,1, 0x89,1, 0x24,1, 0xFF,1, 0xE8,1, 0x0F,2, 0x44,2, 0x41,2)
    return VeryCommon.Get(value, 10)
}

PatternMatchesAt(data, raw, parsed) {
    Loop parsed.Length {
        i := A_Index
        mask := parsed.Masks[i]
        if mask = 0
            continue
        b := NumGet(data, raw + i - 1, "UChar")
        if ((b & mask) != parsed.Bytes[i])
            return false
    }
    return true
}

ParsePattern(text) {
    global PatternCache
    normalized := RegExReplace(Trim(text), "\s+", " ")
    if PatternCache.Has(normalized)
        return PatternCache[normalized]

    tokens := StrSplit(normalized, " ")
    bytes := []
    masks := []
    marker := -1

    for token in tokens {
        if token = ""
            continue
        if token = "|" {
            marker := bytes.Length
            continue
        }

        token := StrUpper(token)
        if StrLen(token) != 2
            throw Error("Unsupported pattern token: " token)

        hi := SubStr(token, 1, 1)
        lo := SubStr(token, 2, 1)
        hiVal := HexNibble(hi)
        loVal := HexNibble(lo)

        value := 0
        mask := 0
        if hiVal >= 0 {
            value |= hiVal << 4
            mask |= 0xF0
        }
        if loVal >= 0 {
            value |= loVal
            mask |= 0x0F
        }
        bytes.Push(value)
        masks.Push(mask)
    }

    allFixed := true
    for mask in masks {
        if mask != 0xFF {
            allFixed := false
            break
        }
    }
    parsed := {Bytes: bytes, Masks: masks, Marker: marker, Length: bytes.Length, CacheKey: normalized, AllFixed: allFixed}
    PatternCache[normalized] := parsed
    return parsed
}

HexNibble(ch) {
    if ch = "?"
        return -1
    pos := InStr("0123456789ABCDEF", ch, true)
    return pos ? pos - 1 : -1
}

PatternForUE4SS(text) {
    text := StrReplace(text, "|", "")
    text := RegExReplace(Trim(text), "\s+", " ")
    return StrUpper(text)
}

BuildLua(resolver, result) {
    header := "-- Generated by UE4SS Signature Generator v" APP_VERSION "`r`n"
        . "-- Target: " resolver.File "`r`n"
        . "-- Scan status: " result.Status "`r`n"
        . "-- Analysis tier: " result.TierLabel "`r`n"
    if HasProp(result, "RuntimeImage") && result.RuntimeImage
        header .= "-- Byte source: captured runtime mapped image (protected on-disk executable fallback).`r`n"
    if result.Status = "STRONG"
        header .= "-- WARNING: STRONG result. High confidence, but not fully independently verified. Test in-game before relying on it.`r`n"
    else if result.Status = "UNVERIFIED"
        header .= "-- WARNING: UNVERIFIED candidate. This may resolve the wrong address and can cause UE4SS/game instability. Use only for testing.`r`n"
    header .= "-- Validation: " result.Validation "`r`n"
    if HasProp(result, "SecondaryProof")
        header .= "-- Secondary proof: " result.SecondaryProof "`r`n"
    header .= "-- Resolver source: " result.Source " | mode: " result.Mode "`r`n"
        . Format("-- Match RVA: 0x{:X} | Resolved target RVA: 0x{:X}`r`n", result.MatchRVA, result.TargetRVA)
        . "-- Verify in-game before distributing this signature.`r`n`r`n"

    body := "function Register()`r`n"
        . '    return "' result.AOB '"`r`n'
        . "end`r`n`r`n"

    if (result.Mode = "direct") {
        body .= "function OnMatchFound(MatchAddress)`r`n"
            . "    return MatchAddress"
        if result.Add != 0
            body .= LuaAddressAdjustment(result.Add)
        body .= "`r`nend`r`n"
    } else {
        marker := result.Marker
        body .= "function OnMatchFound(MatchAddress)`r`n"
            . Format("    local Offset = DerefToInt32(MatchAddress + 0x{:X})`r`n", marker)
            . "    if Offset == nil then`r`n"
            . "        return nil`r`n"
            . "    end`r`n"
            . Format("    local RIP = MatchAddress + 0x{:X}`r`n", marker + 4)
            . "    return RIP + Offset"
        if result.Add != 0
            body .= LuaAddressAdjustment(result.Add)
        body .= "`r`nend`r`n"
    }

    return header body
}

WriteUtf8Raw(path, text) {
    if FileExist(path)
        FileDelete(path)
    FileAppend(text, path, "UTF-8-RAW")
}

Log(text) {
    if LogEdit.Value = ""
        LogEdit.Value := text
    else
        LogEdit.Value .= "`r`n" text
    SendMessage(0x115, 7, 0, LogEdit.Hwnd) ; WM_VSCROLL / SB_BOTTOM
}

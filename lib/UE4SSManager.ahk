; UE4SSManager.ahk
; Installs and updates official RE-UE4SS release builds directly from GitHub.
; Release metadata is fetched at runtime, so the version list stays current
; without rebuilding this tool. Only ordinary HTTPS downloads are used.

global UE4SS_RELEASES_API := "https://api.github.com/repos/UE4SS-RE/RE-UE4SS/releases?per_page=100"
global UE4SSManagerDialog := 0
global UE4SSManagerVersionDDL := 0
global UE4SSManagerLocationEdit := 0
global UE4SSManagerBrowseBtn := 0
global UE4SSManagerActionBtn := 0
global UE4SSManagerMode := ""
global UE4SSManagerEntries := []
global UE4SSManagerExePath := ""
global UE4SSManagerBusy := false

global InstallUE4SSBtn, UpdateUE4SSBtn

UE4SS_RefreshButtons() {
    global InstallUE4SSBtn, UpdateUE4SSBtn, ExeEdit, IsScanning, IsBatchScanning, UE4SSManagerBusy

    if !IsSet(InstallUE4SSBtn) || !IsObject(InstallUE4SSBtn)
        return

    path := Trim(ExeEdit.Value, ' "')
    validExe := path != "" && FileExist(path) && RegExMatch(path, "i)\.exe$")
    busy := IsScanning || IsBatchScanning || UE4SSManagerBusy

    InstallUE4SSBtn.Enabled := validExe && !busy
    UpdateUE4SSBtn.Enabled := validExe && !busy && UE4SS_DetectInstall(path).Found
}

UE4SS_OpenManager(mode := "install") {
    global APP_NAME, APP_VERSION, MainGui, ExeEdit, IsScanning, IsBatchScanning, StatusBar
    global UE4SSManagerDialog, UE4SSManagerVersionDDL, UE4SSManagerLocationEdit
    global UE4SSManagerBrowseBtn, UE4SSManagerActionBtn, UE4SSManagerMode
    global UE4SSManagerEntries, UE4SSManagerExePath, UE4SSManagerBusy

    if IsScanning || IsBatchScanning || UE4SSManagerBusy
        return

    exePath := Trim(ExeEdit.Value, ' "')
    if exePath = "" || !FileExist(exePath) || !RegExMatch(exePath, "i)\.exe$") {
        MsgBox("Choose an existing game executable first.", APP_NAME, "Icon!")
        return
    }

    if mode = "update" {
        detected := UE4SS_DetectInstall(exePath)
        if !detected.Found {
            MsgBox("No UE4SS installation was detected for the selected game. Use Install UE4SS instead.", APP_NAME, "Icon!")
            UE4SS_RefreshButtons()
            return
        }
    }

    UE4SSManagerBusy := true
    UE4SS_RefreshButtons()
    try {
        if IsObject(StatusBar)
            StatusBar.SetText("Fetching UE4SS releases...")
        entries := UE4SS_FetchBuilds()
        if entries.Length = 0
            throw Error("GitHub returned no UE4SS user/developer release assets.")
    } catch as err {
        UE4SSManagerBusy := false
        UE4SS_RefreshButtons()
        if IsObject(StatusBar)
            StatusBar.SetText("UE4SS release lookup failed")
        MsgBox("The UE4SS release list could not be loaded.`n`n" err.Message, APP_NAME, "Iconx")
        return
    }
    UE4SSManagerMode := mode
    UE4SSManagerEntries := entries
    UE4SSManagerExePath := exePath

    if IsObject(UE4SSManagerDialog) {
        try UE4SSManagerDialog.Destroy()
    }

    title := mode = "update" ? "Update UE4SS" : "Install UE4SS"
    dlg := Gui("+Owner" MainGui.Hwnd " +ToolWindow", title)
    dlg.SetFont("s10", "Segoe UI")
    dlg.MarginX := 16
    dlg.MarginY := 14

    dlg.AddText("xm ym", mode = "update"
        ? "Choose the UE4SS build to install over the detected installation."
        : "Choose the UE4SS build and confirm where it should be installed.")

    dlg.AddText("xm y+15", "Install location:")
    defaultLocation := UE4SS_DefaultInstallLocation(exePath)
    UE4SSManagerLocationEdit := dlg.AddEdit("xm y+5 w470", defaultLocation)
    UE4SSManagerBrowseBtn := dlg.AddButton("x+8 yp-1 w85 h25", "Browse...")

    dlg.AddText("xm y+16", "Version / variant:")
    displayItems := []
    for entry in entries
        displayItems.Push(entry.Display)
    UE4SSManagerVersionDDL := dlg.AddDropDownList("xm y+5 w563 Choose1", displayItems)

    detected := UE4SS_DetectInstall(exePath)
    if mode = "update" && detected.Found {
        identity := UE4SS_DetectInstalledIdentity(exePath, detected.Root, entries)
        versionText := identity.Version != "" ? "v" identity.Version : "Unknown (installation detected)"
        if identity.GitSha != "" && !UE4SS_VersionMatchesSha(identity.Version, identity.GitSha)
            versionText .= "  (Git " SubStr(identity.GitSha, 1, 8) ")"

        buildText := identity.Variant = "dev" ? "Developer (zDEV)" : (identity.Variant = "user" ? "User" : "Unknown variant")
        if UE4SS_IsExperimentalVersion(identity.Version)
            buildText .= " (Experimental)"

        dlg.AddText("xm y+12 w563 c606060", "Current version: " versionText)
        dlg.AddText("xm y+4 w563 c606060", "Current build: " buildText)

        UE4SS_SelectNewestVariant(identity.Variant != "" ? identity.Variant : "user")
    }

    note := mode = "update"
        ? "Update preserves settings, custom signatures, and Mods state. Known layout/settings-format transitions are migrated or backed up when needed."
        : "Official UE4SS release builds are fetched directly from RE-UE4SS. Normally install to the folder containing the selected game executable."
    dlg.AddText("xm y+15 w563 h44 c606060 Wrap", note)

    UE4SSManagerActionBtn := dlg.AddButton("xm y+8 w105 h29 Default", mode = "update" ? "Update" : "Install")
    cancelBtn := dlg.AddButton("x+8 yp w90 h29", "Cancel")

    UE4SSManagerBrowseBtn.OnEvent("Click", UE4SS_DialogBrowse)
    UE4SSManagerActionBtn.OnEvent("Click", UE4SS_DialogConfirm)
    cancelBtn.OnEvent("Click", UE4SS_DialogClose)
    dlg.OnEvent("Close", UE4SS_DialogClose)
    dlg.OnEvent("Escape", UE4SS_DialogClose)

    UE4SSManagerDialog := dlg
    try MainGui.Opt("+Disabled")
    dlg.Show("AutoSize Center")
    UE4SS_RefreshButtons()
}

UE4SS_DialogBrowse(*) {
    global UE4SSManagerLocationEdit
    startDir := Trim(UE4SSManagerLocationEdit.Value, ' "')
    if startDir = "" || !DirExist(startDir)
        startDir := A_Desktop
    selected := DirSelect(startDir, 0, "Select the UE4SS install directory")
    if selected != ""
        UE4SSManagerLocationEdit.Value := selected
}

UE4SS_DialogClose(*) {
    global UE4SSManagerDialog, UE4SSManagerBusy, MainGui
    UE4SSManagerBusy := false
    if IsObject(UE4SSManagerDialog) {
        try UE4SSManagerDialog.Destroy()
    }
    UE4SSManagerDialog := 0
    try MainGui.Opt("-Disabled")
    UE4SS_RefreshButtons()
}

UE4SS_DialogConfirm(*) {
    global APP_NAME, StatusBar, UE4SSManagerEntries, UE4SSManagerVersionDDL
    global UE4SSManagerLocationEdit, UE4SSManagerMode, UE4SSManagerExePath
    global UE4SSManagerActionBtn, UE4SSManagerBrowseBtn, UE4SSManagerBusy

    index := UE4SSManagerVersionDDL.Value
    if index < 1 || index > UE4SSManagerEntries.Length
        return

    entry := UE4SSManagerEntries[index]
    targetDir := RTrim(Trim(UE4SSManagerLocationEdit.Value, ' "'), "\/")
    if targetDir = "" {
        MsgBox("Choose an install location first.", APP_NAME, "Icon!")
        return
    }

    try DirCreate(targetDir)
    catch as err {
        MsgBox("The selected install location could not be created.`n`n" err.Message, APP_NAME, "Iconx")
        return
    }

    verb := UE4SSManagerMode = "update" ? "Update" : "Install"
    confirm := MsgBox(verb " " entry.Display " to:`n`n" targetDir "`n`nContinue?", APP_NAME " - " verb " UE4SS", "YesNo Iconi Default2")
    if confirm != "Yes"
        return

    UE4SSManagerBusy := true
    UE4SSManagerActionBtn.Enabled := false
    UE4SSManagerBrowseBtn.Enabled := false
    UE4SSManagerVersionDDL.Enabled := false
    UE4SSManagerLocationEdit.Enabled := false
    UE4SS_RefreshButtons()

    try {
        StatusBar.SetText("Downloading " entry.Display "...")
        Log("")
        Log("[UE4SS] Downloading " entry.Display " from the official RE-UE4SS GitHub release...")
        result := UE4SS_InstallBuild(entry, targetDir, UE4SSManagerExePath, UE4SSManagerMode)
        UE4SS_SaveInstallMetadata(UE4SSManagerExePath, entry.Version, entry.Variant, targetDir, result.Layout)
        try DirCreate(UE4SS_ResolveSignatureDir(UE4SSManagerExePath))
        Log("[UE4SS] " (UE4SSManagerMode = "update" ? "Updated" : "Installed") " " entry.Display " -> " targetDir)
        if result.Preserved.Length > 0
            Log("[UE4SS] Preserved user files: " UE4SS_Join(result.Preserved, ", "))
        StatusBar.SetText("UE4SS " (UE4SSManagerMode = "update" ? "updated" : "installed") ": v" entry.Version)

        modeText := UE4SSManagerMode = "update" ? "updated" : "installed"
        UE4SS_DialogClose()
        MsgBox("UE4SS " entry.Display " was " modeText " successfully.`n`nLocation:`n" targetDir, APP_NAME, "Iconi")
    } catch as err {
        UE4SSManagerBusy := false
        try UE4SSManagerActionBtn.Enabled := true
        try UE4SSManagerBrowseBtn.Enabled := true
        try UE4SSManagerVersionDDL.Enabled := true
        try UE4SSManagerLocationEdit.Enabled := true
        UE4SS_RefreshButtons()
        StatusBar.SetText("UE4SS install/update failed")
        Log("[UE4SS] ERROR: " err.Message)
        MsgBox("UE4SS could not be installed.`n`n" err.Message, APP_NAME, "Iconx")
    }
}

UE4SS_FetchBuilds() {
    global UE4SS_RELEASES_API, APP_NAME, APP_VERSION

    http := ComObject("WinHttp.WinHttpRequest.5.1")
    http.SetTimeouts(5000, 5000, 10000, 15000)
    http.Open("GET", UE4SS_RELEASES_API, false)
    http.SetRequestHeader("User-Agent", APP_NAME "/" APP_VERSION)
    http.SetRequestHeader("Accept", "application/vnd.github+json")
    http.Send()
    if http.Status < 200 || http.Status >= 300
        throw Error("GitHub API returned HTTP " http.Status ".")

    json := http.ResponseText
    byVersion := Map()
    pos := 1
    ; Official assets use matching UE4SS_v<version>.zip and
    ; zDEV-UE4SS_v<version>.zip names. Accept both numbered stable releases and
    ; the rolling experimental-latest build so modern UE versions are available.
    pattern := 's)"name":"((zDEV-)?UE4SS_v([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9]+-g[0-9A-Fa-f]+)?)\.zip)".*?"browser_download_url":"([^"]+)"'
    while pos := RegExMatch(json, pattern, &m, pos) {
        assetName := m[1]
        variant := m[2] != "" ? "dev" : "user"
        version := m[3]
        url := StrReplace(m[4], "\/", "/")

        if !byVersion.Has(version)
            byVersion[version] := Map()
        if !byVersion[version].Has(variant)
            byVersion[version][variant] := {Version: version, Variant: variant, Asset: assetName, Url: url}

        pos := m.Pos(0) + m.Len(0)
    }

    versions := []
    for version, _ in byVersion
        versions.Push(version)
    UE4SS_SortVersionsDesc(versions)

    entries := []
    for version in versions {
        variants := byVersion[version]
        experimental := InStr(version, "-") > 0
        suffix := experimental ? " (Experimental)" : ""
        if variants.Has("user") {
            e := variants["user"]
            e.Display := "v" version " — User" suffix
            entries.Push(e)
        }
        if variants.Has("dev") {
            e := variants["dev"]
            e.Display := "v" version " — Developer (zDEV)" suffix
            entries.Push(e)
        }
    }
    return entries
}

UE4SS_SortVersionsDesc(versions) {
    if versions.Length < 2
        return

    Loop versions.Length - 1 {
        i := A_Index + 1
        key := versions[i]
        j := i - 1
        while j >= 1 && UE4SS_CompareVersions(versions[j], key) < 0 {
            versions[j + 1] := versions[j]
            j -= 1
        }
        versions[j + 1] := key
    }
}

UE4SS_CompareVersions(a, b) {
    pa := UE4SS_ParseVersion(a)
    pb := UE4SS_ParseVersion(b)
    Loop 4 {
        av := pa[A_Index]
        bv := pb[A_Index]
        if av > bv
            return 1
        if av < bv
            return -1
    }
    return 0
}

UE4SS_ParseVersion(version) {
    if RegExMatch(version, "i)^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9]+)-g[0-9a-f]+)?", &m)
        return [m[1] + 0, m[2] + 0, m[3] + 0, m[4] != "" ? (m[4] + 0) : 0]
    return [0, 0, 0, 0]
}

UE4SS_SelectNewestVariant(variant := "user") {
    global UE4SSManagerEntries, UE4SSManagerVersionDDL
    for index, entry in UE4SSManagerEntries {
        if entry.Variant = variant {
            UE4SSManagerVersionDDL.Choose(index)
            return
        }
    }
    UE4SSManagerVersionDDL.Choose(1)
}

UE4SS_InstallBuild(entry, targetDir, exePath, mode) {
    tempRoot := A_Temp "\UE4SSSignatureGenerator\install-" A_TickCount
    zipPath := tempRoot "\" entry.Asset
    extractDir := tempRoot "\extract"
    preserved := []

    DirCreate(extractDir)
    try {
        meta := UE4SS_LoadInstallMetadata(exePath)
        detectedInstall := UE4SS_DetectInstall(exePath)
        oldVersion := meta.Version
        if oldVersion = "" && detectedInstall.Found
            oldVersion := UE4SS_DetectInstalledVersion(detectedInstall.Root)
        crossingTo3 := oldVersion != "" && UE4SS_CompareVersions(oldVersion, "3.0.0") < 0 && UE4SS_CompareVersions(entry.Version, "3.0.0") >= 0

        if crossingTo3
            UE4SS_BackupLegacySettings(targetDir, exePath, oldVersion)

        Download(entry.Url, zipPath)
        if !FileExist(zipPath)
            throw Error("The UE4SS archive download did not produce a file.")

        UE4SS_ExpandZip(zipPath, extractDir)
        payloadRoot := UE4SS_FindPayloadRoot(extractDir)
        if payloadRoot = "" || !DirExist(payloadRoot)
            throw Error("The downloaded UE4SS archive could not be unpacked into a usable directory.")

        ; Stable 3.0.x packages use the classic Win64-root layout while current
        ; experimental packages use a ue4ss subfolder. When changing layouts,
        ; migrate user state first so settings, signatures, and third-party mods
        ; follow the active UE4SS.dll instead of being stranded in the old tree.
        packageLayout := UE4SS_DetectPayloadLayout(payloadRoot)
        UE4SS_MigrateUserStateForLayout(targetDir, payloadRoot, !crossingTo3, &preserved, meta.Layout)
        UE4SS_CopyInstallTree(payloadRoot, targetDir, mode, &preserved, !crossingTo3)

        ; UE4SS 3.0+ moved away from the old xinput1_3.dll proxy. Only remove
        ; it automatically when this tool knows it previously installed a <3.0
        ; build for this exact game. Unknown pre-existing game DLLs are untouched.
        if crossingTo3 {
            legacyProxy := targetDir "\xinput1_3.dll"
            if FileExist(legacyProxy) {
                try {
                    FileDelete(legacyProxy)
                    Log("[UE4SS] Removed the legacy xinput1_3.dll proxy while upgrading to UE4SS 3.x.")
                }
            }
        }
    } finally {
        try DirDelete(tempRoot, true)
    }

    return {Preserved: preserved, Layout: packageLayout}
}

UE4SS_ExpandZip(zipPath, destDir) {
    psZip := UE4SS_PSQuote(zipPath)
    psDest := UE4SS_PSQuote(destDir)
    command := 'powershell.exe -NoProfile -NonInteractive -Command "Expand-Archive -LiteralPath ' psZip ' -DestinationPath ' psDest ' -Force"'
    exitCode := RunWait(command, , "Hide")
    if exitCode != 0
        throw Error("Windows PowerShell could not extract the UE4SS archive (exit code " exitCode ").")
}

UE4SS_PSQuote(value) {
    return "'" StrReplace(value, "'", "''") "'"
}

UE4SS_FindPayloadRoot(extractDir) {
    rootFiles := 0
    rootDirs := []
    Loop Files extractDir "\*", "F" {
        rootFiles += 1
    }
    Loop Files extractDir "\*", "D" {
        rootDirs.Push(A_LoopFileFullPath)
    }
    if rootFiles = 0 && rootDirs.Length = 1
        return rootDirs[1]
    return extractDir
}

UE4SS_DetectLayout(root) {
    if root = "" || !DirExist(root)
        return ""
    if FileExist(root "\ue4ss\UE4SS.dll") || FileExist(root "\ue4ss\UE4SS-settings.ini")
        return "subfolder"
    if FileExist(root "\UE4SS.dll") || FileExist(root "\UE4SS-settings.ini")
        return "classic"
    return ""
}

UE4SS_DetectPayloadLayout(payloadRoot) {
    if FileExist(payloadRoot "\ue4ss\UE4SS.dll") || FileExist(payloadRoot "\ue4ss\UE4SS-settings.ini")
        return "subfolder"
    return "classic"
}

UE4SS_MigrateUserStateForLayout(targetRoot, payloadRoot, preserveSettings, &preserved, oldLayoutHint := "") {
    oldLayout := (oldLayoutHint = "classic" || oldLayoutHint = "subfolder") ? oldLayoutHint : UE4SS_DetectLayout(targetRoot)
    newLayout := UE4SS_DetectPayloadLayout(payloadRoot)

    ; Signatures may have been generated before UE4SS itself was installed. Treat
    ; an existing user-data tree as a layout hint so a first install of a newer
    ; subfolder package carries those generated signatures into the live location.
    if oldLayout = "" {
        if newLayout = "subfolder" && (FileExist(targetRoot "\UE4SS-settings.ini") || DirExist(targetRoot "\UE4SS_Signatures") || DirExist(targetRoot "\Mods"))
            oldLayout := "classic"
        else if newLayout = "classic" && (FileExist(targetRoot "\ue4ss\UE4SS-settings.ini") || DirExist(targetRoot "\ue4ss\UE4SS_Signatures") || DirExist(targetRoot "\ue4ss\Mods"))
            oldLayout := "subfolder"
    }

    if oldLayout = "" || oldLayout = newLayout
        return

    oldBase := oldLayout = "subfolder" ? targetRoot "\ue4ss" : targetRoot
    newBase := newLayout = "subfolder" ? targetRoot "\ue4ss" : targetRoot
    DirCreate(newBase)

    if preserveSettings && FileExist(oldBase "\UE4SS-settings.ini") {
        FileCopy(oldBase "\UE4SS-settings.ini", newBase "\UE4SS-settings.ini", true)
        preserved.Push("UE4SS-settings.ini (layout migration)")
    }

    if DirExist(oldBase "\UE4SS_Signatures") {
        UE4SS_CopyDirectoryOverlay(oldBase "\UE4SS_Signatures", newBase "\UE4SS_Signatures")
        preserved.Push("UE4SS_Signatures (layout migration)")
    }

    if DirExist(oldBase "\Mods") {
        UE4SS_CopyDirectoryOverlay(oldBase "\Mods", newBase "\Mods")
        preserved.Push("Mods (layout migration)")
    }

    Log("[UE4SS] Migrated user state from the " oldLayout " layout to the " newLayout " layout before applying the selected release.")
}

UE4SS_CopyDirectoryOverlay(sourceDir, targetDir) {
    sourceDir := RTrim(sourceDir, "\/")
    targetDir := RTrim(targetDir, "\/")
    DirCreate(targetDir)
    Loop Files sourceDir "\*", "FR" {
        src := A_LoopFileFullPath
        rel := SubStr(src, StrLen(sourceDir) + 2)
        dst := targetDir "\" rel
        SplitPath(dst, , &dstDir)
        DirCreate(dstDir)
        FileCopy(src, dst, true)
    }
}

UE4SS_CopyInstallTree(sourceDir, targetDir, mode, &preserved, preserveSettings := true) {
    sourceDir := RTrim(sourceDir, "\/")
    targetDir := RTrim(targetDir, "\/")

    Loop Files sourceDir "\*", "R" {
        src := A_LoopFileFullPath
        rel := SubStr(src, StrLen(sourceDir) + 2)
        dst := targetDir "\" rel

        if InStr(A_LoopFileAttrib, "D") {
            try DirCreate(dst)
            continue
        }

        SplitPath(dst, , &dstDir)
        DirCreate(dstDir)

        if FileExist(dst) && UE4SS_ShouldPreserveExisting(rel, preserveSettings) {
            preserved.Push(rel)
            continue
        }

        FileCopy(src, dst, true)
    }
}

UE4SS_ShouldPreserveExisting(relativePath, preserveSettings := true) {
    p := "\" StrLower(StrReplace(relativePath, "/", "\"))

    ; User-edited core settings.
    if preserveSettings && RegExMatch(p, "i)\\ue4ss-settings\.ini$")
        return true

    ; Custom signatures are exactly what this generator creates and must never
    ; be destroyed by an installer/update operation.
    if InStr(p, "\ue4ss_signatures\")
        return true

    ; Preserve mod load-order / enable-state files while still allowing the
    ; release's built-in mod files themselves to update normally.
    if RegExMatch(p, "i)\\mods\\mods\.txt$")
        return true
    if RegExMatch(p, "i)\\mods\\[^\\]+\\enabled\.txt$")
        return true

    return false
}

UE4SS_DetectInstall(exePath) {
    defaultRoot := UE4SS_ExeDir(exePath)
    meta := UE4SS_LoadInstallMetadata(exePath)
    roots := []
    if meta.Location != ""
        roots.Push(meta.Location)
    if defaultRoot != "" {
        duplicate := false
        for existing in roots {
            if StrLower(RTrim(existing, "\/")) = StrLower(RTrim(defaultRoot, "\/")) {
                duplicate := true
                break
            }
        }
        if !duplicate
            roots.Push(defaultRoot)
    }

    for root in roots {
        if root = "" || !DirExist(root)
            continue
        if FileExist(root "\UE4SS.dll") || FileExist(root "\ue4ss\UE4SS.dll")
            return {Found: true, Root: root}
        if FileExist(root "\UE4SS-settings.ini") && (FileExist(root "\dwmapi.dll") || FileExist(root "\xinput1_3.dll"))
            return {Found: true, Root: root}
    }
    return {Found: false, Root: defaultRoot}
}

UE4SS_DefaultInstallLocation(exePath) {
    detected := UE4SS_DetectInstall(exePath)
    if detected.Found && detected.Root != ""
        return detected.Root
    meta := UE4SS_LoadInstallMetadata(exePath)
    if meta.Location != "" && DirExist(meta.Location)
        return meta.Location
    return UE4SS_ExeDir(exePath)
}

UE4SS_ExeDir(exePath) {
    if exePath = ""
        return ""
    SplitPath(exePath, , &dir)
    return dir
}

UE4SS_ResolveSignatureDir(exePath) {
    exeDir := UE4SS_ExeDir(exePath)
    if exeDir = ""
        return ""

    detected := UE4SS_DetectInstall(exePath)
    root := detected.Found ? detected.Root : exeDir
    meta := UE4SS_LoadInstallMetadata(exePath)

    ; Managed installs remember which package layout is active. This matters if
    ; a user switches between classic and experimental builds because the old
    ; tree is deliberately left intact to preserve user files.
    if meta.Layout = "subfolder"
        return root "\ue4ss\UE4SS_Signatures"
    if meta.Layout = "classic"
        return root "\UE4SS_Signatures"

    ; For pre-existing unmanaged installs, infer the layout from files on disk.
    if FileExist(root "\ue4ss\UE4SS.dll") || FileExist(root "\ue4ss\UE4SS-settings.ini")
        return root "\ue4ss\UE4SS_Signatures"

    return root "\UE4SS_Signatures"
}

UE4SS_DetectInstalledVersion(root) {
    candidates := [root "\UE4SS.dll", root "\ue4ss\UE4SS.dll"]
    for file in candidates {
        if !FileExist(file)
            continue
        try {
            raw := FileGetVersion(file)
            if RegExMatch(raw, "([0-9]+)\.([0-9]+)\.([0-9]+)", &m)
                return m[1] "." m[2] "." m[3]
        }
    }
    return ""
}

UE4SS_DetectInstalledIdentity(exePath, root, entries) {
    meta := UE4SS_LoadInstallMetadata(exePath)
    logInfo := UE4SS_DetectVersionFromLog(root)
    fileVersion := UE4SS_DetectInstalledVersion(root)
    variant := meta.Variant != "" ? meta.Variant : UE4SS_GuessInstalledVariant(root)
    version := ""
    gitSha := logInfo.GitSha

    ; UE4SS writes its semantic version and Git SHA near the top of UE4SS.log.
    ; When that SHA matches one of the currently published release assets, the
    ; full rolling build identifier (for example 3.0.1-1133-gabcdef12) can be
    ; reconstructed rather than showing only the 3-part DLL version.
    if logInfo.Version != "" {
        version := UE4SS_MatchReleaseVersion(logInfo.Version, logInfo.GitSha, entries)
        if version = ""
            version := logInfo.Version
    }

    ; Managed installs retain the exact release asset version. Prefer that exact
    ; build when it agrees with the live log, or when no usable log exists yet.
    if meta.Version != "" {
        if version = "" {
            version := meta.Version
        } else if UE4SS_BaseVersion(meta.Version) = UE4SS_BaseVersion(version) {
            if gitSha = "" || UE4SS_VersionMatchesSha(meta.Version, gitSha)
                version := meta.Version
        }
    }

    ; File-version metadata is a final fallback, and also protects against stale
    ; manager metadata after a user manually replaces UE4SS.dll with another
    ; major/minor/hotfix version but has not launched the game to refresh the log.
    if fileVersion != "" {
        if version = ""
            version := fileVersion
        else if UE4SS_BaseVersion(version) != fileVersion
            version := fileVersion
    }

    return {Version: version, Variant: variant, GitSha: gitSha}
}

UE4SS_DetectVersionFromLog(root) {
    best := {Version: "", GitSha: "", Modified: ""}
    candidates := [root "\UE4SS.log", root "\ue4ss\UE4SS.log"]

    for file in candidates {
        if !FileExist(file)
            continue

        text := ""
        try text := FileRead(file, "UTF-8")
        catch {
            try text := FileRead(file)
        }
        if text = ""
            continue

        version := ""
        sha := ""
        if RegExMatch(text, "i)UE4SS\s*-\s*v([0-9]+\.[0-9]+\.[0-9]+)[^\r\n]*Git SHA #([0-9A-Fa-f]{7,40})", &m) {
            version := m[1]
            sha := StrLower(m[2])
        } else if RegExMatch(text, "i)UE4SS\s*-\s*v([0-9]+\.[0-9]+\.[0-9]+)", &m2) {
            version := m2[1]
        }

        if version = ""
            continue

        modified := ""
        try modified := FileGetTime(file, "M")
        if best.Version = "" || modified > best.Modified
            best := {Version: version, GitSha: sha, Modified: modified}
    }

    return best
}

UE4SS_MatchReleaseVersion(baseVersion, gitSha, entries) {
    if baseVersion = ""
        return ""

    if gitSha != "" {
        for entry in entries {
            if !RegExMatch(entry.Version, "i)^([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-g([0-9a-f]+)$", &m)
                continue
            if m[1] = baseVersion && UE4SS_ShaMatches(m[3], gitSha)
                return entry.Version
        }
    }

    ; Stable releases have no rolling build suffix, so the semantic version is
    ; already the complete public release identifier.
    for entry in entries {
        if entry.Version = baseVersion
            return baseVersion
    }
    return ""
}

UE4SS_BaseVersion(version) {
    if RegExMatch(version, "i)^v?([0-9]+\.[0-9]+\.[0-9]+)", &m)
        return m[1]
    return ""
}

UE4SS_ShaMatches(a, b) {
    a := StrLower(Trim(a))
    b := StrLower(Trim(b))
    if a = "" || b = ""
        return false
    return InStr(a, b) = 1 || InStr(b, a) = 1
}

UE4SS_VersionMatchesSha(version, gitSha) {
    if version = "" || gitSha = ""
        return false
    if RegExMatch(version, "i)-g([0-9a-f]+)$", &m)
        return UE4SS_ShaMatches(m[1], gitSha)
    return false
}

UE4SS_IsExperimentalVersion(version) {
    return RegExMatch(version, "i)-[0-9]+-g[0-9a-f]+$") != 0
}

UE4SS_BackupLegacySettings(targetDir, exePath, oldVersion) {
    global RecentSettingsDir
    candidates := [targetDir "\UE4SS-settings.ini", targetDir "\ue4ss\UE4SS-settings.ini"]
    for source in candidates {
        if !FileExist(source)
            continue
        stamp := FormatTime(, "yyyyMMdd-HHmmss")
        backupDir := RecentSettingsDir "\backups\" UE4SS_PathKey(exePath) "\" stamp
        DirCreate(backupDir)
        FileCopy(source, backupDir "\UE4SS-settings-v" oldVersion ".ini", true)
        Log("[UE4SS] Backed up the pre-3.0 UE4SS-settings.ini before installing the 3.x settings format: " backupDir)
        return
    }
}

UE4SS_GuessInstalledVariant(root) {
    if root = ""
        return "user"

    ; Official zDEV packages include UE4SS.pdb. Check that exact artifact instead
    ; of treating an unrelated game PDB in Win64 as proof of a developer package.
    if FileExist(root "\UE4SS.pdb") || FileExist(root "\ue4ss\UE4SS.pdb")
        return "dev"
    return "user"
}

UE4SS_SaveInstallMetadata(exePath, version, variant, location, layout := "") {
    global RecentSettingsDir, RecentSettingsFile
    key := UE4SS_PathKey(exePath)
    try {
        DirCreate(RecentSettingsDir)
        IniWrite(version, RecentSettingsFile, "UE4SSManager", key "_Version")
        IniWrite(variant, RecentSettingsFile, "UE4SSManager", key "_Variant")
        IniWrite(location, RecentSettingsFile, "UE4SSManager", key "_Location")
        IniWrite(layout, RecentSettingsFile, "UE4SSManager", key "_Layout")
    }
}

UE4SS_LoadInstallMetadata(exePath) {
    global RecentSettingsFile
    key := UE4SS_PathKey(exePath)
    version := ""
    variant := ""
    location := ""
    layout := ""
    try version := IniRead(RecentSettingsFile, "UE4SSManager", key "_Version", "")
    try variant := IniRead(RecentSettingsFile, "UE4SSManager", key "_Variant", "")
    try location := IniRead(RecentSettingsFile, "UE4SSManager", key "_Location", "")
    try layout := IniRead(RecentSettingsFile, "UE4SSManager", key "_Layout", "")
    return {Version: Trim(version), Variant: Trim(variant), Location: Trim(location, ' "'), Layout: Trim(layout)}
}

UE4SS_PathKey(path) {
    ; Stable FNV-1a style 32-bit key for storing per-game metadata in settings.ini.
    hash := 2166136261
    normalized := StrLower(Trim(path, ' "'))
    Loop StrLen(normalized) {
        ch := SubStr(normalized, A_Index, 1)
        hash := (hash ^ Ord(ch)) & 0xFFFFFFFF
        hash := (hash * 16777619) & 0xFFFFFFFF
    }
    return Format("{:08X}", hash)
}

UE4SS_Join(values, separator := ", ") {
    text := ""
    for index, value in values
        text .= (index > 1 ? separator : "") value
    return text
}

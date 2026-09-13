; Persistent recent-executable history. Stored outside the release directory so
; replacing/upgrading the app does not reset the list.

global RECENT_LIMIT := 20
global RecentPaths := []
global RecentSettingsDir := A_AppData "\UE4SSSignatureGenerator"
global RecentSettingsFile := RecentSettingsDir "\settings.ini"
global LogDestination := ""


LoadLogDestinationSetting() {
    global LogDestination, RecentSettingsFile
    try LogDestination := Trim(IniRead(RecentSettingsFile, "General", "LogDestination", ""), ' "')
    catch
        LogDestination := ""
}

SaveLogDestinationSetting(value) {
    global LogDestination, RecentSettingsDir, RecentSettingsFile
    LogDestination := Trim(value, ' "')
    try {
        DirCreate(RecentSettingsDir)
        IniWrite(LogDestination, RecentSettingsFile, "General", "LogDestination")
    }
}

LoadRecentPaths() {
    global RecentPaths, RECENT_LIMIT, RecentSettingsFile
    RecentPaths := []
    seen := Map()

    Loop RECENT_LIMIT {
        path := ""
        try path := IniRead(RecentSettingsFile, "Recent", "Path" A_Index, "")
        catch
            path := ""
        path := Trim(path, ' "')
        if path = "" || !FileExist(path) || !RegExMatch(path, "i)\.exe$")
            continue
        key := NormalizeExePath(path)
        if seen.Has(key)
            continue
        seen[key] := true
        RecentPaths.Push(path)
    }
}

SaveRecentPaths() {
    global RecentPaths, RECENT_LIMIT, RecentSettingsDir, RecentSettingsFile
    try DirCreate(RecentSettingsDir)
    Loop RECENT_LIMIT {
        value := A_Index <= RecentPaths.Length ? RecentPaths[A_Index] : ""
        try IniWrite(value, RecentSettingsFile, "Recent", "Path" A_Index)
    }
}

AddRecentPath(path) {
    global RecentPaths, RECENT_LIMIT
    path := Trim(path, ' "')
    if path = "" || !FileExist(path) || !RegExMatch(path, "i)\.exe$")
        return

    key := NormalizeExePath(path)
    removeIndex := 0
    for index, existing in RecentPaths {
        if NormalizeExePath(existing) = key {
            removeIndex := index
            break
        }
    }
    if removeIndex > 0
        RecentPaths.RemoveAt(removeIndex)

    RecentPaths.InsertAt(1, path)
    while RecentPaths.Length > RECENT_LIMIT
        RecentPaths.Pop()

    SaveRecentPaths()
    RefreshRecentDDL()
}

RefreshRecentDDL() {
    global RecentDDL, RecentPaths
    if !IsSet(RecentDDL) || !IsObject(RecentDDL)
        return

    items := ["Select a recent executable..."]
    for path in RecentPaths
        items.Push(RecentDisplayName(path))

    RecentDDL.Delete()
    RecentDDL.Add(items)
    RecentDDL.Choose(1)
}

RestoreMostRecentExecutable() {
    global RecentPaths, ExeEdit, RecentDDL

    if RecentPaths.Length < 1
        return

    path := RecentPaths[1]
    if !FileExist(path)
        return

    ; Restore only the selected path. A previous scan result is deliberately not
    ; restored, so Generate/Open Report remain disabled until this executable is
    ; scanned in the current session.
    ExeEdit.Value := path
    ScheduleEngineStatusRefresh()

    ; Keep the Recent control visually in sync with the auto-filled executable.
    if IsSet(RecentDDL) && IsObject(RecentDDL)
        RecentDDL.Choose(2)
}

RecentDisplayName(path) {
    SplitPath(path, &fileName, &dir)

    ; Lead with the user-facing game title rather than the immediate Win64
    ; directory. FriendlyGameNameFromExe() prefers Steam's
    ; steamapps\common\<Game Title> folder and falls back to the usual
    ; Unreal <Game>\<Project>\Binaries\Win64 layout for non-Steam installs.
    gameName := ""
    try gameName := Trim(FriendlyGameNameFromExe(path))
    catch
        gameName := ""

    if gameName != ""
        return gameName "  —  " fileName "  —  " path

    ; Last-resort compatibility fallback if title inference is unavailable.
    SplitPath(dir, &parentName)
    if parentName != ""
        return parentName "  —  " fileName "  —  " path
    return fileName "  —  " path
}

RecentSelectionChanged(*) {
    global RecentDDL, RecentPaths, ExeEdit, IsScanning, APP_NAME
    if IsScanning
        return
    index := RecentDDL.Value - 1
    if index < 1 || index > RecentPaths.Length
        return

    path := RecentPaths[index]
    if !FileExist(path) {
        RecentPaths.RemoveAt(index)
        SaveRecentPaths()
        RefreshRecentDDL()
        MsgBox("That recent executable no longer exists and was removed from the list.", APP_NAME, "Icon!")
        return
    }

    ExeEdit.Value := path
    InvalidateScanState()
    ScheduleEngineStatusRefresh()
    UE4SS_RefreshButtons()
}

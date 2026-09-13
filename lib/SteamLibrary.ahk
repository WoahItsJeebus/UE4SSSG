; Installed Steam-library discovery for Batch mode.
;
; SteamDB's public FileDetectionRuleSets identifies technologies by applying
; filename/path rules to each Steam depot.  This module applies the generator's
; already-attributed local EngineDetection rules to installed app folders and
; never uploads a game file, executable, app manifest, or Steam account data.

SteamLibrary_DiscoverUnrealExecutables() {
    result := {
        Success: false,
        SteamRoot: "",
        Libraries: [],
        InstalledApps: 0,
        AppsWithExecutables: 0,
        UnrealApps: 0,
        Candidates: [],
        Notes: []
    }

    steamRoot := SteamLibrary_FindSteamRoot()
    if steamRoot = "" {
        result.Notes.Push("Steam installation was not found in the current user's registry or the standard install locations.")
        return result
    }

    result.Success := true
    result.SteamRoot := steamRoot
    libraries := SteamLibrary_GetLibraries(steamRoot)
    result.Libraries := libraries

    seenApps := Map()
    seenExecutables := Map()
    for library in libraries {
        manifests := library "\steamapps\appmanifest_*.acf"
        try {
            Loop Files manifests, "F" {
                manifestPath := A_LoopFileFullPath
                app := SteamLibrary_ReadAppManifest(manifestPath)
                if app.AppId = "" || app.InstallDir = ""
                    continue

                appKey := StrLower(library) "|" app.AppId
                if seenApps.Has(appKey)
                    continue
                seenApps[appKey] := true
                result.InstalledApps += 1

                gameRoot := library "\steamapps\common\" app.InstallDir
                if !DirExist(gameRoot)
                    continue
                if !SteamLibrary_HasLikelyUnrealLayout(gameRoot)
                    continue

                exe := SteamLibrary_FindPreferredGameExecutable(gameRoot)
                if exe = ""
                    continue
                result.AppsWithExecutables += 1

                ; EngineDetect uses the SteamDB-style filename/path evidence
                ; plus adjacent Windows Unreal layout checks. Only confirmed
                ; local Unreal results are queued; unknown/mixed games stay out
                ; of the automatic queue and can still be added manually.
                detection := EngineDetect_Get(exe)
                if detection.Decision != "UNREAL"
                    continue

                key := NormalizeExePath(exe)
                if seenExecutables.Has(key)
                    continue
                seenExecutables[key] := true
                result.UnrealApps += 1
                result.Candidates.Push({
                    Path: exe,
                    AppId: app.AppId,
                    Name: app.Name != "" ? app.Name : app.InstallDir,
                    Engine: detection.Engine,
                    Confidence: detection.Confidence,
                    Evidence: detection.EvidenceText
                })
            }
        } catch as err {
            result.Notes.Push("Could not read Steam library manifests in " library ": " err.Message)
        }
    }

    return result
}

SteamLibrary_HasLikelyUnrealLayout(gameRoot) {
    ; Fast local prefilter: packaged UE games normally keep Content\Paks or
    ; the SteamDB Unreal Engine directory markers at the install root or one
    ; project-directory below it. This prevents broad executable walks through
    ; every non-Unreal Steam game before the full EngineDetection confirmation.
    if SteamLibrary_HasUnrealLayoutAt(gameRoot)
        return true

    try {
        Loop Files gameRoot "\*", "D" {
            if SteamLibrary_HasUnrealLayoutAt(A_LoopFileFullPath)
                return true
        }
    } catch {
        return false
    }
    return false
}

SteamLibrary_HasUnrealLayoutAt(root) {
    return DirExist(root "\Content\Paks")
        || DirExist(root "\Engine\Shaders\Binaries")
        || DirExist(root "\Engine\Binaries\ThirdParty")
        || FileExist(root "\Config\DefaultEngine.ini")
}

SteamLibrary_FindSteamRoot() {
    candidates := []
    for keyPath in ["HKEY_CURRENT_USER\Software\Valve\Steam", "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam", "HKEY_LOCAL_MACHINE\SOFTWARE\Valve\Steam"] {
        for valueName in ["SteamPath", "InstallPath"] {
            try {
                value := Trim(RegRead(keyPath, valueName), ' "')
                if value != ""
                    candidates.Push(value)
            }
        }
    }
    candidates.Push(A_ProgramFiles " (x86)\Steam")
    candidates.Push(A_ProgramFiles "\Steam")

    seen := Map()
    for path in candidates {
        path := RTrim(StrReplace(path, "/", "\"), "\")
        key := StrLower(path)
        if path = "" || seen.Has(key)
            continue
        seen[key] := true
        if FileExist(path "\steam.exe") && DirExist(path "\steamapps")
            return path
    }
    return ""
}

SteamLibrary_GetLibraries(steamRoot) {
    libraries := [steamRoot]
    vdfPath := steamRoot "\steamapps\libraryfolders.vdf"
    if !FileExist(vdfPath)
        return libraries

    try contents := FileRead(vdfPath, "UTF-8")
    catch
        return libraries

    ; New-format VDF stores each entry as "path" "...". Old installations
    ; used a numeric key directly. Support both while retaining Steam's root.
    pos := 1
    while RegExMatch(contents, 'im)^\s*"path"\s+"([^"]+)"', &m, pos) {
        SteamLibrary_AddUniquePath(libraries, StrReplace(m[1], "\\\\", "\\"))
        pos := m.Pos(0) + m.Len(0)
    }
    pos := 1
    while RegExMatch(contents, 'im)^\s*"\d+"\s+"([^"]+)"', &m, pos) {
        SteamLibrary_AddUniquePath(libraries, StrReplace(m[1], "\\\\", "\\"))
        pos := m.Pos(0) + m.Len(0)
    }
    return libraries
}

SteamLibrary_AddUniquePath(paths, path) {
    path := RTrim(StrReplace(Trim(path, ' "'), "/", "\"), "\")
    if path = "" || !DirExist(path)
        return
    for existing in paths {
        if StrLower(existing) = StrLower(path)
            return
    }
    paths.Push(path)
}

SteamLibrary_ReadAppManifest(manifestPath) {
    result := {AppId: "", Name: "", InstallDir: ""}
    try contents := FileRead(manifestPath, "UTF-8")
    catch
        return result

    if RegExMatch(contents, 'im)^\s*"appid"\s+"([^"]+)"', &m)
        result.AppId := m[1]
    if RegExMatch(contents, 'im)^\s*"name"\s+"([^"]*)"', &m)
        result.Name := m[1]
    if RegExMatch(contents, 'im)^\s*"installdir"\s+"([^"]+)"', &m)
        result.InstallDir := m[1]
    return result
}

SteamLibrary_FindPreferredGameExecutable(gameRoot) {
    bestPath := ""
    bestScore := -100000
    searchRoots := [gameRoot]
    seen := Map()

    ; Steam Windows builds almost always use either <game>\Binaries\Win64 or
    ; <game>\<Project>\Binaries\Win64. Restrict discovery to those authored
    ; locations rather than recursively walking every file in large installs.
    try {
        Loop Files gameRoot "\*", "D" {
            name := StrLower(A_LoopFileName)
            if name != "engine" && name != "redist" && name != "_commonredist"
                searchRoots.Push(A_LoopFileFullPath)
        }

        for root in searchRoots {
            for pattern in [root "\Binaries\Win64\*.exe", root "\*.exe"] {
                Loop Files pattern, "F" {
                    path := A_LoopFileFullPath
                    key := StrLower(path)
                    if seen.Has(key)
                        continue
                    seen[key] := true
                    if !SteamLibrary_IsWin64Executable(path)
                        continue

                    score := SteamLibrary_GameExecutableScore(path)
                    if score > bestScore {
                        bestPath := path
                        bestScore := score
                    }
                }
            }
        }
    } catch {
        return ""
    }

    return bestScore >= 0 ? bestPath : ""
}

SteamLibrary_GameExecutableScore(path) {
    SplitPath(path, &name)
    lowerName := StrLower(name)
    lowerPath := StrLower(path)

    ; Third-party launchers, prerequisites, editor tooling, and anti-cheat
    ; helpers can be 64-bit executables but are not the installed game binary.
    if RegExMatch(lowerName, "i)^(?:crashreportclient|unreal(?:editor|ed)|ue[45]editor|ue4prereqsetup|start_protected_game|easyanticheat|eac|beservice|battleye|steam(?:service|setup)?|vc_redist|dxsetup|launcher|setup|install)")
        return -100000

    score := 0
    if RegExMatch(lowerName, "-win64-(?:shipping|test|development|debug)\.exe$")
        score += 100
    if InStr(lowerPath, "\binaries\win64\")
        score += 60
    if InStr(lowerPath, "\binaries\")
        score += 20
    if InStr(lowerName, "shipping")
        score += 15
    if InStr(lowerName, "launcher")
        score -= 50
    return score
}

SteamLibrary_IsWin64Executable(path) {
    try {
        file := FileOpen(path, "r")
        if !IsObject(file)
            return false
        try {
            header := Buffer(4096, 0)
            bytesRead := file.RawRead(header, header.Size)
            if bytesRead < 0x40 || NumGet(header, 0, "UShort") != 0x5A4D
                return false
            peOffset := NumGet(header, 0x3C, "UInt")
            if peOffset + 6 > bytesRead || NumGet(header, peOffset, "UInt") != 0x00004550
                return false
            return NumGet(header, peOffset + 4, "UShort") = 0x8664
        } finally file.Close()
    } catch {
        return false
    }
}

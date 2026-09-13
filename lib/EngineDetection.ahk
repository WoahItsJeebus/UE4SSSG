; Offline game-engine preflight for the selected executable.
;
; File/path evidence is intentionally inspired by SteamDB's open-source
; FileDetectionRuleSets project (MIT licensed). We keep only a compact subset
; useful for distinguishing Unreal Engine from common alternatives and combine
; those markers with UE-specific Windows layout conventions. No network access
; is required and no executable content is uploaded anywhere.

global EngineDetectionCache := Map()

global ENGINE_DISPLAY_NAMES := Map(
    "Unreal", "Unreal Engine",
    "Unity", "Unity",
    "Godot", "Godot",
    "CryEngine", "CryEngine",
    "Frostbite", "Frostbite",
    "GameMaker", "GameMaker",
    "RenPy", "Ren'Py",
    "RPGMaker", "RPG Maker",
    "RE_Engine", "RE Engine",
    "Source2", "Source 2",
    "Source", "Source",
    "MonoGame", "MonoGame",
    "FNA", "FNA",
    "XNA", "XNA",
    "idTech", "id Tech",
    "REDengine", "REDengine",
    "GZDoom", "GZDoom",
    "Electron", "Electron",
    "NWJS", "NW.js",
    "Defold", "Defold",
    "Construct", "Construct",
    "GDevelop", "GDevelop",
    "Love2D", "LÖVE / Love2D",
    "OGRE", "OGRE",
    "Unigine", "Unigine",
    "XRay", "X-Ray",
    "UbisoftAnvil", "Ubisoft Anvil",
    "Snowdrop", "Snowdrop",
    "Telltale", "Telltale Tool",
    "Stride", "Stride / Xenko",
    "KiriKiri", "KiriKiri",
    "TyranoBuilder", "TyranoBuilder",
    "AmazonLumberyard", "Amazon Lumberyard"
)

EngineDetect_ClearCache() {
    global EngineDetectionCache
    EngineDetectionCache := Map()
}

EngineDetect_Get(exePath, force := false) {
    global EngineDetectionCache
    path := Trim(exePath, ' "')
    key := StrLower(path)
    if !force && EngineDetectionCache.Has(key)
        return EngineDetectionCache[key]

    result := EngineDetect_Inspect(path)
    EngineDetectionCache[key] := result
    return result
}

EngineDetect_Inspect(exePath) {
    global ENGINE_DISPLAY_NAMES

    result := {
        EngineKey: "Unknown",
        Engine: "Unknown",
        Decision: "UNKNOWN",
        Confidence: "LOW",
        Score: 0,
        UnrealScore: 0,
        RunnerUp: "",
        RunnerUpScore: 0,
        Root: "",
        Evidence: [],
        EvidenceText: "",
        FilesExamined: 0,
        TreeTruncated: false
    }

    path := Trim(exePath, ' "')
    if path = "" || !FileExist(path) || !RegExMatch(path, "i)\.exe$")
        return result

    SplitPath(path, &fileName, &exeDir, &ext, &stem)
    roots := EngineDetect_GetCandidateRoots(path)
    if roots.Length = 0
        roots.Push(exeDir)
    result.Root := roots[1]

    scores := Map()
    evidence := Map()
    for key, display in ENGINE_DISPLAY_NAMES {
        scores[key] := 0
        evidence[key] := []
    }

    ; Strong local-layout checks first. These are cheap and usually decisive.
    EngineDetect_CheckSelectedExe(path, exeDir, stem, scores, evidence)
    EngineDetect_CheckRoots(roots, scores, evidence)

    ; If the cheap checks are not decisive, sample nearby file paths using the
    ; same kind of filename/path evidence SteamDB's detector is built around.
    bestBefore := EngineDetect_BestScore(scores)
    if bestBefore.Score >= 12 {
        ; Strong adjacent/root evidence is already decisive. Avoid walking a
        ; huge game tree just to rediscover the same engine markers.
        tree := {FilesExamined: 0, Truncated: false}
    } else {
        scanBudget := bestBefore.Score >= 7 ? 450 : 850
        scanLimit := bestBefore.Score >= 7 ? 3500 : 7000
        tree := EngineDetect_ScanTree(roots[1], scores, evidence, scanLimit, scanBudget)
    }
    result.FilesExamined := tree.FilesExamined
    result.TreeTruncated := tree.Truncated

    unrealScore := scores.Has("Unreal") ? scores["Unreal"] : 0
    result.UnrealScore := unrealScore

    best := EngineDetect_BestScore(scores)
    runner := EngineDetect_BestScore(scores, best.Key)
    result.RunnerUp := runner.Key != "" && ENGINE_DISPLAY_NAMES.Has(runner.Key) ? ENGINE_DISPLAY_NAMES[runner.Key] : ""
    result.RunnerUpScore := runner.Score

    if best.Key = "Unreal" {
        result.EngineKey := "Unreal"
        result.Engine := "Unreal Engine"
        result.Score := best.Score
        if best.Score >= 12 && best.Score >= runner.Score + 3 {
            result.Decision := "UNREAL"
            result.Confidence := "HIGH"
        } else if best.Score >= 7 && runner.Score <= 3 {
            result.Decision := "UNREAL"
            result.Confidence := "MEDIUM"
        } else if runner.Score >= 5 {
            result.Decision := "MIXED"
            result.Confidence := "LOW"
        }
    } else if best.Score >= 12 && best.Score >= unrealScore + 3 {
        result.EngineKey := best.Key
        result.Engine := ENGINE_DISPLAY_NAMES.Has(best.Key) ? ENGINE_DISPLAY_NAMES[best.Key] : best.Key
        result.Score := best.Score
        result.Decision := "NON_UNREAL"
        result.Confidence := "HIGH"
    } else if best.Score >= 8 && unrealScore <= 3 {
        result.EngineKey := best.Key
        result.Engine := ENGINE_DISPLAY_NAMES.Has(best.Key) ? ENGINE_DISPLAY_NAMES[best.Key] : best.Key
        result.Score := best.Score
        result.Decision := "NON_UNREAL"
        result.Confidence := "MEDIUM"
    } else if unrealScore >= 6 && best.Score >= 6 {
        result.EngineKey := best.Key
        result.Engine := best.Key = "Unreal" ? "Unreal Engine" : (ENGINE_DISPLAY_NAMES.Has(best.Key) ? ENGINE_DISPLAY_NAMES[best.Key] : best.Key)
        result.Score := best.Score
        result.Decision := "MIXED"
        result.Confidence := "LOW"
    } else {
        result.EngineKey := best.Score > 0 ? best.Key : "Unknown"
        result.Engine := best.Score > 0 && ENGINE_DISPLAY_NAMES.Has(best.Key) ? ENGINE_DISPLAY_NAMES[best.Key] : "Unknown"
        result.Score := best.Score
        result.Decision := "UNKNOWN"
        result.Confidence := "LOW"
    }

    chosenEvidence := []
    if result.EngineKey != "Unknown" && evidence.Has(result.EngineKey) {
        for item in evidence[result.EngineKey]
            chosenEvidence.Push(item)
    }
    if result.Decision = "MIXED" && result.EngineKey != "Unreal" && evidence.Has("Unreal") {
        for item in evidence["Unreal"] {
            if chosenEvidence.Length >= 6
                break
            EngineDetect_PushUnique(chosenEvidence, item)
        }
    }
    if chosenEvidence.Length = 0 && unrealScore > 0 && evidence.Has("Unreal") {
        for item in evidence["Unreal"]
            chosenEvidence.Push(item)
    }

    result.Evidence := chosenEvidence
    result.EvidenceText := EngineDetect_JoinEvidence(chosenEvidence, 6)
    return result
}

EngineDetect_CheckSelectedExe(exePath, exeDir, stem, scores, evidence) {
    lowerPath := StrLower(StrReplace(exePath, "/", "\"))
    lowerName := StrLower(stem)

    ; Unreal conventions around the selected executable itself.
    if RegExMatch(lowerPath, "\\binaries\\win64\\")
        EngineDetect_Add(scores, evidence, "Unreal", 3, "selected EXE is under Binaries\Win64")
    if RegExMatch(lowerName, "-win64-(?:shipping|test|development|debug)$")
        EngineDetect_Add(scores, evidence, "Unreal", 5, "selected EXE uses Unreal's -Win64-<configuration> naming")

    ; Unity's player DLL and <Game>_Data directory are especially strong because
    ; they sit directly beside the executable they belong to.
    if FileExist(exeDir "\UnityPlayer.dll")
        EngineDetect_Add(scores, evidence, "Unity", 14, "UnityPlayer.dll beside selected EXE")
    if DirExist(exeDir "\" stem "_Data")
        EngineDetect_Add(scores, evidence, "Unity", 12, stem "_Data directory beside selected EXE")
    if FileExist(exeDir "\" stem "_Data\globalgamemanagers") || FileExist(exeDir "\" stem "_Data\globalgamemanagers.assets")
        EngineDetect_Add(scores, evidence, "Unity", 12, "globalgamemanagers in the selected game's _Data directory")
    if FileExist(exeDir "\GameAssembly.dll")
        EngineDetect_Add(scores, evidence, "Unity", 5, "GameAssembly.dll beside selected EXE")

    ; Godot export convention: an external PCK commonly shares the EXE stem.
    if FileExist(exeDir "\" stem ".pck")
        EngineDetect_Add(scores, evidence, "Godot", 14, stem ".pck beside selected EXE")

    if FileExist(exeDir "\data.win")
        EngineDetect_Add(scores, evidence, "GameMaker", 14, "data.win beside selected EXE")
    if FileExist(exeDir "\re_chunk_000.pak")
        EngineDetect_Add(scores, evidence, "RE_Engine", 14, "re_chunk_000.pak beside selected EXE")
    if FileExist(exeDir "\UnityEngine.dll")
        EngineDetect_Add(scores, evidence, "Unity", 10, "UnityEngine.dll beside selected EXE")
}

EngineDetect_CheckRoots(roots, scores, evidence) {
    for root in roots {
        if root = "" || !DirExist(root)
            continue

        ; Unreal markers adapted from SteamDB plus Windows shipping-layout clues.
        if DirExist(root "\Engine\Binaries\ThirdParty")
            EngineDetect_Add(scores, evidence, "Unreal", 10, "Engine\Binaries\ThirdParty directory")
        if DirExist(root "\Engine\Shaders")
            EngineDetect_Add(scores, evidence, "Unreal", 8, "Engine\Shaders directory")
        if DirExist(root "\Content\Paks")
            EngineDetect_Add(scores, evidence, "Unreal", 8, "Content\Paks directory")
        if FileExist(root "\Config\DefaultEngine.ini")
            EngineDetect_Add(scores, evidence, "Unreal", 6, "Config\DefaultEngine.ini")
        if EngineDetect_HasFile(root "\Content\Paks\*.pak")
            EngineDetect_Add(scores, evidence, "Unreal", 4, "Unreal-style .pak under Content\Paks")
        if EngineDetect_HasFile(root "\Content\Paks\*.utoc") || EngineDetect_HasFile(root "\Content\Paks\*.ucas")
            EngineDetect_Add(scores, evidence, "Unreal", 4, "IoStore .utoc/.ucas under Content\Paks")

        ; High-confidence alternatives.
        if FileExist(root "\project.godot")
            EngineDetect_Add(scores, evidence, "Godot", 14, "project.godot")
        if FileExist(root "\GodotSharp.dll")
            EngineDetect_Add(scores, evidence, "Godot", 9, "GodotSharp.dll")

        if FileExist(root "\CrySystem.dll") || FileExist(root "\Bin64\CrySystem.dll") || FileExist(root "\bin\win_x64\CrySystem.dll")
            EngineDetect_Add(scores, evidence, "CryEngine", 14, "CrySystem.dll")
        if FileExist(root "\Cry3DEngine.dll") || FileExist(root "\Bin64\Cry3DEngine.dll")
            EngineDetect_Add(scores, evidence, "CryEngine", 12, "Cry3DEngine.dll")

        if FileExist(root "\Runtime_Win64_retail.BuildSettings")
            EngineDetect_Add(scores, evidence, "Frostbite", 14, "Runtime_Win64_retail.BuildSettings")
        if EngineDetect_HasFile(root "\Engine.BuildInfo*.dll")
            EngineDetect_Add(scores, evidence, "Frostbite", 12, "Engine.BuildInfo*.dll")

        if DirExist(root "\renpy")
            EngineDetect_Add(scores, evidence, "RenPy", 14, "renpy directory")
        if FileExist(root "\www\js\rpg_core.js") || FileExist(root "\www\js\rmmz_core.js")
            EngineDetect_Add(scores, evidence, "RPGMaker", 14, "RPG Maker core JavaScript runtime")
        if FileExist(root "\RPG_RT.ini")
            EngineDetect_Add(scores, evidence, "RPGMaker", 12, "RPG_RT.ini")

        if FileExist(root "\gameinfo.gi")
            EngineDetect_Add(scores, evidence, "Source2", 14, "gameinfo.gi")
        if FileExist(root "\gameinfo.txt") && (FileExist(root "\bin\vphysics.dll") || FileExist(root "\vphysics.dll"))
            EngineDetect_Add(scores, evidence, "Source", 14, "gameinfo.txt + vphysics.dll")

        if FileExist(root "\MonoGame.Framework.dll")
            EngineDetect_Add(scores, evidence, "MonoGame", 14, "MonoGame.Framework.dll")
        if FileExist(root "\FNA.dll") || FileExist(root "\fna.dll")
            EngineDetect_Add(scores, evidence, "FNA", 14, "FNA.dll")
        if EngineDetect_HasFile(root "\Microsoft.Xna.Framework*.dll")
            EngineDetect_Add(scores, evidence, "XNA", 12, "Microsoft.Xna.Framework*.dll")

        if FileExist(root "\resources\app.asar")
            EngineDetect_Add(scores, evidence, "Electron", 12, "resources\app.asar")
        if FileExist(root "\nw.dll") || FileExist(root "\nw.pak")
            EngineDetect_Add(scores, evidence, "NWJS", 10, "NW.js runtime files")

        if FileExist(root "\game.dmanifest")
            EngineDetect_Add(scores, evidence, "Defold", 14, "game.dmanifest")
        if FileExist(root "\c3runtime.js") || FileExist(root "\c3main.js") || FileExist(root "\c2runtime.js")
            EngineDetect_Add(scores, evidence, "Construct", 12, "Construct runtime JavaScript")
        if FileExist(root "\LICENSE.GDevelop.txt")
            EngineDetect_Add(scores, evidence, "GDevelop", 14, "LICENSE.GDevelop.txt")
        if FileExist(root "\love.dll")
            EngineDetect_Add(scores, evidence, "Love2D", 12, "love.dll")
        if FileExist(root "\OgreMain.dll") || FileExist(root "\OgreMain_x64.dll")
            EngineDetect_Add(scores, evidence, "OGRE", 12, "OgreMain DLL")
        if FileExist(root "\Unigine_x64.dll") || FileExist(root "\core.ung")
            EngineDetect_Add(scores, evidence, "Unigine", 12, "Unigine runtime marker")
        if FileExist(root "\xrGame.dll")
            EngineDetect_Add(scores, evidence, "XRay", 14, "xrGame.dll")
        if FileExist(root "\bootstrap.cfg")
            EngineDetect_Add(scores, evidence, "AmazonLumberyard", 10, "bootstrap.cfg")
        if FileExist(root "\Stride.Core.dll") || FileExist(root "\Xenko.Core.dll")
            EngineDetect_Add(scores, evidence, "Stride", 12, "Stride/Xenko Core DLL")
    }
}

EngineDetect_ScanTree(root, scores, evidence, maxEntries := 8000, budgetMs := 1100) {
    result := {FilesExamined: 0, Truncated: false}
    if root = "" || !DirExist(root)
        return result

    deadline := A_TickCount + budgetMs
    queue := [{Path: root, Depth: 0}]
    qIndex := 1
    stop := false

    while qIndex <= queue.Length && !stop {
        item := queue[qIndex]
        qIndex += 1

        try {
            Loop Files item.Path "\*", "FD" {
                if A_TickCount >= deadline || result.FilesExamined >= maxEntries {
                    result.Truncated := true
                    stop := true
                    break
                }

                result.FilesExamined += 1
                full := A_LoopFileFullPath
                name := A_LoopFileName
                attrs := A_LoopFileAttrib

                if InStr(attrs, "D") {
                    if item.Depth < 4 && !EngineDetect_SkipDirectory(name)
                        queue.Push({Path: full, Depth: item.Depth + 1})
                    continue
                }

                rel := EngineDetect_RelativePath(root, full)
                EngineDetect_CheckInventoryFile(name, rel, scores, evidence)
            }
        } catch {
            ; Access-denied subdirectories are irrelevant to a best-effort engine
            ; preflight. Continue with the rest of the local tree.
        }
    }

    return result
}

EngineDetect_CheckInventoryFile(name, relPath, scores, evidence) {
    lowerName := StrLower(name)
    lowerRel := StrLower(StrReplace(relPath, "\", "/"))

    switch lowerName {
        case "unityplayer.dll", "unityengine.dll":
            EngineDetect_Add(scores, evidence, "Unity", 12, name)
        case "globalgamemanagers", "globalgamemanagers.assets":
            EngineDetect_Add(scores, evidence, "Unity", 12, name)
        case "project.godot":
            EngineDetect_Add(scores, evidence, "Godot", 14, relPath)
        case "godotsharp.dll":
            EngineDetect_Add(scores, evidence, "Godot", 9, relPath)
        case "cry3dengine.dll", "cryd3dcompilerstub.dll", "cryrendervulkan.dll", "cryrenderd3d11.dll", "cryrenderd3d12.dll":
            EngineDetect_Add(scores, evidence, "CryEngine", 12, relPath)
        case "runtime_win64_retail.buildsettings":
            EngineDetect_Add(scores, evidence, "Frostbite", 14, relPath)
        case "data.win":
            EngineDetect_Add(scores, evidence, "GameMaker", 14, relPath)
        case "godotsteam.dll", "steamsdk-godot.dll":
            EngineDetect_Add(scores, evidence, "Godot", 9, relPath)
        case "re_chunk_000.pak":
            EngineDetect_Add(scores, evidence, "RE_Engine", 14, relPath)
        case "gameinfo.gi":
            EngineDetect_Add(scores, evidence, "Source2", 14, relPath)
        case "vphysics.dll", "bsppack.dll":
            EngineDetect_Add(scores, evidence, "Source", 10, relPath)
        case "monogame.framework.dll":
            EngineDetect_Add(scores, evidence, "MonoGame", 14, relPath)
        case "fna.dll":
            EngineDetect_Add(scores, evidence, "FNA", 14, relPath)
        case "gzdoom.pk3", "gzdoom.sf2", "zmusic.dll":
            EngineDetect_Add(scores, evidence, "GZDoom", 12, relPath)
        case "game.dmanifest":
            EngineDetect_Add(scores, evidence, "Defold", 14, relPath)
        case "license.gdevelop.txt":
            EngineDetect_Add(scores, evidence, "GDevelop", 14, relPath)
        case "ogremain.dll", "ogremain_x64.dll":
            EngineDetect_Add(scores, evidence, "OGRE", 12, relPath)
        case "unigine_x64.dll", "unigine_x86.dll", "core.ung":
            EngineDetect_Add(scores, evidence, "Unigine", 12, relPath)
        case "xrgame.dll":
            EngineDetect_Add(scores, evidence, "XRay", 14, relPath)
        case "bakinengine.dll":
            EngineDetect_Add(scores, evidence, "RPGMaker", 8, relPath)
        case "stride.core.dll", "xenko.core.dll":
            EngineDetect_Add(scores, evidence, "Stride", 12, relPath)
        case "bootstrap.cfg":
            EngineDetect_Add(scores, evidence, "AmazonLumberyard", 10, relPath)
    }

    if InStr(lowerName, "engine.buildinfo") && RegExMatch(lowerName, "\.dll$")
        EngineDetect_Add(scores, evidence, "Frostbite", 12, relPath)
    if RegExMatch(lowerName, "^cry(?:render|system|action).+\.dll$")
        EngineDetect_Add(scores, evidence, "CryEngine", 8, relPath)
    if RegExMatch(lowerName, "^microsoft\.xna\.framework.*\.dll$")
        EngineDetect_Add(scores, evidence, "XNA", 12, relPath)

    if RegExMatch(lowerName, "\.(?:uasset|upk)$")
        EngineDetect_Add(scores, evidence, "Unreal", 4, relPath)
    if InStr(lowerRel, "engine/shaders/binaries/") || InStr(lowerRel, "engine/binaries/thirdparty/")
        EngineDetect_Add(scores, evidence, "Unreal", 8, relPath)
    if InStr(lowerRel, "/content/paks/") && RegExMatch(lowerName, "\.(?:pak|utoc|ucas)$")
        EngineDetect_Add(scores, evidence, "Unreal", 4, relPath)

    if RegExMatch(lowerName, "\.(?:rgssad|rgss2a|rgss3a)$") || lowerName = "rpg_rt.ini"
        EngineDetect_Add(scores, evidence, "RPGMaker", 12, relPath)
    if RegExMatch(lowerRel, "(?:^|/)js/(?:rpg|rmmz)_core\.js$")
        EngineDetect_Add(scores, evidence, "RPGMaker", 14, relPath)

    if InStr(lowerRel, "renpy/") || RegExMatch(lowerName, "\.rpyb$")
        EngineDetect_Add(scores, evidence, "RenPy", 10, relPath)
    if RegExMatch(lowerName, "\.pk4$")
        EngineDetect_Add(scores, evidence, "idTech", 9, relPath)
    if RegExMatch(lowerName, "\.(?:redscripts|w2scripts)$")
        EngineDetect_Add(scores, evidence, "REDengine", 12, relPath)
    if RegExMatch(lowerName, "\.rpkg$")
        EngineDetect_Add(scores, evidence, "RE_Engine", 5, relPath)
    if RegExMatch(lowerName, "\.sdfdata$")
        EngineDetect_Add(scores, evidence, "Snowdrop", 12, relPath)
    if RegExMatch(lowerName, "\.forge$")
        EngineDetect_Add(scores, evidence, "UbisoftAnvil", 10, relPath)
    if RegExMatch(lowerName, "\.ttarch2?$")
        EngineDetect_Add(scores, evidence, "Telltale", 12, relPath)
    if RegExMatch(lowerName, "\.xnb$")
        EngineDetect_Add(scores, evidence, "XNA", 5, relPath)
    if RegExMatch(lowerName, "\.xp3$")
        EngineDetect_Add(scores, evidence, "KiriKiri", 10, relPath)
    if lowerName = "tyrano.js"
        EngineDetect_Add(scores, evidence, "TyranoBuilder", 12, relPath)
    if lowerName = "c2runtime.js" || lowerName = "c3runtime.js" || lowerName = "c3main.js"
        EngineDetect_Add(scores, evidence, "Construct", 12, relPath)
    if lowerName = "resources.assets" && InStr(lowerRel, "_data/")
        EngineDetect_Add(scores, evidence, "Unity", 8, relPath)
    if lowerName = "app.asar" && InStr(lowerRel, "resources/")
        EngineDetect_Add(scores, evidence, "Electron", 12, relPath)
    if lowerName = "nw.dll" || lowerName = "nw.pak"
        EngineDetect_Add(scores, evidence, "NWJS", 10, relPath)
}

EngineDetect_GetCandidateRoots(exePath) {
    roots := []
    SplitPath(exePath, , &exeDir)
    EngineDetect_PushUnique(roots, exeDir)

    projectRoot := ""
    if RegExMatch(exeDir, "i)^(.*)\\Binaries\\Win64$", &m)
        projectRoot := m[1]
    else if RegExMatch(exeDir, "i)^(.*)\\bin\\(?:win64|x64)$", &m)
        projectRoot := m[1]

    if projectRoot != "" {
        EngineDetect_PushUnique(roots, projectRoot, true)
        SplitPath(projectRoot, , &parent)
        if !EngineDetect_IsBroadRoot(parent)
            EngineDetect_PushUnique(roots, parent)
    } else {
        SplitPath(exeDir, , &parent)
        if parent != "" && !EngineDetect_IsBroadRoot(parent)
            EngineDetect_PushUnique(roots, parent)
    }

    return roots
}

EngineDetect_IsBroadRoot(path) {
    if path = ""
        return true
    SplitPath(path, &name)
    lower := StrLower(name)
    return (lower = "common" || lower = "steamapps" || lower = "steamlibrary"
        || lower = "program files" || lower = "program files (x86)" || lower = "games")
}

EngineDetect_SkipDirectory(name) {
    lower := StrLower(name)
    return lower = "saved" || lower = "logs" || lower = "screenshots"
        || lower = "deriveddatacache" || lower = "shadercache" || lower = "crashreportclient"
        || lower = "node_modules" || lower = ".git" || lower = "__installer"
}

EngineDetect_HasFile(pattern) {
    try {
        Loop Files pattern, "F"
            return true
    }
    return false
}

EngineDetect_RelativePath(root, fullPath) {
    if StrLen(fullPath) > StrLen(root) && StrLower(SubStr(fullPath, 1, StrLen(root))) = StrLower(root)
        return LTrim(SubStr(fullPath, StrLen(root) + 1), "\/")
    return fullPath
}

EngineDetect_Add(scores, evidence, engine, points, detail) {
    if !scores.Has(engine) {
        scores[engine] := 0
        evidence[engine] := []
    }
    scores[engine] += points
    if detail != "" && evidence[engine].Length < 8
        EngineDetect_PushUnique(evidence[engine], detail)
}

EngineDetect_BestScore(scores, excludeKey := "") {
    bestKey := ""
    bestScore := 0
    for key, score in scores {
        if key = excludeKey
            continue
        if score > bestScore {
            bestKey := key
            bestScore := score
        }
    }
    return {Key: bestKey, Score: bestScore}
}

EngineDetect_PushUnique(arr, value, forceFront := false) {
    if value = ""
        return false
    lower := StrLower(value)
    for existing in arr {
        if StrLower(existing) = lower
            return false
    }
    if forceFront
        arr.InsertAt(1, value)
    else
        arr.Push(value)
    return true
}

EngineDetect_JoinEvidence(items, limit := 5) {
    if !IsObject(items) || items.Length = 0
        return "no decisive local engine markers found"
    out := ""
    count := Min(items.Length, limit)
    Loop count
        out .= (A_Index > 1 ? "; " : "") items[A_Index]
    if items.Length > count
        out .= "; +" (items.Length - count) " more"
    return out
}

EngineDetect_ShortLabel(result) {
    if result.Decision = "UNREAL"
        return "Unreal Engine (" StrLower(result.Confidence) " confidence)"
    if result.Decision = "NON_UNREAL"
        return result.Engine " (" StrLower(result.Confidence) " confidence)"
    if result.Decision = "MIXED"
        return "Mixed / uncertain engine evidence"
    return result.Engine != "Unknown" ? result.Engine " (uncertain)" : "Unknown / unconfirmed"
}

EngineDetect_CompactLabel(result) {
    if result.Decision = "UNREAL"
        return "Unreal Engine (" StrLower(result.Confidence) ")"
    if result.Decision = "NON_UNREAL"
        return result.Engine " (" StrLower(result.Confidence) ")"
    if result.Decision = "MIXED"
        return "Mixed / uncertain"
    return result.Engine != "Unknown" ? result.Engine " (?)" : "Unknown"
}

EngineDetect_StatusColor(result) {
    if result.Decision = "UNREAL"
        return "2EA043"
    if result.Decision = "NON_UNREAL"
        return "CF222E"
    if result.Decision = "MIXED"
        return "D29922"
    return "606060"
}

EngineDetect_ConfirmSingle(result) {
    global APP_NAME
    if result.Decision = "UNREAL"
        return true

    evidenceText := EngineDetect_JoinEvidence(result.Evidence, 5)
    if result.Decision = "NON_UNREAL" {
        message := "Engine preflight detected " result.Engine " rather than Unreal Engine.`n`n"
            . "UE4SS targets Unreal Engine games, so scanning this executable is unlikely to produce meaningful custom signatures and may waste several minutes.`n`n"
            . "Evidence: " evidenceText "`n`nScan anyway?"
    } else if result.Decision = "MIXED" {
        message := "Engine preflight found mixed or conflicting engine evidence and could not safely confirm Unreal Engine.`n`n"
            . "Strongest evidence currently points to " result.Engine ".`n`n"
            . "Evidence: " evidenceText "`n`nScan anyway?"
    } else {
        message := "Engine preflight could not confidently confirm that this executable belongs to an Unreal Engine game.`n`n"
            . "Protected, heavily customized, or unusual Unreal titles can still land here, so this is a warning rather than a hard block.`n`n"
            . "Evidence: " evidenceText "`n`nScan anyway?"
    }

    answer := MsgBox(message, APP_NAME " - Engine preflight", "YesNo Icon! Default2")
    return answer = "Yes"
}

EngineDetect_BatchPreflight(paths) {
    global APP_NAME
    detections := []
    flagged := []
    skip := Map()

    for path in paths {
        d := EngineDetect_Get(path)
        detections.Push(d)
        if d.Decision != "UNREAL"
            flagged.Push({Path: path, Detection: d})
    }

    if flagged.Length = 0
        return {Cancelled: false, Skip: skip, Detections: detections, Flagged: 0}

    lines := ""
    shown := Min(flagged.Length, 10)
    Loop shown {
        item := flagged[A_Index]
        SplitPath(item.Path, &name)
        lines .= "- " name ": " EngineDetect_ShortLabel(item.Detection) "`n"
    }
    if flagged.Length > shown
        lines .= "- ...and " (flagged.Length - shown) " more`n"

    message := "Engine preflight flagged " flagged.Length " batch target(s) that are not confidently confirmed as Unreal Engine:`n`n"
        . lines
        . "`nYes = Scan every target anyway.`n"
        . "No = Skip the flagged targets and scan only confirmed Unreal targets.`n"
        . "Cancel = Stop the batch before scanning."

    answer := MsgBox(message, APP_NAME " - Batch engine preflight", "YesNoCancel Icon! Default2")
    if answer = "Cancel"
        return {Cancelled: true, Skip: skip, Detections: detections, Flagged: flagged.Length}

    if answer = "No" {
        for item in flagged
            skip[StrLower(Trim(item.Path, ' "'))] := true
    }

    return {Cancelled: false, Skip: skip, Detections: detections, Flagged: flagged.Length}
}

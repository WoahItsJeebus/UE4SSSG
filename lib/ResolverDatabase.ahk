; Resolver database layer. Keep byte-pattern families isolated from UI/orchestration.

BuildResolverDB() {
    db := []

    db.Push({
        File: "FName_Constructor",
        Required: true,
        Mode: "direct",
        Add: 0,
        Patterns: [
            {Pattern: "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 41 8B F8 33 C9 4C 8B DA 44 8B D1 4C 8B CA 48 85 D2 74 ?? 0F B7 02 66 85 C0", Mode: "direct", Source: "PatternSleuth direct prologue"},
            {Pattern: "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 48 89 54 24 20 33 C9 41 8B F8 4C 8B D2 44 8B C9 48 85 D2 74 ?? 0F B7 02 66 85 C0", Mode: "direct", Source: "PatternSleuth direct prologue"},
            {Pattern: "EB 07 48 8D 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 B8 01 00 00 00 E8 | ?? ?? ?? ??", Mode: "rel32", Source: "PatternSleuth inlined-call fallback"},
            {Pattern: "40 53 48 83 EC 30 48 8B D9 48 85 D2 74 ?? 45 8B C8 C7 44 24 28 FF FF FF FF", Mode: "direct", Source: "UE4SS legacy constructor variant"}
        ]
    })

    db.Push({
        File: "FName_ToString",
        Required: false,
        Mode: "direct",
        Add: 0,
        Patterns: [
            {Pattern: "56 57 48 83 EC 28 48 89 D6 48 89 CF 83 79 ?? 00 74", Mode: "direct", Source: "PatternSleuth direct prologue"},
            {Pattern: "E8 | ?? ?? ?? ?? ?? 01 00 00 00 ?? 39 ?? 48 0F 8E", Mode: "rel32", Source: "PatternSleuth FString-return callsite"},
            {Pattern: "E8 | ?? ?? ?? ?? BD 01 00 00 00 41 39 6E ?? 0F 8E", Mode: "rel32", Source: "PatternSleuth FString-return callsite"},
            {Pattern: "E8 | ?? ?? ?? ?? 48 8B 4C 24 ?? 8B FD 48 85 C9", Mode: "rel32", Source: "PatternSleuth FString-return callsite"},
            {Pattern: "48 8B 48 ?? 48 89 4C 24 ?? 48 8D 4C 24 ?? E8 | ?? ?? ?? ?? 83 7C 24 ?? 00 48 8D", Mode: "rel32", Source: "PatternSleuth FString-out callsite"},
            {Pattern: "E8 | ?? ?? ?? ?? 83 7D C8 00 48 8D 15 ?? ?? ?? ?? 0F 5A DE", Mode: "rel32", Source: "PatternSleuth legacy ToString C family"},
            {Pattern: "E8 | ?? ?? ?? ?? 83 7D C8 00 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 0F", Mode: "rel32", Source: "PatternSleuth legacy ToString D family"},
            {Pattern: "C6 ?? 2A 01 48 89 44 24 ?? E8 | ?? ?? ?? ?? 83 7C 24 ?? 00", Mode: "rel32", Source: "PatternSleuth legacy ToString FullyLoad family"},
            {Pattern: "48 89 0F EB 15 48 8B CF E8 | ?? ?? ?? ?? 48 8D ?? 24 ?? 48 8B CB E8 ?? ?? ?? ?? 48 8B ?? 24 ?? 48 85 C9 74 05", Mode: "rel32", Source: "PatternSleuth legacy ToString FMemoryArchive family"},
            {Pattern: "48 63 C9 48 C1 ?? 05 48 03 ?? E8 | ?? ?? ?? ?? 48 8B ?? ?? 48 85 C9 74 05", Mode: "rel32", Source: "PatternSleuth legacy ToString FLoadTimeTracker family"},
            {Pattern: "E8 ?? ?? ?? ?? 48 ?? ?? 24 ?? 48 ?? ?? 24 98 00 00 00 E8 | ?? ?? ?? ?? 8B 48 ?? 83 F9 01", Mode: "rel32", Source: "PatternSleuth legacy ToString ISlateStyleJoin family"},
            {Pattern: "00 74 ?? 48 8D ?? 24 ?? 48 8B ?? E8 ?? ?? ?? ?? 48 8B C8 48 8D ?? 24 ?? E8 | ?? ?? ?? ?? 83 78 08 00 74 ?? ?? ?? ?? EB", Mode: "rel32", Source: "PatternSleuth legacy ToString UClassRename family"},
            {Pattern: "48 8D 0C C1 E8 | ?? ?? ?? ?? 83 78 08 00", Mode: "rel32", Source: "PatternSleuth legacy ToString LinkerManagerExec family"},
            {Pattern: "48 89 5C 24 ?? 48 89 ?? 24 ?? 48 89 ?? 24 ?? 41 56 48 83 EC ?? 48 8B DA 4C 8B F1 E8 ?? ?? ?? ?? 4C 8B C8 41 8B 06 99", Mode: "direct", Source: "PatternSleuth legacy ToString direct family"}
        ]
    })

    db.Push({
        File: "StaticConstructObject",
        Required: true,
        Mode: "rel32",
        Add: 0,
        Patterns: [
            "48 89 44 24 28 C7 44 24 20 00 00 00 00 E8 | ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B ?? 24",
            "E8 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 E9 ?? 32 88 ?? ?? ?? ?? 80 E1 01 30 88 ?? ?? ?? ?? 48",
            "E8 | ?? ?? ?? ?? 48 8B D8 48 39 75 30 74 15",
            "C6 44 24 30 00 0F 57 C0 0F 11 44 24 38 4C 89 FF E8 | ?? ?? ?? ?? 48 89"
        ]
    })

    db.Push({
        File: "GMalloc",
        Required: true,
        Mode: "rel32",
        Add: 0,
        Patterns: [
            "48 ?? ?? F0 ?? 0F B1 ?? | ?? ?? ?? ?? 74 ?? ?? 85 ?? 74 ?? ?? 8B",
            {Pattern: "EB 03 ?? 8B ?? 48 8B ?? F0 ?? 0F B1 ?? | ?? ?? ?? ?? 74 ?? ?? 85 ?? 74 ?? ?? 8B", Mode: "rel32", Source: "Known custom corpus: GMalloc Purg_notX verified family"},
            "E8 ?? ?? ?? ?? 48 8B ?? F0 ?? 0F B1 ?? | ?? ?? ?? ?? 74 ?? ?? 85 ?? 74 ?? ?? 8B",
            "48 85 C9 74 2E 53 48 83 EC 20 48 8B D9 48 8B ?? | ?? ?? ?? ?? 48 85 C9",
            "75 ?? E8 ?? ?? ?? ?? 48 8B 0D | ?? ?? ?? ?? 48 8B ?? 48 ?? ?? FF 50 ?? 48 83 C4 ?? ?? C3",
            "48 85 C9 74 ?? 4C 8B 05 | ?? ?? ?? ?? 4D 85 C0 0F 84",
            "48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 0D | ?? ?? ?? ?? 48 8B 01 FF 50 ?? 84 C0 75 ?? B9 38 00 00 00",
            "84 C0 75 ?? B9 38 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 0D | ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89",
            "FF 15 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 89 3D | ?? ?? ?? ?? 48 8B 7C 24 20 48 83 C4 28 C3",
            "48 89 ?? F0 ?? 0F B1 ?? | ?? ?? ?? ?? 48 39 ?? 74 ?? 48 8B 1D",
            "48 89 ?? F0 ?? 0F B1 ?? | ?? ?? ?? ?? 48 39 ?? 75 ?? 48 83 C4",
            {Pattern: "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 85 C9 75 ?? E8 ?? ?? ?? FF 48 8B 0D | ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48", Mode: "rel32", Source: "PatternSleuth current GMalloc pattern"},
            {Pattern: "48 89 5C 24 08 57 48 83 EC ?? 48 83 3D ?? ?? ?? ?? 00 8B DA 48 8B F9 75 07 E8 ?? ?? ?? FF EB 07 33 C9 E8 ?? ?? ?? FF 48 8B 0D | ?? ?? ?? ?? 44 8B C3 48 8B D7 48 8B 01 FF 50 10 80 3D ?? ?? ?? ?? 00 48 8B D8 75 ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 05 E8 ?? ?? ?? FF ?? 44 24 ?? 01", Mode: "rel32", Source: "PatternSleuth current GMalloc pattern"},
            {Pattern: "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 8B DA 48 8B 0D | ?? ?? ?? ?? 48 85 C9 75 2E 65 48 8B 04 25 58 00 00 00 44 8B 05 ?? ?? ?? ?? BA 18 00 00 00 4E 8B 04 C0 42 8B 04 02 39 05 ?? ?? ?? ?? 7E 09 EB 1E 48 8B 0D ?? ?? ?? ?? 48 8B 01 44 8B C3 48 8B D7 48 8B 5C 24 30 48 83 C4 20 5F 48 FF 60 10 48 8D 0D", Mode: "rel32", Source: "PatternSleuth current GMalloc pattern"}
        ]
    })

    db.Push({
        File: "GUObjectArray",
        Required: true,
        Mode: "rel32",
        Add: 0,
        Patterns: [
            {Pattern: "83 E0 FB 89 47 08 8B 44 24 60 48 8D 0D | ?? ?? ?? ?? 44 8B CE 89 44 24 20 48 8B D7 E8 ?? ?? ?? ??", Mode: "rel32", Source: "Known custom corpus: Life is Strange Reunion GUObjectArray"},
            "8B 05 ?? ?? ?? ?? 3B 05 ?? ?? ?? ?? 75 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D | ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05",
            "74 ?? 48 8D 0D | ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01",
            "75 ?? 48 ?? ?? 48 8D 0D | ?? ?? ?? ?? E8 ?? ?? ?? ?? 45 33 C9 4C 89 74 24",
            "45 84 C0 48 C7 41 10 00 00 00 00 B8 FF FF FF FF 4C 8D 1D | ?? ?? ?? ?? 89 41 08 4C 8B D1 4C 89 19 0F 45 05 ?? ?? ?? ?? FF C0 89 41 08 3B 05",
            "81 CE 00 00 00 02 83 E0 FB 89 47 08 48 8D 0D | ?? ?? ?? ?? 48 89 FA 45 31 C0 E8 ?? ?? ?? ??",
            "E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D | ?? ?? ?? ?? 29 C8 87 05"
        ]
    })


    ; Optional compatibility/feature signatures recognized by current UE4SS PatternSleuth.
    db.Push({
        File: "FText_Constructor",
        Required: false,
        Mode: "direct",
        Add: 0,
        Patterns: [
            {Pattern: "48 8B 74 24 60 40 F6 C5 02 74 11 83 E5 FD 4D 85 F6 74 09 49 8B 06 49 8B CE FF 50 10 4C 8B 74 24 30 40 F6 C5 01 48 8B 6C 24 58 74 0E 48 85 FF 74 09 48 8B 07 48 8B CF FF 50 10 83 4B 08 12", Mode: "direct", Add: -206, Source: "Known custom corpus: Life is Strange Reunion FText_Constructor"},
            {Pattern: "40 53 48 83 EC ?? 48 8B D9 E8 | ?? ?? ?? ?? 83 4B ?? 12 48 8B C3 48 83 ?? ?? 5B C3", Mode: "rel32", Source: "PatternSleuth FText indirect family"},
            {Pattern: "EB 12 48 8D ?? 24 ?? E8 | ?? ?? ?? ?? ?? 02 00 00 00 48 8B 10 48 89 17", Mode: "rel32", Source: "PatternSleuth FText indirect family"},
            {Pattern: "EB 12 48 8D ?? 24 ?? E8 | ?? ?? ?? ?? ?? 02 00 00 00 48 8B 10 89", Mode: "rel32", Source: "PatternSleuth FText indirect family"},
            {Pattern: "48 89 5C 24 10 48 89 6C 24 18 56 57 41 54 41 56 41 57 48 83 EC 40 45 33 E4 48 8B F1 41 8B DC 4C 8B F2 89 5C 24 70 41 8D 4C 24 70 E8 ?? ?? ?? FF 48 8B F8 48 85 C0 0F 84 ?? 00 00 00 49 63 5E 08 ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? EB 2E 45 33 C0 48 8D 4C 24 20 8B D3 E8", Mode: "direct", Source: "PatternSleuth FText direct family"},
            {Pattern: "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 54 41 56 41 57 48 83 EC 40 4C 8B F1 48 8B F2", Mode: "direct", Source: "PatternSleuth FText direct family"},
            {Pattern: "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 54 41 56 41 57 48 83 EC 40 45 33 E4 48 8B F1", Mode: "direct", Source: "PatternSleuth FText direct family"},
            {Pattern: "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8D 05 ?? ?? ?? ?? 33 F6 48 8B D9 48 89 44 24", Mode: "direct", Source: "PatternSleuth FText UE5.4 direct family"}
        ]
    })

    db.Push({
        File: "GUObjectHashTables",
        Required: false,
        Mode: "rel32",
        Add: 0,
        Patterns: [
            {Pattern: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 40 41 0F B6 F9 49 8B D8 48 8B F2 48 8B E9 E8 | ?? ?? ?? ?? 44 8B 84 24 80 00 00 00 4C 8B CB", Mode: "rel32", Source: "PatternSleuth FUObjectHashTables::Get family"},
            {Pattern: "48 89 5C 24 08 48 89 74 24 10 4C 89 44 24 18 57 48 83 EC 40 41 0F B6 D9 48 8B FA 48 8B F1 E8 | ?? ?? ?? ?? 44 8B 84 24 80 00 00 00 48 8B D6", Mode: "rel32", Source: "PatternSleuth FUObjectHashTables::Get family"},
            {Pattern: "E8 | ?? ?? ?? ?? 45 33 FF 48 8B F0 33 C0 F0 44 0F B1 3D", Mode: "rel32", Source: "PatternSleuth FUObjectHashTables::Get family"},
            {Pattern: "CC 48 83 EC 28 E8 | ?? ?? ?? ?? 48 8B C8 48 83 C4 28 48 FF", Mode: "rel32", Source: "PatternSleuth FUObjectHashTables::Get family"},
            {Pattern: "CC CC CC CC CC CC CC 48 83 EC 28 E8 | ?? ?? ?? ?? 48 8B 80 ?? 01 00 00 90 48", Mode: "rel32", Source: "PatternSleuth FUObjectHashTables::Get family"},
            {Pattern: "89 ?? C8 4D 89 ?? C0 E8 | ?? ?? ?? ?? 4C 8B ?? 44 8B", Mode: "rel32", Source: "PatternSleuth FUObjectHashTables::Get family"}
        ]
    })

    db.Push({
        File: "GNatives",
        Required: false,
        Mode: "rel32",
        Add: 0,
        Patterns: [
            {Pattern: "80 3D ?? ?? ?? ?? 00 48 8D 15 ?? ?? ?? ?? 75 ?? C6 05 ?? ?? ?? ?? 01 48 8D 05 | ?? ?? ?? ?? B9", Mode: "rel32", Source: "PatternSleuth GNatives direct family"}
        ]
    })

    db.Push({
        File: "ConsoleManager",
        Required: false,
        Mode: "direct",
        Add: 0,
        Patterns: []
    })

    db.Push({
        File: "GameEngineTick",
        Required: false,
        Mode: "direct",
        Add: 0,
        Patterns: []
    })

    ; Hook-specific Lua overrides recognized by UE4SS. Upstream documents these
    ; as rarely required and does not currently expose generalized PatternSleuth
    ; resolvers for them, so installed custom signatures are imported and
    ; revalidated when present rather than inventing weak signatures.
    db.Push({
        File: "ProcessLocalScriptFunction",
        Required: false,
        Mode: "direct",
        Add: 0,
        Patterns: []
    })

    db.Push({
        File: "ProcessInternal",
        Required: false,
        Mode: "direct",
        Add: 0,
        Patterns: []
    })

    db.Push({
        File: "CallFunctionByNameWithArguments",
        Required: false,
        Mode: "direct",
        Add: 0,
        Patterns: []
    })


    return db
}

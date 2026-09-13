UE4SS Signature Generator v0.38.0

Zero-setup hybrid UE4SS custom-signature generator for Win64 Unreal Engine games.

Launch:
  UE4SSSignatureGenerator.ahk

Requirements:
  AutoHotkey v2.0.19 when running the raw source.
  No Go, Rust, Python, disassembler, or other runtime needs to be installed.
  Engine preflight is offline and uses only local file/path metadata. SteamDB-derived
  detection rules are attributed in THIRD-PARTY-NOTICES.txt.

  Batch mode's Scan Steam Library action reads the locally registered Steam
  libraries and installed-app manifests, then queues only Win64 executables
  confirmed as Unreal by that same local detector. It does not send game files,
  Steam manifests, or account data to SteamDB or any other service.

  Install/Update UE4SS requires internet access to GitHub and uses the Windows
  PowerShell Expand-Archive command; scanning/generation itself remains local.

The application is still controlled entirely through the AHK front-end. A bundled
native ScannerCore.exe is used automatically for expensive binary-analysis work.
When the AHK front-end is compiled, FileInstall can embed ScannerCore.exe inside
the compiled application and extract it silently at runtime.





v0.37 full UE4SS custom-signature target coverage
--------------------------------------------------
- Expanded the resolver table from the original five targets to the full practical set of UE4SS Lua custom-signature overrides currently recognized/documented upstream: FName_Constructor, FName_ToString, StaticConstructObject, GMalloc, GUObjectArray, FText_Constructor, GUObjectHashTables, GNatives, ConsoleManager, GameEngineTick, ProcessLocalScriptFunction, ProcessInternal, and CallFunctionByNameWithArguments.
- Results now distinguish REQUIRED targets (FName_Constructor, StaticConstructObject, GMalloc, GUObjectArray) from OPTIONAL/feature-specific targets. FName_ToString and FText_Constructor are optional in current PatternSleuth, while the hook-specific Process* / CallFunction override files are documented as rarely required.
- Added current upstream PatternSleuth families for FText_Constructor, GUObjectHashTables, and GNatives, plus semantic string/XREF resolvers for ConsoleManager and GameEngineTick.
- Existing installed signatures are still imported and revalidated for every target. The rare ProcessLocalScriptFunction, ProcessInternal, and CallFunctionByNameWithArguments overrides are surfaced and imported, but are not fabricated when no safe generalized upstream resolver exists.
- Legacy FMemory_Free.lua is recognized as the historical alias for GMalloc.lua and is imported/revalidated as GMalloc. New generation always uses the modern GMalloc.lua filename.
- Scan reports and Batch status now show required/optional coverage independently, so a missing optional feature target does not masquerade as core UE4SS incompatibility.

v0.38 runtime-evidence recovery for rare hook overrides
--------------------------------------------------------
- ProcessLocalScriptFunction, ProcessInternal, and CallFunctionByNameWithArguments do not have a safe generalized static resolver in current upstream tooling. They are intentionally not guessed.
- If a nearby UE4SS runtime log explicitly records one of these resolved addresses, the generator treats that as a candidate identity proof only. It then rebuilds a target-entry AOB from the selected executable and requires the AOB to be unique before returning VERIFIED.
- This supports a real UE4SS-resolved address for the same binary without trusting a stale RVA. The runtime log must be at least as recent as the selected EXE, and changed binaries, missing logs, malformed log lines, and non-unique AOBs are withheld rather than generated.

v0.36 offline engine preflight
--------------------------------
- Before the UE4SS resolver set runs, the generator now classifies the selected game's engine from local filename/path/layout evidence. The method is inspired by SteamDB's open-source FileDetectionRuleSets but runs completely offline against the user's installed files.
- Confirmed Unreal Engine targets proceed normally. A confidently detected non-Unreal engine is named and requires Scan Anyway confirmation. Unknown or mixed cases also warn instead of being blocked, which keeps protected/custom Unreal games eligible for deeper analysis.
- Single mode displays the current engine classification beside the executable label. Batch mode adds an Engine column and presents one consolidated choice to scan flagged entries anyway, skip them, or cancel the batch.
- Engine evidence and any override are recorded in scan-report.txt. Engine detection is only a preflight advisory and never changes VERIFIED/STRONG/UNVERIFIED thresholds.
- Current positive alternative-engine fingerprints include Unity, Godot, CryEngine, Frostbite, GameMaker, Ren'Py, RPG Maker, RE Engine, Source/Source 2, MonoGame/FNA/XNA, id Tech, REDengine, GZDoom, Electron/NW.js, Defold, Construct, GDevelop, Love2D, OGRE, Unigine, X-Ray, Ubisoft Anvil, Snowdrop, Telltale Tool, Stride/Xenko, KiriKiri, TyranoBuilder, and Amazon Lumberyard.

v0.35 UE4SS install/update manager + direct signature deployment
------------------------------------------------------------------
- Single mode now includes Install UE4SS and Update UE4SS controls tied to the selected game executable.
- The installer fetches official RE-UE4SS release assets directly from GitHub at runtime and presents builds newest-first, with each normal User package immediately followed by its same-version Developer (zDEV) package. The rolling experimental-latest user/developer pair is included and labeled Experimental.
- The install/update dialog confirms the destination folder before downloading. The default is the selected game's executable directory, or the previously managed install location when one is known.
- The Update dialog also identifies the currently installed UE4SS version/build when possible. Managed installs know their exact selected asset; manual installs fall back to UE4SS.log (semantic version + Git SHA), official-release matching, and DLL version metadata.
- Update preserves UE4SS settings, UE4SS_Signatures content, and Mods state while updating release-owned files. When switching between classic and newer ue4ss-subfolder layouts, user state is migrated to the active layout. A recognized pre-3.0 -> 3.x transition backs up the old settings file and uses the newer settings format required by UE4SS.
- Generated signature Lua files now go directly into the UE4SS_Signatures directory used by the selected game's UE4SS installation. New-layout installs with a ue4ss subfolder are detected automatically.
- Generation no longer clears every .lua in the destination; only the exact signature files generated by the current scan are overwritten, so unrelated custom signatures are not destroyed.
- The old UE4SS_Signature_Output staging tree is no longer used. Scan reports remain in the configured centralized log location.


v0.33 offline runtime-dump fallback
------------------------------------
- Single mode now includes a Runtime Dump... button. Choose the normal game EXE first, then select a user-authorized process dump or mapped-image snapshot; the generator normalizes the selected executable module and runs the same full target set against those runtime bytes.
- Protected/opaque scans also offer the dump importer automatically when live PROCESS_VM_READ capture is unavailable. An explicitly selected dump skips the live-process read attempt for that scan.
- ScannerCore understands standard Windows MDMP files containing ModuleListStream plus MemoryListStream and/or Memory64ListStream. The selected EXE is matched by exact module path when available, with a unique-basename fallback when a dump omits/rewrites the full path.
- ScannerCore also accepts mapped PE snapshots laid out by virtual address. Ordinary on-disk PE files are rejected as mapped snapshots when their file size/layout cannot address SizeOfImage by RVA.
- Imported module memory is rebuilt into the same normalized PE form used by automatic runtime capture: section raw offsets become RVAs, missing regions remain zero-filled, executable coverage is measured, and incomplete executable coverage keeps the image conservatively flagged opaque/protected.
- Runtime-dump import is offline only. It never opens the game process and does not bypass protected-process or anti-cheat access controls. If a game or system policy prevents creating a dump through an ordinary authorized tool, the generator treats that as a boundary rather than attempting to defeat it.
- Scan reports identify imported-dump analysis separately from live runtime capture and record dump format, source path, mapped module base, image size, missing bytes, and missing executable bytes.


v0.32 cancellation + protected module discovery
-------------------------------------------------
- Scan and Scan Batch no longer perform the long scan inside their own button-event callback. The work is deferred to a one-shot timer, allowing a later click on the same control to enter the Cancel path while the scan is still running.
- Cancel immediately closes an active ScannerCore helper and invalidates partial results. Batch cancellation survives the hand-off between queued executables.
- Scan/Scan Batch action buttons dynamically resize for longer temporary labels such as Cancelling... and move neighboring controls with them, so native button text never wraps.
- Runtime capture first tries the normal Toolhelp module list. If only module enumeration is denied while the exact process has already granted read-only memory access, ScannerCore can recover the main image base from the process PEB and validate its PE headers before continuing.
- This is a discovery fallback only. It does not request write access, inject code, disable protections, or continue when normal PROCESS_VM_READ / PEB / mapped-header reads are blocked.


v0.31 automatic runtime-image fallback
----------------------------------------
- When the on-disk executable trips the conservative opaque/protected-image classifier, Single and Batch scans now automatically look for a running process whose full executable path matches the selected EXE.
- ScannerCore requests only normal read-only process rights (PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ). It does not inject code, write memory, suspend threads, disable protections, or bypass anti-cheat/protected-process policy.
- The running main module is captured section-by-section and normalized into a temporary PE snapshot whose raw offsets mirror mapped RVAs. The existing AHK/native resolver stack can therefore analyze runtime bytes without a second address model.
- The temporary snapshot is deleted after the scan. The selected game EXE and running process are never modified.
- If the protected game is not running, Single mode offers Retry after the user launches it normally. Batch mode only uses a runtime image when the exact target process is already running.
- Runtime captures are re-indexed through the same native static-family cache and then pass through the exact same resolver, uniqueness, corroboration, and confidence rules as ordinary disk images. No WuWa address or resolver result is hardcoded.
- Reports identify whether analysis used disk or runtime bytes, record PID/module base/image size/unreadable-page counts, and separately classify the runtime snapshot. Excessive unreadable executable pages keep the image flagged protected instead of letting zero-filled holes masquerade as clean code.



v0.29 outlined/LTO GUObjectArray + centralized reports
------------------------------------------------------
- Optimized UE4/UE5 builds can outline UObject diagnostic branches and access FUObjectArray fields directly from hot functions. ScannerCore now follows those semantic families back to their callers and reconstructs the struct base from a consistent multi-field layout rather than assuming the nearest LEA RCX is the global itself.
- Verification requires at least two independently identified UObject families to converge on the same aligned writable base, including the characteristic object-array field constellation. Internal locks such as a +0x30 synchronization member are treated as fields, not as GUObjectArray.
- This new resolver is conditional and runs only after the existing cheap pattern/stat-layout layers miss.
- Scan reports are now centralized under <Log destination>\log. Leaving Log destination blank uses the application's/script's own directory. Filenames include the game name and executable stem for easier regression-suite organization.
- Log destination is persistent across releases. Open Report in both Single and Batch follows the centralized report path.
- Open Folder beside Browse opens the directory containing the currently selected executable.

v0.28 StaticConstructObject XREF acceleration
----------------------------------------------
- Native StaticConstructObject semantic analysis now finds RIP-relative string XREFs with a cheap target-driven LEA pass instead of fully decoding every broad LEA-like byte sequence in large Shipping binaries.
- The scanner computes disp32 targets directly and only performs heavier function/call-graph work after a semantic anchor is actually referenced.
- This keeps the same NewObject / class-anchor / 0x10000080 RF-flags identity evidence and the same confidence policy while removing a pathological multi-minute preprocessing cost seen on very large executables.
- PAYDAY 3's native StaticConstructObject semantic pass dropped from roughly six minutes to about 1.24 seconds while resolving the same target.


v0.27 staged FName constructor corroboration
--------------------------------------------
- FName_Constructor can now verify staged wchar wrappers that first parse the incoming name into a temporary descriptor before calling the internal FName construction path.
- ScannerCore proves the parser is really consuming the original RDX as wchar_t through 16-bit loads, 2-byte stepping, and zero termination, including tiny leaf helpers with no .pdata entry.
- The outer wrapper must independently preserve this and EFindName, then restore exactly RCX=this and R8D=the incoming EFindName for a later construction call.
- Adjacent overloads that share the same wchar parser but route EFindName through a different slot are rejected. Existing compact-wrapper and T1 direct-prologue proofs remain unchanged.


v0.26 newer StaticConstructObject corroboration
---------------------------------------------
- StaticConstructObject can now promote a STRONG preselected target when ScannerCore independently proves the newer parameter-pack implementation.
- ScannerCore tracks decoded data flow from the incoming construction-parameter structure rather than trusting the candidate AOB.
- The proof requires Class(+0), Outer(+8), Name(+0x10), and ObjectFlags(+0x18), multiple additional pack fields, the 0x10000080 Native/Intrinsic EClassFlags test on the loaded UClass, and a reconstructed allocation-call ABI using those exact values.
- The proof is candidate-only. It cannot invent a target, and older direct-ABI SCO implementations continue using the existing deep semantic resolver.

v0.25 old/custom UE4 constructor corroboration
-----------------------------------------------
- FName_Constructor can now verify compact delegating constructor wrappers that do not match the modern full PatternSleuth wchar prologues.
- ScannerCore decodes the wrapper itself: preserves RCX as this, null-tests RDX, forwards incoming R8D/EFindName through the helper ABI, supplies constructor defaults, returns this, and handles null-name zeroing.
- It then follows the wrapper's decoded helper and requires real wchar_t behavior: propagated 16-bit name loads, 2-byte stepping, and zero-termination semantics.
- This deliberately distinguishes near-identical ANSI and wchar constructor wrappers without relying on game-specific RVAs or string literals.
- Existing T1 direct constructor fingerprints stay first priority. This deeper proof runs only when a STRONG/semantic constructor candidate still needs independent corroboration.

v0.24 old-engine semantic core
------------------------------
- Pre-4.23 FName::ToString no longer depends on one exact GNames getter byte layout. ScannerCore decodes the lazy old-GNames singleton behavior and follows its real callers.
- Candidate ToString functions are identified from old FName data flow: ComparisonIndex/Number, 0x3FFF chunk math, >>14 selection, indirect GNames entry lookup, FString output behavior, and numbered-name suffix formatting.
- GUObjectArray can be independently corroborated or discovered without diagnostic strings by finding the characteristic FUObjectArray constructor layout and deriving its singleton global from a decoded LEA RCX,&global -> CALL site.
- These paths are conditional fallbacks. Existing T1/T2/T3 fast paths are unchanged.

v0.22 workflow/testing features
-------------------------------
- Single and Batch tabs share the same resolver engine.
- Single mode has a persistent Recent dropdown containing the 20 most recently completed executable scans.
- On launch, Single automatically selects and fills the most recently completed valid scan target from Recent history.
- Recent history lives in %AppData%\UE4SSSignatureGenerator\settings.ini, so installing a newer release does not erase it.
- Batch mode accepts multiple EXEs, scans them sequentially, and shows a compact per-game result matrix.
- Selecting a Batch row populates a separate read-only 13-target details pane with each target's Required/Optional classification, status, tier, matches, RVA, resolver source, generated AOB, and confidence indicator.
- The Batch queue is persisted in the same AppData settings file, and Add Recent queues the saved recent-executable list in one click.
- Batch scans use the same centralized <Log destination>\log report folder as Single mode.
- Double-click a Batch row to send that executable to the Single tab.
- Batch mode does not overwrite the last Single scan's Generate state.

v0.22 legacy resolver addition
------------------------------
- Adds the historical PatternSleuth UEnum::SetEnums FName::ToString callsite family as a conditional old-engine fallback.

v0.15 SCO runtime-metadata fix:
  - Win64 RUNTIME_FUNCTION entries are discovered from IMAGE_DIRECTORY_ENTRY_EXCEPTION, the authoritative PE data directory, rather than assuming a literal .pdata section name
  - named .pdata parsing remains as a fallback
  - SCO diagnostics include the runtime metadata source/count

v0.14 fast/reuse paths:
  - sub-millisecond cached/native resolver timings display as <1ms
  - full direct FName constructor fingerprints explicitly lock to T1 instead of being reclassified from explanatory text
  - SCO NewObject consensus counts independent root evidence correctly and preserves a unique PatternSleuth-style support leader as STRONG when the stricter convergence threshold is not met
  - unique full PatternSleuth FName constructor prologues verify at T1 without the slow semantic XREF round-trip
  - full direct constructor fingerprints no longer require exact .pdata-start agreement; chained/overlapping unwind metadata cannot force an otherwise decisive fingerprint into T4
  - nearby prior PatternSleuth SCO results are revalidated against the current EXE before deep graph analysis
  - a unique RF-flags SCO body candidate is preserved as STRONG when semantic graph convergence is unavailable
  - shorter/legacy/inlined constructor candidates retain the deeper verification fallbacks

v0.11 native work:
  - batched static AOB scans
  - dynamically generated AOB uniqueness scans
  - .pdata runtime-function parsing for native semantic work
  - StaticConstructObject UTF-16/string anchor discovery
  - direct and indirect RIP-relative XREF discovery
  - CALL/JMP graph traversal and simple thunk following
  - 0x10000080 RF-flags candidate indexing
  - forward NewObject consensus and reverse call-graph evidence
  - chained Win64 unwind/.pdata canonicalization
  - reusable native RIP-relative LEA and CALL/JMP semantic indexes
  - last-resort-only historical log evidence (removed from the scan hot path)

AHK remains responsible for the UI, orchestration, confidence policy, report/Lua
generation, local signature corpus import, and compatibility fallbacks.

Scan never modifies the selected game executable.


Native Windows UI imagery
-------------------------
The release ships no UI image assets. Command buttons use semantic Windows stock
shell icons requested with SHGetStockIconInfo, and the four confidence dots are
generated in memory with Win32 GDI. This keeps the UI completely offline while
avoiding brittle hard-coded icon resource indexes and Windows color-emoji/font
extraction.


Analysis tiers
--------------
T1 - Direct fingerprint: a decisive unique full function fingerprint.
T2 - Known / corpus signature: an existing or bundled known-good signature was rescanned and reverified.
T3 - Structural / callsite: structural, callsite, addressing, or consensus evidence was required.
T4 - Semantic XREF: string/XREF semantic corroboration was required.
T5 - Deep call graph: deep call-graph/thunk/RF-flags style analysis was required.

The tier describes how deep the scanner had to dig, not a separate confidence grade.


v0.17.0 SCO/runtime-function fixes
----------------------------------
- The AHK PE layer now reads Win64 RUNTIME_FUNCTION metadata from IMAGE_DIRECTORY_ENTRY_EXCEPTION instead of requiring a section literally named .pdata.
- Chained unwind metadata is followed when resolving canonical root functions.
- Historical PatternSleuth SCO addresses can therefore be revalidated correctly on games whose runtime table is merged/renamed.
- Fixed a native SCO nil-index crash in the RF-flags-singleton fallback.
- Native SCO failure now fails fast instead of silently dropping into the multi-minute interpreted duplicate scan after ScannerCore already launched.


v0.18.0 SCO decoder/evidence fixes
----------------------------------
- ScannerCore now uses a real x86-64 instruction decoder for SCO LEA XREF, CALL/JMP, thunk, and RF-flags validation instead of treating raw E8/E9/48 8D bytes as instructions.
- Historical PatternSleuth SCO evidence is now searched target-first and stops after the first usable nearby hit.
- Historical SCO revalidation no longer rejects a known-good address solely because chained/unusual unwind metadata does not report that address as the canonical root start.
- Native SCO errors or failed post-validation never wake the old multi-minute interpreted duplicate pass.


v0.19.0 GUObjectArray structural fallback
------------------------------------------
- Adds PatternSleuth's inlined object-count stat resolver for GUObjectArray.
- Reconstructs the FUObjectArray base from three RIP-relative field operands and known UE field spacings.
- Generates a unique relocatable AOB with all three displacements wildcarded.
- Supports the layout whose smallest referenced field is FUObjectArray+0x8 using a signed resolver adjustment.
- The supplemental structural pattern is included in the initial ScannerCore batch so large executables do not require another full scan.


v0.21.0 legacy UE4 coverage
- Restores selected historical PatternSleuth FName::ToString callsite families for older/custom UE4 compilers.
- Adds independent UObjectBaseShutdown corroboration for semantic GUObjectArray candidates.


Protected / opaque Shipping images
----------------------------------
Some commercial Shipping executables keep ordinary Unreal strings visible on disk while the corresponding engine machine code is packed, encrypted, or virtualized. v0.30 added conservative detection of that condition. v0.31 turns the warning into an automatic fallback: if the exact selected EXE is already running, ScannerCore captures its mapped main module read-only and scans those runtime bytes instead.

If the game is not running, Single mode asks the user to launch it normally and Retry. If Windows or a protection/anti-cheat policy refuses ordinary read access, v0.33 can instead import a user-supplied Windows process dump or mapped-image snapshot. Use Runtime Dump... to select one explicitly, or accept the automatic dump-import prompt after live capture fails. The generator does not attempt to evade process protection or create the dump through restricted access itself.

Runtime-derived signatures, whether live-captured or imported from a dump, are still subject to the same VERIFIED / STRONG / UNVERIFIED evidence rules and AOB uniqueness checks. Partial dumps remain conservative: missing executable bytes are measured and can keep the normalized image classified opaque/protected.

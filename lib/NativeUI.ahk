; NativeUI.ahk
; Windows-native UI imagery for UE4SS Signature Generator.
; No external image assets are required. Button glyphs come from the Windows
; stock shell icon API and confidence dots are generated in memory with GDI.

; SHSTOCKICONID values used by this tool. These IDs are part of the Windows
; shell API rather than resource-number guesses into shell32.dll/imageres.dll.
global SIID_DOCASSOC := 1
global SIID_FOLDEROPEN := 4
global SIID_DRIVEFIXED := 8
global SIID_FIND := 22
global SIID_STACK := 55
global SIID_SETTINGS := 106
global SIID_DELETE := 84
global SIID_RECYCLER := 31

global NativeUIButtonImageLists := []

NativeUI_CreateStatusImageList() {
    ; ILC_MASK | ILC_COLOR32. ListView owns no source files; every dot is built
    ; as a native HICON and copied into this image list at startup.
    himl := DllCall("Comctl32.dll\ImageList_Create"
        , "Int", 16
        , "Int", 16
        , "UInt", 0x21
        , "Int", 4
        , "Int", 1
        , "Ptr")
    if !himl
        throw Error("Windows could not create the confidence-icon image list.")

    indices := Map()
    colors := Map(
        "GREEN",  0x2EA043,
        "YELLOW", 0xD29922,
        "GRAY",   0x828282,
        "RED",    0xCF222E
    )

    for name, rgb in colors {
        hIcon := NativeUI_CreateDotIcon(rgb, 16)
        if !hIcon
            continue
        idx := DllCall("Comctl32.dll\ImageList_ReplaceIcon"
            , "Ptr", himl
            , "Int", -1
            , "Ptr", hIcon
            , "Int")
        DllCall("User32.dll\DestroyIcon", "Ptr", hIcon)
        if idx >= 0
            indices[name] := idx + 1 ; ListView IconN is 1-based.
    }

    ; Keep the UI resilient if an unusually restricted Windows environment
    ; prevented one of the in-memory icons from being created.
    for _, name in ["GREEN", "YELLOW", "GRAY", "RED"] {
        if !indices.Has(name)
            indices[name] := 0
    }

    return Map("Handle", himl, "Indices", indices)
}

NativeUI_CreateDotIcon(rgb, size := 16) {
    ; 32-bit top-down DIB. DWORD pixels are 0xAARRGGBB, which becomes BGRA in
    ; little-endian memory as expected by a Windows 32-bpp DIB.
    bmi := Buffer(40, 0)
    NumPut("UInt", 40, bmi, 0)
    NumPut("Int", size, bmi, 4)
    NumPut("Int", -size, bmi, 8)
    NumPut("UShort", 1, bmi, 12)
    NumPut("UShort", 32, bmi, 14)
    NumPut("UInt", 0, bmi, 16) ; BI_RGB
    NumPut("UInt", size * size * 4, bmi, 20)

    hdc := DllCall("User32.dll\GetDC", "Ptr", 0, "Ptr")
    pBitsOut := Buffer(A_PtrSize, 0)
    hbmColor := DllCall("Gdi32.dll\CreateDIBSection"
        , "Ptr", hdc
        , "Ptr", bmi.Ptr
        , "UInt", 0 ; DIB_RGB_COLORS
        , "Ptr", pBitsOut.Ptr
        , "Ptr", 0
        , "UInt", 0
        , "Ptr")
    DllCall("User32.dll\ReleaseDC", "Ptr", 0, "Ptr", hdc)
    pBits := NumGet(pBitsOut, 0, "Ptr")
    if !hbmColor || !pBits
        return 0

    pixels := Buffer(size * size * 4, 0)
    ; A 1-bpp icon mask uses 1 for transparent and 0 for opaque. Sixteen pixels
    ; happen to be one WORD per scanline, which is already DWORD-compatible for
    ; CreateBitmap's monochrome source rows on current Windows builds.
    maskStride := ((size + 15) // 16) * 2
    mask := Buffer(maskStride * size, 0xFF)

    cx := (size - 1) / 2.0
    cy := (size - 1) / 2.0
    outerR2 := 5.75 * 5.75
    innerR2 := 5.00 * 5.00
    borderRgb := 0x3C3C3C

    r := (rgb >> 16) & 0xFF
    g := (rgb >> 8) & 0xFF
    b := rgb & 0xFF
    borderR := (borderRgb >> 16) & 0xFF
    borderG := (borderRgb >> 8) & 0xFF
    borderB := borderRgb & 0xFF

    Loop size {
        y := A_Index - 1
        Loop size {
            x := A_Index - 1
            dx := x - cx
            dy := y - cy
            d2 := dx * dx + dy * dy
            if d2 > outerR2
                continue

            if d2 <= innerR2 {
                pixel := (0xFF << 24) | (r << 16) | (g << 8) | b
            } else {
                pixel := (0xD2 << 24) | (borderR << 16) | (borderG << 8) | borderB
            }
            NumPut("UInt", pixel, pixels, (y * size + x) * 4)

            byteOffset := y * maskStride + (x // 8)
            bitIndex := 7 - Mod(x, 8)
            current := NumGet(mask, byteOffset, "UChar")
            NumPut("UChar", current & ~(1 << bitIndex), mask, byteOffset)
        }
    }

    DllCall("Ntdll.dll\RtlMoveMemory"
        , "Ptr", pBits
        , "Ptr", pixels.Ptr
        , "UPtr", pixels.Size)

    hbmMask := DllCall("Gdi32.dll\CreateBitmap"
        , "Int", size
        , "Int", size
        , "UInt", 1
        , "UInt", 1
        , "Ptr", mask.Ptr
        , "Ptr")
    if !hbmMask {
        DllCall("Gdi32.dll\DeleteObject", "Ptr", hbmColor)
        return 0
    }

    iiSize := (A_PtrSize = 8) ? 32 : 20
    hbmOffset := (A_PtrSize = 8) ? 16 : 12
    iconInfo := Buffer(iiSize, 0)
    NumPut("Int", 1, iconInfo, 0) ; fIcon
    NumPut("UInt", 0, iconInfo, 4)
    NumPut("UInt", 0, iconInfo, 8)
    NumPut("Ptr", hbmMask, iconInfo, hbmOffset)
    NumPut("Ptr", hbmColor, iconInfo, hbmOffset + A_PtrSize)

    hIcon := DllCall("User32.dll\CreateIconIndirect", "Ptr", iconInfo.Ptr, "Ptr")
    DllCall("Gdi32.dll\DeleteObject", "Ptr", hbmMask)
    DllCall("Gdi32.dll\DeleteObject", "Ptr", hbmColor)
    return hIcon
}

NativeUI_SetButtonStockIcon(buttonCtrl, stockId) {
    global NativeUIButtonImageLists
    if !IsObject(buttonCtrl) || !buttonCtrl.Hwnd
        return false

    hIcon := NativeUI_GetStockIcon(stockId, true)
    if !hIcon
        return false

    ; A BUTTON_IMAGELIST is the native themed-button path for showing an icon
    ; next to normal text. A one-image list is reused for every visual state.
    himl := DllCall("Comctl32.dll\ImageList_Create"
        , "Int", 16
        , "Int", 16
        , "UInt", 0x21 ; ILC_MASK | ILC_COLOR32
        , "Int", 1
        , "Int", 1
        , "Ptr")
    if !himl {
        DllCall("User32.dll\DestroyIcon", "Ptr", hIcon)
        return false
    }

    idx := DllCall("Comctl32.dll\ImageList_ReplaceIcon"
        , "Ptr", himl
        , "Int", -1
        , "Ptr", hIcon
        , "Int")
    DllCall("User32.dll\DestroyIcon", "Ptr", hIcon)
    if idx < 0 {
        DllCall("Comctl32.dll\ImageList_Destroy", "Ptr", himl)
        return false
    }

    bilSize := (A_PtrSize = 8) ? 32 : 24
    bil := Buffer(bilSize, 0)
    NumPut("Ptr", himl, bil, 0)
    marginOffset := A_PtrSize
    NumPut("Int", 4, bil, marginOffset + 0)  ; left
    NumPut("Int", 0, bil, marginOffset + 4)  ; top
    NumPut("Int", 6, bil, marginOffset + 8)  ; right
    NumPut("Int", 0, bil, marginOffset + 12) ; bottom
    NumPut("UInt", 0, bil, marginOffset + 16) ; BUTTON_IMAGELIST_ALIGN_LEFT

    ok := DllCall("User32.dll\SendMessageW"
        , "Ptr", buttonCtrl.Hwnd
        , "UInt", 0x1602 ; BCM_SETIMAGELIST
        , "Ptr", 0
        , "Ptr", bil.Ptr
        , "Ptr")
    if !ok {
        DllCall("Comctl32.dll\ImageList_Destroy", "Ptr", himl)
        return false
    }

    ; The button references the image list after this function returns, so keep
    ; the handle alive for the lifetime of the process.
    NativeUIButtonImageLists.Push(himl)
    return true
}

NativeUI_GetStockIcon(stockId, small := true) {
    ; SHGetStockIconInfo is preferable to hard-coded icon resource indexes. The
    ; semantic stock IDs are stable even when Microsoft reshuffles shell32 or
    ; imageres resources between Windows releases.
    siiSize := (A_PtrSize = 8) ? 544 : 536
    hIconOffset := (A_PtrSize = 8) ? 8 : 4
    sii := Buffer(siiSize, 0)
    NumPut("UInt", siiSize, sii, 0)

    flags := 0x100 ; SHGSI_ICON
    if small
        flags |= 0x1 ; SHGSI_SMALLICON
    else
        flags |= 0x0 ; SHGSI_LARGEICON

    hr := DllCall("Shell32.dll\SHGetStockIconInfo"
        , "Int", stockId
        , "UInt", flags
        , "Ptr", sii.Ptr
        , "Int")
    if hr != 0
        return 0
    return NumGet(sii, hIconOffset, "Ptr")
}


NativeUI_MeasureControlText(control, text) {
    if !IsObject(control) || !control.Hwnd
        return StrLen(text) * 8

    hdc := DllCall("User32.dll\GetDC", "Ptr", control.Hwnd, "Ptr")
    if !hdc
        return StrLen(text) * 8

    hFont := DllCall("User32.dll\SendMessageW"
        , "Ptr", control.Hwnd
        , "UInt", 0x0031 ; WM_GETFONT
        , "Ptr", 0
        , "Ptr", 0
        , "Ptr")
    oldFont := 0
    if hFont
        oldFont := DllCall("Gdi32.dll\SelectObject", "Ptr", hdc, "Ptr", hFont, "Ptr")

    size := Buffer(8, 0)
    ok := DllCall("Gdi32.dll\GetTextExtentPoint32W"
        , "Ptr", hdc
        , "Str", text
        , "Int", StrLen(text)
        , "Ptr", size.Ptr
        , "Int")

    if oldFont
        DllCall("Gdi32.dll\SelectObject", "Ptr", hdc, "Ptr", oldFont, "Ptr")
    DllCall("User32.dll\ReleaseDC", "Ptr", control.Hwnd, "Ptr", hdc)

    return ok ? NumGet(size, 0, "Int") : StrLen(text) * 8
}

NativeUI_SetButtonTextAutoWidth(buttonCtrl, text, baseText, baseWidth, followers := []) {
    ; Preserve the original button padding/icon allowance and only grow by the
    ; measured difference in label width. Controls to the right move by the same
    ; delta, so transient labels such as "Cancelling..." never wrap or overlap.
    if !IsObject(buttonCtrl)
        return

    buttonCtrl.GetPos(&x, &y, &oldWidth, &height)
    baseTextWidth := NativeUI_MeasureControlText(buttonCtrl, baseText)
    newTextWidth := NativeUI_MeasureControlText(buttonCtrl, text)
    newWidth := Max(baseWidth, Ceil(baseWidth + newTextWidth - baseTextWidth))
    delta := newWidth - oldWidth

    buttonCtrl.Text := text
    if delta = 0
        return

    buttonCtrl.Move(, , newWidth, height)
    for ctrl in followers {
        if !IsObject(ctrl)
            continue
        ctrl.GetPos(&fx, &fy, &fw, &fh)
        ctrl.Move(fx + delta, fy, fw, fh)
    }
}

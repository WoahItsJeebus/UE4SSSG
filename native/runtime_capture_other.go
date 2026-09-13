//go:build !windows

package main

func captureRuntimeImage(exePath, outPath, progressPath string, waitMs int) RuntimeCaptureResult {
	return RuntimeCaptureResult{SourceKind: "live", SourcePath: exePath, Format: "LIVE_PROCESS",
		Status: "UNSUPPORTED",
		Detail: "runtime process-image capture is available only in the Windows ScannerCore build",
	}
}

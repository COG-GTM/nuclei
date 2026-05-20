//go:build headless

package testheadless

import (
	"os/exec"
	"testing"
)

// TestHeadlessPlaceholder verifies that a Chrome/Chromium binary is available
// on the host. Real headless browser tests should be added to this package
// with the "headless" build tag.
//
// Requirements:
//   - Chrome or Chromium must be installed and available on PATH.
//   - Run via: make headless
func TestHeadlessPlaceholder(t *testing.T) {
	if _, err := exec.LookPath("google-chrome"); err != nil {
		if _, err := exec.LookPath("chromium"); err != nil {
			t.Skip("skipping headless tests: neither google-chrome nor chromium found on PATH")
		}
	}
	t.Log("Chrome/Chromium detected; headless test infrastructure is ready")
}

//go:build darwin && !cgo

package signing

import "fmt"

func createKeychainWithSecurityFramework(string, []byte) error {
	return fmt.Errorf("signing run requires a cgo-enabled macOS build")
}

func importPKCS12WithSecurityFramework(string, []byte, []byte) error {
	return fmt.Errorf("signing run requires a cgo-enabled macOS build")
}

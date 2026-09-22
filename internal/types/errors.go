package types

import "fmt"

// errf keeps validation messages consistent across this package.
func errf(format string, args ...any) error { return fmt.Errorf(format, args...) }

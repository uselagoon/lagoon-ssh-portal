package k8s

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation"
)

// ValidateLabelValue validates the given string to determine if it is a valid
// kubernetes label value.
func ValidateLabelValue(s string) error {
	errs := validation.IsValidLabelValue(s)
	if len(errs) > 0 {
		return fmt.Errorf("invalid label value: %v", errs)
	}
	return nil
}

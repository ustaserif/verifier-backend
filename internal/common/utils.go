package common

// ToPointer is a helper function to create a pointer to a value.
func ToPointer[T any](p T) *T {
	return &p
}

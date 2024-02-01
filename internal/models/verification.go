package models

// VerificationResponse is the struct for verification response
type VerificationResponse struct {
	Jwz     string
	UserDID string
	Scopes  []VerificationResponseScope
}

// VerificationResponseScope is the struct for verification response scope
type VerificationResponseScope struct {
	ID                 uint32
	NullifierSessionID string
	Nullifier          string
}

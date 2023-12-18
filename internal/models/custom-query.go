package models

// CustomQuery is the struct for custom query
type CustomQuery struct {
	Query     map[string]interface{} `json:"query"`
	CircuitID string                 `json:"circuitId"`
	RequestID int                    `json:"requestID"`
	To        string                 `json:"to,omitempty"`
}

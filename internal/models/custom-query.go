package models

type CustomQuery struct {
	Query     map[string]interface{} `json:"query"`
	CircuitID string                 `json:"circuitId"`
	RequestID int                    `json:"requestID"`
	To        string                 `json:"to,omitempty"`
}

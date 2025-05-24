package calltypes

// JSONResponse API response.
// @JSONResponse.
type JSONResponse struct {
	Error   bool        `json:"error"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// ErrorResponse represents standard error response.
// @ErrorResponse.
type ErrorResponse struct {
	Error   bool   `example:"true"              json:"error"`
	Message string `example:"Error description" json:"message"`
}

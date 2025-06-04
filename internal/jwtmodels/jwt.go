package jwtmodels

// FIXME: use proper golang-jwt package

type AzureJwt struct {
	Header     AzureJwtHeader
	Payload    Claims
	Signature  []byte
	RawToken   []byte
	RawPayload []byte
}

type AzureJwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

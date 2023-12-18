package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xPolygonID/verifier-backend/internal/common"
)

func TestSignIn(t *testing.T) {
	ctx := context.Background()
	server := New(cfg, keysLoader)

	type expected struct {
		httpCode int
		SignInResponseObject
	}

	type bodyType struct {
		CallbackUrl *string  `json:"callbackUrl,omitempty"`
		Reason      *string  `json:"reason,omitempty"`
		Scope       *[]Scope `json:"scope,omitempty"`
	}

	type testConfig struct {
		name     string
		body     SignInRequestObject
		expected expected
	}

	for _, tc := range []testConfig{
		{
			name: "valid request for credentialAtomicQuerySigV2 circuit with KYCAgeCredential",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					Network:   "mumbai",
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						}
					  }`),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				SignInResponseObject: SignIn200JSONResponse{
					QrCode: QRCode{
						Body: bodyType{
							Scope: &[]Scope{
								{
									CircuitId: "credentialAtomicQuerySigV2",
									Id:        1,
									Query: map[string]interface{}{
										"allowedIssuers": []interface{}{"*"},
										"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
										"credentialSubject": map[string]interface{}{
											"birthday": map[string]interface{}{
												"$eq": float64(19960424),
											},
										},
										"type": "KYCAgeCredential",
									},
								},
							},
						},
						From: cfg.MumbaiSenderDID,
						To:   nil,
						Typ:  "application/iden3comm-plain-json",
						Type: "https://iden3-communication.io/authorization/1.0/request",
					},
				},
			},
		},
		{
			name: "valid request for credentialAtomicQuerySigV2 circuit with KYCAgeCredential and to field",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					Network:   "mumbai",
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						}
					  }`),
					To: common.ToPointer("did:polygonid:polygon:mumbai:2qEATqfECVbCBzq9EhJpPSiv1xtJRpbMBKDaNM68Ci"),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				SignInResponseObject: SignIn200JSONResponse{
					QrCode: QRCode{
						Body: bodyType{
							Scope: &[]Scope{
								{
									CircuitId: "credentialAtomicQuerySigV2",
									Id:        1,
									Query: map[string]interface{}{
										"allowedIssuers": []interface{}{"*"},
										"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
										"credentialSubject": map[string]interface{}{
											"birthday": map[string]interface{}{
												"$eq": float64(19960424),
											},
										},
										"type": "KYCAgeCredential",
									},
								},
							},
						},
						From: cfg.MumbaiSenderDID,
						To:   common.ToPointer("did:polygonid:polygon:mumbai:2qEATqfECVbCBzq9EhJpPSiv1xtJRpbMBKDaNM68Ci"),
						Typ:  "application/iden3comm-plain-json",
						Type: "https://iden3-communication.io/authorization/1.0/request",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := server.SignIn(ctx, tc.body)
			require.NoError(t, err)
			switch tc.expected.httpCode {
			case http.StatusOK:
				var response SignIn200JSONResponse
				response = rr.(SignIn200JSONResponse)
				expected := tc.expected.SignInResponseObject.(SignIn200JSONResponse)
				require.Equal(t, expected.QrCode.Body.Scope, response.QrCode.Body.Scope)
				assert.True(t, isValidCallBack(t, response.QrCode.Body.CallbackUrl))
				assert.Equal(t, expected.QrCode.From, response.QrCode.From)
				assert.Equal(t, expected.QrCode.Typ, response.QrCode.Typ)
				assert.Equal(t, expected.QrCode.Type, response.QrCode.Type)
				assert.Equal(t, expected.QrCode.To, response.QrCode.To)
			default:
				t.Errorf("unexpected http code: %d", tc.expected.httpCode)
			}
		})
	}

}

func isValidCallBack(t *testing.T, url *string) bool {
	callBackURL := *url
	items := strings.Split(callBackURL, "?")
	if len(items) != 2 {
		return false
	}
	if items[0] != cfg.Host+"/callback" {
		return false
	}

	queryItems := strings.Split(items[1], "=")
	if len(queryItems) != 2 {
		return false
	}
	n, err := strconv.Atoi(queryItems[1])
	require.NoError(t, err)
	assert.True(t, n > 0)
	return true
}

func jsonToMap(t *testing.T, jsonStr string) map[string]interface{} {
	result := make(map[string]interface{})
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &result))
	return result
}

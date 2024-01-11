# Verifier Backend
[![Checks](https://github.com/0xPolygonID/verifier-backend/actions/workflows/checks.yml/badge.svg)](https://github.com/0xPolygonID/verifier-backend/actions/workflows/checks.yml)
[![golangci-lint](https://github.com/0xPolygonID/verifier-backend/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/0xPolygonID/verifier-backend/actions/workflows/golangci-lint.yml)

### Requirements:
1. Create a file named `.env` in the root directory of the project. .env-example is provided as an example.
2. Create a file named `resolvers_settings.yaml` in the root directory of the project. resolvers_settings_sample.yaml is provided as an example.

### Some useful commands:

```shell
make run      # run the server
make stop     # stop the server
make restart  # stop and remove the container, build the image and run the container
```

### Cache expiration
The default cache expiration is 1 hour. This can be changed by setting the environment variable `VERIFIER_BACKEND_CACHE_EXPIRATION` to the desired value.
For instance, to set the cache expiration to 30 minutes, you can run the following command:
```shell
VERIFIER_BACKEND_CACHE_EXPIRATION=30m
```


#### /sign-in body example:

```json
{
  "chainID": "80001",
  "circuitID": "credentialAtomicQuerySigV2",
  "skipClaimRevocationCheck": false, 
  "query": {
    "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
    "allowedIssuers": ["*"],
    "type": "KYCAgeCredential",
    "credentialSubject": {
        "birthday": {
            "$eq": 19960424
        }
    }
  }
}
```

#### /sign-in payload response sample:

```json
{
    "qrCode": {
        "body": {
            "callbackUrl": "https://my-verifier-host/verifier/callback?sessionID=63622",
            "reason": "test flow",
            "scope": [
                {
                    "circuitId": "credentialAtomicQuerySigV2",
                    "id": 1,
                    "query": {
                        "allowedIssuers": ["*"],
                        "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
                        "credentialSubject": {
                            "birthday": {
                                "$eq": 19960424
                            }
                        },
                        "type": "KYCAgeCredential"
                    }
                }
            ]
        },
        "from": "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
        "id": "7f38a193-0918-4a48-9fac-36adfdb8b542",
        "thid": "7f38a193-0918-4a48-9fac-36adfdb8b542",
        "typ": "application/iden3comm-plain-json",
        "type": "https://iden3-communication.io/authorization/1.0/request"
    },
    "sessionID": 63622
}
```
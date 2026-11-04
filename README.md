[![CI](https://github.com/dadrus/httpsig/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dadrus/httpsig/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/dadrus/httpsig/branch/main/graph/badge.svg)](https://codecov.io/gh/dadrus/httpsig)
[![Go Reference](https://pkg.go.dev/badge/github.com/dadrus/httpsig.svg)](https://pkg.go.dev/github.com/dadrus/httpsig)

## Introduction and Scope

`httpsig` is a library that facilitates the signing and verification of HTTP requests in compliance with the [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) standard.

Its `Message` abstraction allows integration with different HTTP frameworks.

## Usage

### Standalone Signing and Verification

To sign an HTTP request, first, create a `Signer` instance using your preferred key and signing algorithm:

```go
// Create a signer.
signer, err := httpsig.NewSigner( 
    // specify a key
    httpsig.Key{Material: privKey, Algorithm: httpsig.EcdsaP256Sha256}, 
    // the keyid parameter for the above key
    httpsig.WithKeyID("key1"),
    // specify the required options 
    // duration for which the signature should be valid
    httpsig.WithTTL(5 * time.Second), 
    // which components should be protected by a signature 
    httpsig.WithComponents("@authority", "@method", "x-my-fancy-header"), 
    // a tag for your specific application
    httpsig.WithTag("myapp"),
)
// error handling goes here

// Create a request
req, err := http.NewRequestWithContext(context.Background(), "GET", "https://some-url.com", nil)
// error handling goes here

// Sign the request
header, err := signer.Sign(
    httpsig.MessageFromRequest(req), 
    // add a nonce if required
    httpsig.WithParameter("nonce", someNonce)
)
// error handling goes here

// Add the signature to the request
req.Header = header
```

To verify a response, create a `Verifier` using your preferred key and signing algorithm:

```go
// Receive a response from the server
resp, err := client.Post("https://some-url.com", "application/json", &buf)
// error handling

// Create a verifier
verifier, err := httpsig.NewVerifier(
    // specify a key resolver to resolve the key used by the client
    keyResolver,
    // specify the required options
    // which response components are expected to be protected
    httpsig.WithComponents("@status", "content-type"),
    // validity time skew
    httpsig.WithValidityTolerance(5 * time.Second),
    // how old a signature is allowed to be
    httpsig.WithMaxAge(30 * time.Second),
    // whether to validate all signatures present in the message
    httpsig.WithValidateAllSignatures(),
)
// error handling

// Verify the response. No partial result is returned on failure.
verified, err := verifier.Verify(httpsig.MessageFromResponse(resp))
// Each entry in verified contains the covered components, transmitted
// signature parameters, and any metadata returned by the key resolver.

// error handling

```

Once `Verify` succeeds, the application can inspect the `verified` object and perform its own policies, like e.g., the nonce correlation and replay checks.

If you need to validate a signature created by a specific application (identified by a tag), use the `WithRequiredTag` option when creating the verifier. This option allows you to specify a tag along with the same options as the `NewVerifier` function. Here’s an example:

```go
verifier, err := httpsig.NewVerifier(
    // specify a key resolver to resolve the key used by the client
    keyResolver,
    // specify the required options
    httpsig.WithRequiredTag(
        // tag of the signature
        "myapp",
        // which components are expected to be protected by a signature
        httpsig.WithComponents("@authority", "@method", "x-my-fancy-header"),
        // validity time skew
        httpsig.WithValidityTolerance(5 * time.Second),
        // how old a signature is allowed to be
        httpsig.WithMaxAge(30 * time.Second),
    ), 
)
// error handling goes here

verified, err := verifier.Verify(msg)
// error handling goes here
```

Global verifier options act as defaults for all required tags. Explicit tag-specific options take precedence (for example, a tag's `WithComponents` replaces the global component list), while required, forbidden, and expected signature parameters are additive. Automatic signature negotiation reflects the effective requirements for each tag.

While the examples demonstrate signing a request and verifying a response, you can also verify requests and sign responses. Both the `Verifier.Verify()` and `Signer.Sign()` methods require a `Message` object, which can be created for requests and responses on both client and server sides using the following functions:

* `MessageFromRequest` - creates a `Message` from an `http.Request`. Can be used for outbound (client-side) and inbound (server-side) requests.
* `MessageFromResponse` - creates a `Message` from an `http.Response`. Can be used for inbound (client-side) responses from a server.
* `MessageForResponse` - creates a Message from an outbound (server-side) response.

For middleware integration, see [HTTP Frameworks](#http-frameworks).

Both the `Signer` and `Verifier` respect the `"content-digest"` component identifier as highlighted in the [Security Considerations](https://www.rfc-editor.org/rfc/rfc9421.html#name-message-content) of the RFC. This is handled as follows:

* On the `Signer` side, if `"content-digest"` is configured to be included via the `WithComponents` option and the `WithContentDigestAlgorithm` option is not used, the implementation will calculate a message digest over the body using the `sha-256` and `sha-512` algorithms (the only supported algorithms according to [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)). It will then create or replace the `"Content-Digest"` header with the calculated values in addition to the signature-related headers. If the `WithContentDigestAlgorithm` option is used, the message digest will be calculated using the specified algorithm and the `"Content-Digest"` header will be created or replaced with that value.

* On the `Verifier` side, verification of the corresponding hash values is done by default with no additional configuration required. If the `"Signature-Input"` header value contains a `"content-digest"` component, the implementation expects the `"Content-Digest"` header to be present and uses the supplied algorithm names and values to calculate the digest over the body and compare these values to the received ones. If the `"Content-Digest"` header is missing, references unsupported hash algorithms (only `sha-256` and `sha-512` are supported), or there is a mismatch between the calculated and provided values, the message verification will fail with an error.

> [!IMPORTANT]
> Signing or verifying `"content-digest"` requires reading the message body. Since request and response bodies may be attacker-controlled input, callers are responsible for enforcing appropriate body size limits before passing messages to this library.
>
> For server-side request handling, consider using `http.MaxBytesReader`; for other contexts, use `io.LimitedReader` or an equivalent mechanism. The library restores the body after reading it, so it can still be consumed by subsequent handlers, but it does not impose global body size limits on behalf of the application.

### Key Resolution

A `Verifier` uses a `KeyResolver` to select the key for each signature. `ResolveKey` receives `SignatureInfo` before cryptographic verification, so its parameters, components, and message are still unverified.

```go
type trustedKeys map[string]httpsig.Key

func (keys trustedKeys) ResolveKey(_ context.Context, info httpsig.SignatureInfo) (httpsig.KeyInfo, error) {
    keyID, ok := info.Parameters.KeyID()
    if !ok {
        return httpsig.KeyInfo{}, errors.New("missing keyid")
    }

    key, ok := keys[keyID]
    if !ok {
        return httpsig.KeyInfo{}, errors.New("unknown key")
    }

    return httpsig.KeyInfo{Key: key}, nil
}
```

This example looks up a previously trusted key by `keyid`. A fixed `httpsig.Key` can also serve directly as a `KeyResolver`. `KeyInfo` can carry optional application-specific `Metadata`.

### Identity

After `Verify` succeeds, `VerifiedSignature` provides the verified signature parameters and covered component values. The application uses these values according to its protocol to establish a principal and make authorization decisions. Signature labels are not signed and must not be used as identities.

### Signature Negotiation

The library not only supports signing and verifying HTTP messages but also facilitates signature negotiation, as defined in the [RFC 9421 HTTP Message Signatures - Requesting Signatures](https://www.rfc-editor.org/rfc/rfc9421.html#name-requesting-signatures), by utilizing the `"Accept-Signature"` header.

> [!NOTE]  
> While [Chapter 5.2 - Processing an Accept-Signature](https://www.rfc-editor.org/rfc/rfc9421.html#name-processing-an-accept-signat) of the RFC mandates that 
> 
> > ... a target message MUST have the same label ...
> 
> this requirement conflicts with [Chapter 7.2.5 - Signature Labels](https://www.rfc-editor.org/rfc/rfc9421.html#name-signature-labels), which clearly states:
> 
> > An intermediary is allowed to relabel an existing signature when processing the message.
> > Therefore, applications **should not** rely on specific labels being present, and applications **should not** put semantic meaning on the labels themselves. Instead, additional signature parameters can be used to convey whatever additional meaning is required to be attached to, and covered by, the signature. In particular, the `tag` parameter can be used to define an application-specific value.
> 
> As a result, the current implementation does not enforce label consistency, even though you can specify them. The only reliable method to ensure effective signature negotiation is by utilizing the `tag` parameter, as also recommended in the statement above.

#### Requesting Signatures on the Client-Side from the Server

On the client side, you can request the server to sign the response by using the `AcceptSignatureBuilder`. This builder can be created with the `NewAcceptSignature` function, which accepts several options to specify parameters and components that you want the server to include in the response. Here’s an example:

```go
// create a builder (all options are optional)
builder, err := httpsig.NewAcceptSignature(
    // request a key ID and signing algorithm
    httpsig.WithKeyID("foo"),
    // specify which signature algorithm the peer should use
    httpsig.WithSignatureAlgorithm(httpsig.EcdsaP256Sha256),
    // specify which label should the server use when creating the response 
    httpsig.WithLabel("bar"),
    // specify which components should be covered by the signature 
    httpsig.WithComponents("@status", "content-digest;req", "content-digest"),
    // specify your content digest algorithm references 
    httpsig.WithContentDigestAlgorithmPreferences(httpsig.AlgorithmPreference{Algorithm: httpsig.Sha256, Preference: 2}),
    // specify which tag the server should use 
    httpsig.WithTag("awesome-app"),
    // specify whether you want the created time stamp to be included 
    httpsig.WithCreatedTimestamp(true),
    // specify whether you want the expires time stamp to be included 
    httpsig.WithExpiresTimestamp(true),
)
// error handling goes here

req := ... // create your request
nonce := ... // application-generated nonce for this request

err = builder.Build(req.Context(), req.Header, httpsig.WithParameter("nonce", nonce))
// error handling goes here
```

When the above code executes, it will add an `"Accept-Signature"` header to the request with a value like: `bar=("@status", "content-digest";req, "content-digest");keyid="foo";alg="ecdsa-p256-sha256";nonce="...";tag="awesome-app";created;expires`.

#### Requesting Signatures on the Server-Side from the Client

Signature negotiation on the server side works differently from the client-side. Instead of using the `AcceptSignatureBuilder`, you specify the corresponding options when creating the `Verifier`. This ensures that there are no discrepancies between what the `Verifier` expects and what is included in the `"Accept-Signature"` response header if an expected signature is not present or required parameters/components are missing. Here’s an example, building on the earlier `Verifier` creation example:

```go
verifier, err := httpsig.NewVerifier(
    // specify a key resolver
    keyResolver,
    // specify the required options
    httpsig.WithRequiredTag(
        // tag of the signature
        "myapp",
        // which components are expected to be protected by a signature
        httpsig.WithComponents("@authority", "@method", "x-my-fancy-header"),
        // validity time skew
        httpsig.WithValidityTolerance(5 * time.Second),
        // how old a signature is allowed to be
        httpsig.WithMaxAge(30 * time.Second),
        // if there is no signature tagged "myapp", or some of the required components or parameters
        // are not present, request a signature from the client
        httpsig.WithSignatureNegotiation(
            // request a key ID and signature algorithm
            httpsig.WithKeyID("key1"),
            // request a signature algorithm the peer should use
            httpsig.WithSignatureAlgorithm(httpsig.EcdsaP256Sha256),
            // specify the source for the nonce
            httpsig.WithNonceGetter(nonceGetter),
            // specify the label for the signature
            httpsig.WithLabel("bar"),
        ),
    ),
)
// error handling goes here

_, err = verifier.Verify(msg)

var missingSigErr *httpsig.NoApplicableSignatureError
if errors.As(err, &missingSigErr) {
    // if this error is returned, call Negotiate to update the http headers with the 
    // Accept-Signature header
    missingSigErr.Negotiate(resp.Header)
}
// further error handling
```

For automatic negotiation, the configured `NonceGetter` runs while `Verify` prepares the `Accept-Signature` headers, before `NoApplicableSignatureError` is returned.

> [!NOTE]  
> The `WithSignatureNegotiation` option at the top level (outside the `WithRequiredTag` option) is mutually exclusive with the `WithValidateAllSignatures` option. However, you can still use `WithSignatureNegotiation` at the top level if you want to apply the same configuration for all expected tagged signatures, thereby simplifying your code.

### Reusing Signers and Verifiers

A `Signer` or `Verifier` represents a reusable signing or verification policy. Create an instance once per policy and reuse it across messages. This allows most of the configuration work to happen upfront, keeping the per-message overhead low. Message-specific values can be supplied through per-call options.

## Protocols and Profiles

### WIMSE Workload-to-Workload HTTP Signatures

The [WIMSE HTTP Signatures draft](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-http-signature-08) binds signed requests to Workload Identity Tokens (WITs). For an ordinary request carrying a `Workload-Identity-Token` header:

```go
// Sender
signer, err := httpsig.NewSigner(
    httpsig.Key{Material: privateKey, Algorithm: httpsig.Ed25519},
    httpsig.WithTag("wimse-workload-to-workload"),
    httpsig.WithComponents("@method", "@path", "@query", "workload-identity-token"),
)

req.Header, err = signer.Sign(httpsig.MessageFromRequest(req),
    httpsig.WithParameter(httpsig.Nonce, nonce),
    httpsig.WithParameter("wimse-aud", audience),
)

// Recipient
verifier, err := httpsig.NewVerifier(witKeyResolver,
    httpsig.WithRequiredTag("wimse-workload-to-workload",
        httpsig.WithComponents("@method", "@path", "@query", "workload-identity-token"),
        httpsig.WithRequiredParameters(httpsig.Nonce),
        httpsig.WithForbiddenParameters(httpsig.KeyID, httpsig.Alg),
        httpsig.WithParameter("wimse-aud", expectedAudience),
    ),
)

result, err = verifier.Verify(httpsig.MessageFromRequest(req))
```

Include `content-digest` for requests with a body and cover any other headers required by the draft when present. The application validates the WIT and enforces replay rules.

### Web Bot Auth

The [Web Bot Auth draft](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-01) uses a signed `Signature-Agent` dictionary member to advertise the signer's key directory.

```go
// Sender: the dictionary member matches the signature label.
req.Header.Set("Signature-Agent", `sig1="https://agent.example/keys.jwks"`)
signer, err := httpsig.NewSigner(
    httpsig.Key{Material: privateKey, Algorithm: httpsig.Ed25519},
    httpsig.WithLabel("sig1"),
    httpsig.WithTag("web-bot-auth"),
    httpsig.WithKeyID(jwkThumbprint),
    httpsig.WithComponents("@authority", `signature-agent;key="sig1"`),
)

req.Header, err = signer.Sign(httpsig.MessageFromRequest(req))

// Recipient
verifier, err := httpsig.NewVerifier(webBotKeyResolver,
    httpsig.WithRequiredTag("web-bot-auth",
        httpsig.WithComponents("@authority"),
        httpsig.WithRequiredParameters(httpsig.KeyID),
    ),
)

verified, err := verifier.Verify(httpsig.MessageFromRequest(req))
```

`webBotKeyResolver` resolves keys from `Signature-Agent` and validates their thumbprints. 

### AAuth

The [AAuth Protocol draft](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-11) authenticates agents using HTTP Message Signatures and a signed `Signature-Key` header containing key information.

```go
// Agent
req.Header.Set("Signature-Key", `sig=jwt;jwt="`+agentToken+`"`)
signer, err := httpsig.NewSigner(
    httpsig.Key{Material: privateKey, Algorithm: httpsig.Ed25519},
    httpsig.WithLabel("sig"),
    httpsig.WithTTL(0),
    httpsig.WithComponents("@method", "@authority", "@path", "signature-key"),
)
req.Header, err = signer.Sign(httpsig.MessageFromRequest(req))

// Resource server
verifier, err := httpsig.NewVerifier(aauthKeyResolver,
    httpsig.WithValidateAllSignatures(),
    httpsig.WithComponents("@method", "@authority", "@path", "signature-key"),
    httpsig.WithExpiresTimestamp(false),
    httpsig.WithMaxAge(time.Minute),
)
_, err = verifier.Verify(httpsig.MessageFromRequest(req))
```

`aauthKeyResolver` validates the agent token and resolves its signing key via `Signature-Key`. For requests with bodies to person or access servers and revocation endpoints, also cover `content-digest` and `content-type`.

### OAuth Proof-of-Possession Tokens

The [OAuth HTTP Signature PoP draft](https://datatracker.ietf.org/doc/html/draft-richer-oauth-httpsig-03) binds access tokens to signing keys. For a resource request carrying an `Authorization` header:

```go
// Client
signer, err := httpsig.NewSigner(
    httpsig.Key{Material: privateKey, Algorithm: httpsig.Ed25519},
    httpsig.WithTag("httpsig-oauth"),
    httpsig.WithTTL(0),
    httpsig.WithComponents("@method", "@target-uri", "authorization"),
)

req.Header, err = signer.Sign(httpsig.MessageFromRequest(req),
    httpsig.WithParameter(httpsig.Nonce, nonce),
)

// Resource server
verifier, err := httpsig.NewVerifier(tokenBoundKeyResolver,
    httpsig.WithRequiredTag("httpsig-oauth",
        httpsig.WithComponents("@method", "@target-uri", "authorization"),
        httpsig.WithExpiresTimestamp(false),
        httpsig.WithRequiredParameters(httpsig.Nonce),
        httpsig.WithForbiddenParameters(httpsig.KeyID, httpsig.Alg, "pub"),
    ),
)

_, err = verifier.Verify(httpsig.MessageFromRequest(req))
```

The resource server validates the access token, supplies its bound key through `KeyResolver`, and checks nonce reuse. For requests with bodies, also cover `content-digest`.

## HTTP Frameworks

The examples below verify incoming requests. The same signing, verification, and signature negotiation APIs can be used in client middleware and for responses as well.

**net/http**

```go
http.Handle("/api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // Retain Verify's result if a principal is needed for the next handler.
    if _, err := verifier.Verify(httpsig.MessageFromRequest(r)); err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)

        return
    }

    handler.ServeHTTP(w, r)
}))
```

**Gin**

```go
router.Use(func(c *gin.Context) {
    // Retain Verify's result if a principal is needed downstream.
    if _, err := verifier.Verify(httpsig.MessageFromRequest(c.Request)); err != nil {
        c.AbortWithStatus(http.StatusUnauthorized)

        return
    }

    c.Next()
})
```

**Fiber v3 (`fasthttp`)**

```go
app.Use(func(c fiber.Ctx) error {
    req, err := adaptor.ConvertRequest(c, true)
    if err != nil {
        return err
    }

    // Retain Verify's result if a principal is needed downstream.
    if _, err := verifier.Verify(httpsig.MessageFromRequest(req)); err != nil {
        return c.SendStatus(fiber.StatusUnauthorized)
    }

    return c.Next()
})
```

## Security Considerations

* **Coverage:** Require the components your application relies on. For messages with bodies, sign and verify `content-digest` when body integrity matters.
* **Key trust:** `KeyResolver` receives unverified message data. Select and validate keys according to the application protocol; never treat a reported key ID as proof of identity.
* **Replay:** Enforce the required freshness and nonce checks after successful signature verification.
* **Multiple signatures:** Labels are not signed, and `VerificationResult` has no defined order. Choose the required tags or validate all signatures as appropriate.
* **HTTP intermediaries:** Proxies can rewrite covered components. Apply the body-size limits described above before hashing untrusted content.

See [RFC 9421 Security Considerations](https://www.rfc-editor.org/rfc/rfc9421.html#section-7).

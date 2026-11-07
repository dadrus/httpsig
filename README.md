[![CI](https://github.com/dadrus/httpsig/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dadrus/httpsig/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/dadrus/httpsig/branch/main/graph/badge.svg)](https://codecov.io/gh/dadrus/httpsig)
[![Go Reference](https://pkg.go.dev/badge/github.com/dadrus/httpsig.svg)](https://pkg.go.dev/github.com/dadrus/httpsig)

## Introduction and Scope

`httpsig` is a library for signing and verifying HTTP requests and responses according to [RFC 9421 (HTTP Message Signatures)](https://www.rfc-editor.org/rfc/rfc9421.html). In addition to the Structured Fields types defined by [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html?utm_source=chatgpt.com), it also supports the `Date` and `Display String` types introduced by [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html?utm_source=chatgpt.com).

Its key features include:

- **Policy-based signing and verification:** Reusable policies for covered components, signature parameters, tags, and validity constraints.
- **Message integrity:** Automatic generation and verification of `Content-Digest` to protect HTTP message bodies.
- **Signature negotiation:** Support for requesting signatures via `Accept-Signature` and deriving signature requirements from verification policies.
- **Framework independence:** A `Message` abstraction that enables integration with `net/http`, Fiber, other HTTP frameworks, and proxy-based services.
- **Cryptographic agility:** Support for custom signing and verification implementations, allowing applications to use cryptographic algorithms and key management systems (HSMs and KMSs) independently of the library's built-in support (see [Cryptographic Agility](#cryptographic-agility)).

For API details and option semantics, see the [Go reference](https://pkg.go.dev/github.com/dadrus/httpsig). For known limitations and the current scope of RFC 9421 support, see [Limitations and Compliance](#limitations-and-compliance).

## Usage

### Standalone Signing and Verification

The following snippets show two independent flows: signing an outgoing request and verifying a received response. They assume application-provided keys and other values; routine error handling is abbreviated.

To sign a request, configure a `Signer` with the signing key and the HTTP components to protect:

```go
// Configure the signing policy.
signer, err := httpsig.NewSigner(
    // specify a key
    httpsig.Key{Material: privKey, Algorithm: httpsig.EcdsaP256Sha256},
    // the keyid parameter for the above key
    httpsig.WithKeyID("key1"),
    // specify the required options 
    // duration for which the signature should be valid
    httpsig.WithTTL(5 * time.Second),
    // which components should be protected by a signature 
    httpsig.WithComponents(`"@authority"`, `"@method"`, `"x-my-fancy-header"`),
    // a tag for your specific application
    httpsig.WithTag("myapp"),
    // custom parameter
    httpsig.WithParameter("first", "value 1"),
    // custom parameter
    httpsig.WithParameter("second", httpsig.DisplayString("öäü")),
    // custom parameter
    httpsig.WithParameter("third", httpsig.Date(time.Now())),
)
// error handling goes here

// Create a request
req, err := http.NewRequestWithContext(context.Background(), "GET", "https://some-url.com", nil)
// error handling goes here
req.Header.Set("X-My-Fancy-Header", "example-value")

nonce := ... // generate a nonce

// Sign the request
header, err := signer.Sign(
    httpsig.MessageFromRequest(req),
    // add a nonce if required
    httpsig.WithParameter(httpsig.Nonce, nonce),
)
// error handling goes here

// MessageFromRequest clones the headers; use the headers returned by Sign.
req.Header = header
// send the request
```

To verify a response, create a `Verifier` with a `KeyResolver` that supplies trusted verification keys (see [Key Resolution](#key-resolution)). `WithValidateAllSignatures` checks every signature present in the message; use `WithRequiredTag` instead when your protocol expects particular signed tags.

```go
// Receive a response from the server
resp, err := client.Post("https://some-url.com", "application/json", &buf)
// error handling

// Create a verifier
verifier, err := httpsig.NewVerifier(
    // specify a key resolver to resolve the key
    keyResolver,
    // specify the required options
    // which response components are expected to be protected
    httpsig.WithComponents(`"@status"`, `"content-type"`),
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

Once `Verify` succeeds, your application can inspect the `verified` object and enforce protocol-specific rules, such as nonce correlation, replay protection, and authorization.

If a protocol requires a signature with a particular `tag`, use `WithRequiredTag`. Unlike `WithValidateAllSignatures`, tag-based verification selects signatures carrying the required tag; unrelated signatures are not verified unless all-signature verification is also enabled. For example:

```go
verifier, err := httpsig.NewVerifier(
    // specify a key resolver to resolve the key used by the client
    keyResolver,
    // specify the required options
    httpsig.WithRequiredTag(
        // tag of the signature
        "myapp",
        // which components are expected to be protected by a signature
        httpsig.WithComponents(`"@authority"`, `"@method"`, `"x-my-fancy-header"`),
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

Global verifier options act as defaults for required tags. Tag-specific options take precedence (for example, `WithComponents` replaces the global component list), while required, forbidden, and expected signature-parameter constraints are additive. Automatic signature negotiation uses these effective per-tag requirements.

The same APIs also verify incoming requests and sign outgoing responses. Both `Signer.Sign` and `Verifier.Verify` operate on a `Message`, created for the corresponding HTTP direction:

* `MessageFromRequest` — outbound client requests or inbound server requests.
* `MessageFromResponse` — responses received by clients.
* `MessageForResponse` — responses produced by servers.

For middleware integration, see [HTTP Frameworks](#http-frameworks).

To protect a message body, include `"content-digest"` among the covered components (see [RFC 9421's discussion of message content](https://www.rfc-editor.org/rfc/rfc9421.html#name-message-content)):

* **Signing:** The `Signer` calculates the digest and creates or replaces `Content-Digest` before signing. By default, it uses both `sha-256` and `sha-512` (as defined in [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)); `WithContentDigestAlgorithm` selects a single algorithm.
* **Verification:** If the signature covers `content-digest`, the `Verifier` also checks the digest against the body. Verification fails if the header is missing, no supported digest is present, or any supported digest mismatches. Only `sha-256` and `sha-512` are checked.

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

Signature negotiation uses the `Accept-Signature` header defined in [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html#name-requesting-signatures). A client can explicitly request a signed response; a server can derive a request for missing client signatures from its verification policy.

> [!NOTE]
> [RFC 9421 §5.2](https://www.rfc-editor.org/rfc/rfc9421.html#name-processing-an-accept-signat) requires a negotiated signature to use the requested label, but [§7.2.5](https://www.rfc-editor.org/rfc/rfc9421.html#name-signature-labels) permits intermediaries to relabel signatures and warns against assigning labels application semantics. `httpsig` therefore does not enforce label consistency. Use the signed `tag` parameter to identify application-specific signatures instead.

#### Requesting Signatures on the Client-Side from the Server

Use `AcceptSignatureBuilder` when a client needs to request a signed response. It constructs the `Accept-Signature` header independently of any verifier policy, so the client can specify the components and parameters it expects the server to sign:

```go
// create a builder (all options are optional)
builder, err := httpsig.NewAcceptSignature(
    // request a key identifier and signing algorithm
    httpsig.WithKeyID("foo"),
    // specify which signature algorithm the peer should use
    httpsig.WithSignatureAlgorithm(httpsig.EcdsaP256Sha256),
    // request the label and covered components
    httpsig.WithLabel("bar"),
    // specify which components should be covered by the signature 
    httpsig.WithComponents(`"@status"`, `"content-digest";req`, `"content-digest"`),
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

// send the request
```

This adds an `Accept-Signature` header with a value such as:

```http
Accept-Signature: bar=("@status" "content-digest";req "content-digest");created;expires;keyid="foo";alg="ecdsa-p256-sha256";nonce="...";tag="awesome-app"
Want-Content-Digest: sha-256=2
```

The `Want-Content-Digest` header is also added because the requested signature covers `content-digest`.

#### Fulfilling a Signature Request

Use `ParseAcceptSignature` when a peer requests a signature, for example in a `401` response to your request. It takes an `http.Header`, so it works independently of signers and verifiers, and returns one `SignatureRequest` per requested signature:

```go
requests, err := httpsig.ParseAcceptSignature(resp.Header)
// err reports the members that can't be used; requests holds the usable ones

msg := httpsig.MessageFromRequest(req)

for _, request := range requests {
    // decide whether the request is acceptable for your application

    signer, err := httpsig.NewSigner(
        key,
        httpsig.WithLabel(request.Label),
        httpsig.WithComponents(request.Components...),
        httpsig.WithTag(request.Tag),
    )
    // error handling goes here

    var opts []httpsig.SignOption
    if request.Nonce != "" {
        opts = append(opts, httpsig.WithParameter("nonce", request.Nonce))
    }

    _, err := signer.Sign(msg, opts...)
    // error handling goes here

    // ...
}

req.Header = msg.Header

// send the request
```

`Created` and `Expires` report whether these parameters are requested, as `Accept-Signature` carries no timestamp values. A `Signer` always includes `created`; use `WithTTL` to include `expires`. Parameters not defined by RFC 9421 are available in `Extensions`. If the field as a whole isn't valid Structured Fields, no requests are returned. A malformed member or one with an unsupported component identifier doesn't affect the other members: the usable requests are returned together with a joined error that wraps `ErrMalformedData` for each unusable member. Require `err == nil` if your application must fulfill every request.

#### Requesting Signatures on the Server-Side from the Client

On the server side, the `Verifier` can derive `Accept-Signature` requirements from its configured policy. This avoids defining component and parameter requirements separately for verification and negotiation. If a required signature, component, or parameter is missing, `Verify` returns an error wrapping `NoApplicableSignatureError`; use `errors.As` to retrieve it and call `Negotiate` to add the prepared headers to the response. An invalid cryptographic signature is still a verification failure, not a negotiation request.

For example, extending the earlier tag-based verifier:

```go
verifier, err := httpsig.NewVerifier(
    // specify a key resolver
    keyResolver,
    // specify the required options
    httpsig.WithRequiredTag(
        // tag of the signature
        "myapp",
        // which components are expected to be protected by a signature
        httpsig.WithComponents(`"@authority"`, `"@method"`, `"x-my-fancy-header"`),
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

## Cryptographic Agility

`httpsig` supports custom signing and verification implementations through the `MessageSigner` and `MessageVerifier` interfaces. This allows applications to use cryptographic algorithms (e.g., PQC) and key management systems (HSMs and KMSs) independently of the library's built-in support.

The library constructs the [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) signature base and passes it unchanged to the application-provided implementation, which is responsible for the entire cryptographic operation, including hashing and signature encoding.

### ML-DSA

The following example demonstrates how to use ML-DSA, available in the Go standard library since Go 1.27, without requiring `httpsig` itself to target that Go version.

First, define adapters for signing and verification:

```go
type mlDSASigner mldsa.PrivateKey

func (s *mlDSASigner) SignMessage(_ context.Context, message []byte) ([]byte, error) {
    return (*mldsa.PrivateKey)(s).Sign(nil, message, &mldsa.Options{})
}

type mlDSAVerifier mldsa.PublicKey

func (v *mlDSAVerifier) VerifyMessage(_ context.Context, message, signature []byte) error {
    return mldsa.Verify((*mldsa.PublicKey)(v), message, signature, &mldsa.Options{})
}
```

These adapters can then be used directly with the existing signing and verification APIs:

```go
// Generate an ML-DSA key pair.
privateKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
// error handling

// Create a signer.
signer, err := httpsig.NewSigner(
    httpsig.Key{
        Material:  (*mlDSASigner)(privateKey),
        Algorithm: "ml-dsa-44",
    },
    httpsig.WithKeyID("demo-ml-dsa-44"),
    httpsig.WithAlg(),
    httpsig.WithComponents(`"@method"`, `"@path"`),
)
// error handling

req, err := ... // create the request

// Sign the request.
req.Header, err = signer.Sign(httpsig.MessageFromRequest(req))
// error handling

// Create a verifier.
verifier, err := httpsig.NewVerifier(
    httpsig.Key{
        Material:  (*mlDSAVerifier)(privateKey.PublicKey()),
        Algorithm: "ml-dsa-44",
    },
    httpsig.WithValidateAllSignatures(),
    httpsig.WithComponents(`"@method"`, `"@path"`),
)
// error handling

// Verify the request.
result, err := verifier.Verify(httpsig.MessageFromRequest(req))
// error handling
```

### AWS KMS

The same approach works with external key management systems such as AWS KMS. The application-provided adapter handles the KMS interaction and any required cryptographic processing.

For example, an ECDSA signer backed by AWS KMS could look like this:

```go
type awsMessageSigner struct {
    client *kms.Client
    keyID  string
}

func (s awsMessageSigner) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
    digest := sha256.Sum256(message)

    response, err := s.client.Sign(ctx, &kms.SignInput{
        KeyId:            &s.keyID,
        Message:          digest[:],
        MessageType:      types.MessageTypeDigest,
        SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
    })
    if err != nil {
        return nil, err
    }

    // Convert the ASN.1 DER-encoded ECDSA signature returned by AWS KMS to r || s.
    return ecdsaSignatureToRaw(response.Signature)
}
```

The adapter can then be passed to `httpsig` like any other signing key:

```go
client := ... // create the AWS KMS client
keyID := ...  // obtain the key ID

signer, err := httpsig.NewSigner(
    httpsig.Key{
        Material:  awsMessageSigner{client: client, keyID: keyID},
        Algorithm: httpsig.EcdsaP256Sha256,
    },
    httpsig.WithKeyID(keyID),
    httpsig.WithComponents(`"@method"`, `"@path"`),
)
// error handling

req, err := ... // create the request

req.Header, err = signer.Sign(httpsig.MessageFromRequest(req))
// error handling
```

## Protocols and Profiles

### WIMSE Workload-to-Workload HTTP Signatures

The [WIMSE HTTP Signatures draft](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-http-signature-08) binds signed requests to Workload Identity Tokens (WITs). For an ordinary request carrying a `Workload-Identity-Token` header:

```go
// Sender
signer, err := httpsig.NewSigner(
    httpsig.Key{Material: privateKey, Algorithm: httpsig.Ed25519},
    httpsig.WithTag("wimse-workload-to-workload"),
    httpsig.WithComponents(`"@method"`, `"@path"`, `"@query"`, `"workload-identity-token"`),
)

req.Header, err = signer.Sign(httpsig.MessageFromRequest(req),
    httpsig.WithParameter(httpsig.Nonce, nonce),
    httpsig.WithParameter("wimse-aud", audience),
)

// Recipient
verifier, err := httpsig.NewVerifier(witKeyResolver,
    httpsig.WithRequiredTag("wimse-workload-to-workload",
        httpsig.WithComponents(`"@method"`, `"@path"`, `"@query"`, `"workload-identity-token"`),
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
    httpsig.WithComponents(`"@authority"`, `"signature-agent";key="sig1"`),
)

req.Header, err = signer.Sign(httpsig.MessageFromRequest(req))

// Recipient: resolve the covered Signature-Agent member dynamically.
verifier, err := httpsig.NewVerifier(webBotKeyResolver,
    httpsig.WithRequiredTag("web-bot-auth",
        httpsig.WithComponents(`"@authority"`, `"signature-agent";key="sig1"`),
        httpsig.WithRequiredParameters(httpsig.KeyID),
    ),
)

verified, err := verifier.Verify(httpsig.MessageFromRequest(req))
```

`webBotKeyResolver` implementation needs to resolve the signing key using the `Signature-Agent` member covered by the signature.

### AAuth

The [AAuth Protocol draft](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-11) authenticates agents using HTTP Message Signatures and a signed `Signature-Key` header containing key information.

```go
// Agent
req.Header.Set("Signature-Key", `sig=jwt;jwt="`+agentToken+`"`)
signer, err := httpsig.NewSigner(
    httpsig.Key{Material: privateKey, Algorithm: httpsig.Ed25519},
    httpsig.WithLabel("sig"),
    httpsig.WithTTL(0),
    httpsig.WithComponents(`"@method"`, `"@authority"`, `"@path"`, `"signature-key"`),
)
req.Header, err = signer.Sign(httpsig.MessageFromRequest(req))

// Resource server
verifier, err := httpsig.NewVerifier(aauthKeyResolver,
    httpsig.WithValidateAllSignatures(),
    httpsig.WithComponents(`"@method"`, `"@authority"`, `"@path"`, `"signature-key"`),
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
    httpsig.WithComponents(`"@method"`, `"@target-uri"`, `"authorization"`),
)

req.Header, err = signer.Sign(httpsig.MessageFromRequest(req),
    httpsig.WithParameter(httpsig.Nonce, nonce),
)

// Resource server
verifier, err := httpsig.NewVerifier(tokenBoundKeyResolver,
    httpsig.WithRequiredTag("httpsig-oauth",
        httpsig.WithComponents(`"@method"`, `"@target-uri"`, `"authorization"`),
        httpsig.WithExpiresTimestamp(false),
        httpsig.WithRequiredParameters(httpsig.Nonce),
        httpsig.WithForbiddenParameters(httpsig.KeyID, httpsig.Alg, "pub"),
    ),
)

_, err = verifier.Verify(httpsig.MessageFromRequest(req))
```

The resource server validates the access token, supplies its bound key through `KeyResolver`, and checks nonce reuse. For requests with bodies, also cover `content-digest`. When verifying `@target-uri` on incoming requests, use the externally visible absolute URL, reconstructed from trusted server or proxy configuration.

## HTTP Frameworks

The examples below verify incoming requests. The same signing, verification, and signature negotiation APIs can be used in client middleware and for responses as well.

**net/http**

```go
http.Handle("/api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    result, err := verifier.Verify(httpsig.MessageFromRequest(r))
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)

        return
    }

    // establish a principal from the result object
    // and propagate it downstream

    handler.ServeHTTP(w, r)
}))
```

**Gin**

```go
router.Use(func(c *gin.Context) {
    result, err := verifier.Verify(httpsig.MessageFromRequest(c.Request))
    if err != nil {
        c.AbortWithStatus(http.StatusUnauthorized)

        return
    }

    // establish a principal from the result object
    // and propagate it downstream

    c.Next()
})
```

**Fiber v3 (`fasthttp`)**

```go
app.Use(func(c fiber.Ctx) error {
    targetURL, err := url.Parse(c.FullURL())
    if err != nil {
        return err
    }

    headers := make(http.Header)
    for name, values := range c.GetReqHeaders() {
        for _, value := range values {
            headers.Add(name, value)
        }
    }

    msg := &httpsig.Message{
        Context:   c.Context(),
        Method:    c.Method(),
        Authority: c.Host(),
        URL:       targetURL,
        Header:    headers,
        Body: func() (io.ReadCloser, error) {
            return io.NopCloser(bytes.NewReader(c.BodyRaw())), nil
        },
        IsRequest: true,
    }

    result, err := verifier.Verify(msg)
    if err != nil {
        return c.SendStatus(fiber.StatusUnauthorized)
    }

    // establish a principal from the result object
    // and propagate it downstream

    return c.Next()
})
```

## Security Considerations

* **Coverage:** Require the components your application relies on. For messages with bodies, sign and verify `content-digest` when body integrity matters.
* **Key trust:** `KeyResolver` receives unverified message data. Select and validate keys according to your application protocol.
* **Signature requests:** `Accept-Signature` is controlled by the peer. Check the components, key, and parameters of a `SignatureRequest` before signing, so a peer cannot obtain signatures your application did not intend to produce.
* **Replay:** Enforce the required nonce checks after successful signature verification.
* **Multiple signatures:** Labels are not signed, and `VerificationResult` has no defined order. Choose the required tags or validate all signatures as appropriate.

See also [RFC 9421 Security Considerations](https://www.rfc-editor.org/rfc/rfc9421.html#section-7).

## Limitations and Compliance

### RFC 9421 Compliance

Following are the known limitations and deviations:

- **HTTP trailers:** The `;tr` component identifier parameter is not supported. `Signature` and `Signature-Input` fields cannot be processed as trailers.
- **Query parameter parsing:** `@query-param` uses Go's `url.URL.Query()` to parse form parameters. Its handling of malformed percent escapes, raw semicolons, and invalid UTF-8 differs from WHATWG form parsing. For ambiguous or repeated parameters, cover the entire query with `@query` instead. The `@query-param` component uses `%20` for spaces, following the RFC 9421 examples and other HMS implementations.

### Other Limitations

- **Body streaming:** `Content-Digest` generation and verification currently require buffering the complete message body in memory. Streaming digest calculation is not yet supported.
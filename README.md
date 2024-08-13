## Introduction

`httpsig` is a library that facilitates the signing and verification of HTTP requests in compliance with the [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) standard.

## Standalone Signing and Verification

To sign an HTTP request, first, create a `Signer` instance using your preferred key and signing algorithm:

```go
// Create a signer.
signer, err := httpsig.NewSigner( 
    // specify a key
    httpsig.Key{KeyID: "key1", Key: privKey, Algorithm: httpsig.EcdsaP256Sha256}, 
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
header, err := signer.Sign(httpsig.MessageFromRequest(req))
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
    // to detect and mitigate replay attacks
    httpsig.WithNonceChecker(nonceChecker),
    // which components are expected to be protected by a signature
    httpsig.WithRequiredComponents("@authority", "@method", "x-my-fancy-header"),
    // validity time skew
    httpsig.WithValidityTolerance(5 * time.Second),
    // how old a signature is allowed to be
    httpsig.WithMaxAge(30 * time.Second),
    // whether to validate all signatures present in the message
    httpsig.WithValidateAllSignatures(),
)
// error handling

// Verify the response
err := verifier.Verify(httpsig.MessageFromResponse(resp))
// error handling

```

If you need to validate a signature created by a specific application (identified by a tag), use the `WithRequiredTag` option when creating the verifier. This option allows you to specify a tag along with the same options as the `NewVerifier` function. Here’s an example:

```go
verifier, err := httpsig.NewVerifier(
    // specify a key resolver to resolve the key used by the client
    keyResolver,
    // specify the required options
    // to detect and mitigate replay attacks
    httpsig.WithNonceChecker(nonceChecker), 
    httpsig.WithRequiredTag(
        // tag of the signature
        "myapp",
        // which components are expected to be protected by a signature
        httpsig.WithRequiredComponents("@authority", "@method", "x-my-fancy-header"),
        // validity time skew
        httpsig.WithValidityTolerance(5 * time.Second),
        // how old a signature is allowed to be
        httpsig.WithMaxAge(30 * time.Second),
    ), 
)
// error handling goes here

err = verifier.Verify(msg)
// error handling goes here
```

While the examples demonstrate signing a request and verifying a response, you can also verify requests and sign responses. Both the `Verifier.Verify()` and `Signer.Sign()` methods require a `Message` object, which can be created for requests and responses on both client and server sides using the following functions:

* `MessageFromRequest` - creates a `Message` from an `http.Request`. Can be used for outbound (client-side) and inbound (server-side) requests.
* `MessageFromResponse` - creates a `Message` from an `http.Response`. Can be used for inbound (client-side) responses from a server.
* `MessageForResponse` - creates a Message from an outbound (server-side) response.

Both the `Signer` and `Verifier` respect the `"content-digest"` component identifier as highlighted in the [Security Considerations](https://www.rfc-editor.org/rfc/rfc9421.html#name-message-content) of the RFC. This is handled as follows:

* On the `Signer` side, if the `"content-digest"` is configured to be included via the `WithComponents` option and the `WithContentDigestAlgorithm` option is not used, the implementation will calculate a message digest over the body using the `sha-256` and `sha-512` algorithms (the only supported algorithms according to [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)). It will then create the `"Content-Digest"` header with the calculated values in addition to the signature-related headers. If the `WithContentDigestAlgorithm` option is used, the message digest will be calculated using the specified algorithm.
* On the `Verifier` side, verification of the corresponding hash values is done by default with no additional configuration required. If the `"Signature-Input"` header value contains a `"content-digest"` component, the implementation expects the `"Content-Digest"` header to be present and uses the supplied algorithm names and values to calculate the digest over the body and compare these value to the received ones. If the `"Content-Digest"` header is missing, references unsupported hash algorithms (only `sha-256` and `sha-512` are supported), or there is a mismatch between the calculated and provided values, the message verification will fail with an error.

## Signature Negotiation

The library not only supports signing and verifying HTTP messages but also facilitates signature negotiation, as defined in the [RFC 9421 HTTP Message Signatures - Requesting Signatures](https://www.rfc-editor.org/rfc/rfc9421.html#name-requesting-signatures), by utilizing the `"Accept-Signature"` header.

> [!IMPORTANT]  
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

### Requesting Signatures on the Client-Side from the Server

On the client side, you can request the server to sign the response by using the `AcceptSignatureBuilder`. This builder can be created with the `NewAcceptSignature` function, which accepts several options to specify parameters and components that you want the server to include in the response. Here’s an example:

```go
// create a builder (all options are optional)
builder, err := httpsig.NewAcceptSignature(
    // specify which key and key algorithm the server should use for signing the response
    httpsig.WithExpectedKey(Key{KeyID: "foo", Algorithm: httpsig.EcdsaP256Sha256}), 
    // specify the NonceSource for the nonce to be added 
    httpsig.WithExpectedNonce(nonceSource),
    // specify which label should the server use when creating the response 
    httpsig.WithExpectedLabel("bar"),
    // specify which components should be covered by the signature 
    httpsig.WithExpectedComponents("@status", "content-digest;req", "content-digest"),
    // specify your content digest algorithm references 
    httpsig.WithContentDigestAlgorithmPreferences(httpsig.AlgorithmPreference{Algorithm: httpsig.Sha256, Preference: 2}),
    // specify which tag the server should use 
    httpsig.WithExpectedTag("awesome-app"),
    // specify whether you want the created time stamp to be included 
    httpsig.WithExpectedCreatedTimestamp(true),
    // specify whether you want the expires time stamp to be included 
    httpsig.WithExpectedExpiresTimestamp(true),
)
// error handling goes here

req := ... // create your request

err = builder.Build(req.Context(), req.Header)
// error handling goes here
```

When the above code executes, it will add an `"Accept-Signature"` header to the request with a value like: `bar=("@status", "content-digest";req, "content-digest");keyid="foo";alg="ecdsa-p256-sha256";nonce="...";tag="awesome-app";created;expires`.

### Requesting Signatures on the Server-Side from the Client

Signature negotiation on the server side works differently from the client-side. Instead of using the `AcceptSignatureBuilder`, you specify the corresponding options when creating the `Verifier`. This ensures that there are no discrepancies between what the `Verifier` expects and what is included in the `"Accept-Signature"` response header if an expected signature is not present or required parameters/components are missing. Here’s an example, building on the earlier `Verifier` creation example:

```go
verifier, err := httpsig.NewVerifier(
    // specify a key resolver
    keyResolver,
    // specify the required options
    // to detect and mitigate replay attacks
    httpsig.WithNonceChecker(nonceChecker),
    httpsig.WithRequiredTag(
        // tag of the signature
        "myapp",
        // which components are expected to be protected by a signature
        httpsig.WithRequiredComponents("@authority", "@method", "x-my-fancy-header"),
        // validity time skew
        httpsig.WithValidityTolerance(5 * time.Second),
        // how old a signature is allowed to be
        httpsig.WithMaxAge(30 * time.Second),
        // if there is no signature tagged "myapp", or some of the required components or parameters
        // are not present, request a signature from the client
        httpsig.WithSignatureNegotiation(
            // specify which key and algorithm the client should use
            httpsig.WithRequestedKey(httpsig.Key{KeyID: "key1", Algorithm: httpsig.EcdsaP256Sha256}),
            // specify the source for the nonce, the client should use
            httpsig.WithRequestedNonce(nonceGetter),
            // specify the label for the signature, the client should use
            httpsig.WithRequestedLabel("bar"),
        ),
    ),
)
// error handling goes here

err = verifier.Verify(msg)

var missingSigErr *httpsig.NoApplicableSignatureError
if errors.As(err, &missingSigErr) {
    // if this error is returned, call Negotiate to update the http headers with the 
    // Accept-Signature header
    missingSigErr.Negotiate(resp.Header)
}
// further error handling
```

> [!IMPORTANT]  
> The `WithSignatureNegotiation` option at the top level (outside the `WithRequiredTag` option) is mutually exclusive with the `WithValidateAllSignatures` option. However, you can still use `WithSignatureNegotiation` at the top level if you want to apply the same configuration for all expected tagged signatures, thereby simplifying your code.

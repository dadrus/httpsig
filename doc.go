// Package httpsig implements HTTP Message Signatures as specified by RFC 9421.
// It provides signing, verification, and Accept-Signature negotiation for HTTP
// requests and responses independently of a particular HTTP framework.
//
// Convert net/http messages with MessageFromRequest, MessageFromResponse, or
// MessageForResponse, then use a Signer or Verifier. Verification returns a
// VerificationResult containing the covered components, transmitted signature
// parameters, and optional key-resolution metadata for each verified signature.
//
// A KeyResolver is responsible for selecting trusted verification keys. It
// receives sender-controlled information before the cryptographic signature
// has been verified. Applications are responsible for applying profile-specific
// trust, identity, and authorization rules to the results; verifying a signature
// alone does not establish the sender's identity or permissions.
//
// Signing and digest verification may read complete message bodies. Applications
// must enforce appropriate body size limits before passing untrusted messages
// to the library.
package httpsig

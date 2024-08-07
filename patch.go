package httpsig

import "time"

// replaced in tests to have the behavior required to use/verify
// vectors data provided in RFC9421
//
//nolint:gochecknoglobals
var (
	currentTime     = time.Now
	filterAlgorithm = func(alg SignatureAlgorithm) SignatureAlgorithm { return alg }
)

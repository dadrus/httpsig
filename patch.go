package httpsig

import "time"

// replaced in tests to use the timestamps from the RFC 9421 test vectors.
//
//nolint:gochecknoglobals
var currentTime = time.Now

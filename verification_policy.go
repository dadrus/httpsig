package httpsig

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

type verificationPolicy struct {
	tolerance           *time.Duration
	maxAge              time.Duration
	identifiers         []*componentIdentifier
	asb                 *AcceptSignatureBuilder
	reqCreatedTS        *bool
	reqExpiresTS        *bool
	requiredParameters  []SignatureParameter
	forbiddenParameters []SignatureParameter
	expectedParameters  []parameterOption
}

// clone copies the parameter slices for per-call options. Other fields are
// shared because VerifyOption does not modify them.
func (e *verificationPolicy) clone() *verificationPolicy {
	clone := *e
	clone.requiredParameters = slices.Clone(e.requiredParameters)
	clone.forbiddenParameters = slices.Clone(e.forbiddenParameters)
	clone.expectedParameters = slices.Clone(e.expectedParameters)

	return &clone
}

// withOptions applies per-call options without changing the configured policy.
func (e *verificationPolicy) withOptions(tag string, opts []VerifyOption) (*verificationPolicy, error) {
	if len(opts) == 0 {
		return e, nil
	}

	effective := e.clone()
	for _, opt := range opts {
		if err := opt.applyVerifyOption(effective); err != nil {
			return nil, err
		}
	}

	if err := effective.validateParameters(tag); err != nil {
		return nil, err
	}

	return effective, nil
}

// inherit applies global requirements to a tag-specific configuration.
// Tag-specific values take precedence, while parameter requirements remain additive.
func (e *verificationPolicy) inherit(globalPolicy *verificationPolicy, tag string) error {
	if e.tolerance == nil {
		e.tolerance = globalPolicy.tolerance
	}

	if e.maxAge == -1 {
		e.maxAge = globalPolicy.maxAge
	}

	if len(globalPolicy.identifiers) != 0 && len(e.identifiers) == 0 {
		e.identifiers = globalPolicy.identifiers
	}

	if e.reqExpiresTS == nil {
		e.reqExpiresTS = globalPolicy.reqExpiresTS
	}

	if e.reqCreatedTS == nil {
		e.reqCreatedTS = globalPolicy.reqCreatedTS
	}

	if globalPolicy.asb != nil && e.asb == nil {
		// Keep negotiation configuration independent for each required tag.
		tmp := *globalPolicy.asb
		e.asb = &tmp
	}

	if err := e.inheritParameters(globalPolicy); err != nil {
		return err
	}

	return e.prepare(tag)
}

func (e *verificationPolicy) prepare(tag string) error {
	if err := e.validateParameters(tag); err != nil {
		return err
	}

	if e.asb != nil {
		e.asb.setIdentifiers(e.identifiers)
		e.asb.tag = tag
		e.asb.addCreatedTS = *e.reqCreatedTS
		e.asb.addExpiresTS = *e.reqExpiresTS
	}

	return nil
}

func (e *verificationPolicy) inheritParameters(globalPolicy *verificationPolicy) error {
	for _, name := range globalPolicy.requiredParameters {
		if err := e.requireParameter(name); err != nil {
			return err
		}
	}

	for _, name := range globalPolicy.forbiddenParameters {
		if err := e.forbidParameter(name); err != nil {
			return err
		}
	}

	for _, param := range globalPolicy.expectedParameters {
		if err := e.expectParameter(param); err != nil {
			return err
		}
	}

	return nil
}

func (e *verificationPolicy) addRequiredParameter(name SignatureParameter) error {
	if err := validateParameter(name, true); err != nil {
		return err
	}

	return e.requireParameter(name)
}

func (e *verificationPolicy) requireParameter(name SignatureParameter) error {
	if slices.Contains(e.forbiddenParameters, name) {
		return fmt.Errorf("%w: required parameter %q is forbidden", ErrParameter, name)
	}

	if !slices.Contains(e.requiredParameters, name) {
		e.requiredParameters = append(e.requiredParameters, name)
	}

	return nil
}

func (e *verificationPolicy) addForbiddenParameter(name SignatureParameter) error {
	if err := validateParameter(name, true); err != nil {
		return err
	}

	return e.forbidParameter(name)
}

func (e *verificationPolicy) forbidParameter(name SignatureParameter) error {
	if slices.Contains(e.requiredParameters, name) {
		return fmt.Errorf("%w: required parameter %q is forbidden", ErrParameter, name)
	}

	for _, param := range e.expectedParameters {
		if param.name == name {
			return fmt.Errorf("%w: expected parameter %q is forbidden", ErrParameter, name)
		}
	}

	if !slices.Contains(e.forbiddenParameters, name) {
		e.forbiddenParameters = append(e.forbiddenParameters, name)
	}

	return nil
}

func (e *verificationPolicy) addExpectedParameter(option parameterOption) error {
	if slices.Contains(e.forbiddenParameters, option.name) {
		return fmt.Errorf("%w: expected parameter %q is forbidden", ErrParameter, option.name)
	}

	if option.name == Nonce {
		if _, err := validateNonceOption(option.value); err != nil {
			return err
		}
	} else {
		var err error

		option, err = normalizeParameter(option)
		if err != nil {
			return err
		}
	}

	// Structured Fields sends decimal values rounded to three places. Compare
	// the parsed wire value, not the caller's higher-precision float64.
	if _, isDecimal := option.value.(float64); isDecimal {
		encoded, err := httpsfv.Marshal(httpsfv.Item{Value: option.value, Params: httpsfv.NewParams()})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrParameter, err)
		}

		parsed, err := httpsfv.UnmarshalItem([]string{encoded})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrParameter, err)
		}

		option.value = parsed.Value
	}

	if v, ok := option.value.([]byte); ok {
		option.value = bytes.Clone(v)
	}

	return e.expectParameter(option)
}

func (e *verificationPolicy) expectParameter(option parameterOption) error {
	if slices.Contains(e.forbiddenParameters, option.name) {
		return fmt.Errorf("%w: expected parameter %q is forbidden", ErrParameter, option.name)
	}

	for _, existing := range e.expectedParameters {
		if existing.name == option.name {
			if reflect.DeepEqual(existing.value, option.value) {
				return nil
			}

			return fmt.Errorf("%w: conflicting expectations for parameter %q", ErrParameter, option.name)
		}
	}

	e.expectedParameters = append(e.expectedParameters, option)

	return nil
}

func (e *verificationPolicy) validateParameters(tag string) error {
	for _, name := range e.forbiddenParameters {
		if name == Tag && tag != "" ||
			name == Created && *e.reqCreatedTS ||
			name == Expires && *e.reqExpiresTS {
			return fmt.Errorf("%w: required signature parameter %q is forbidden", ErrParameter, name)
		}
	}

	return nil
}

// nolint: funlen, cyclop, gocognit
func (e *verificationPolicy) assertMetadata(si *signatureInput, msg *Message) error {
	var (
		missingComponents []string
		cmv               compositeMessageVerifier
		mv                messageVerifier
		tolerance         time.Duration
	)

	now := time.Now().UTC()
	if e.tolerance != nil {
		tolerance = *e.tolerance
	}

	expires, expiresPresent := si.expires()
	if !expiresPresent {
		if *e.reqExpiresTS {
			return fmt.Errorf("%w: expected expires parameter not present", ErrMissingParameter)
		}
	} else if now.After(expires.Add(tolerance)) {
		return fmt.Errorf("%w: signature expired", ErrValidity)
	}

	created, createdPresent := si.created()
	if !createdPresent {
		if *e.reqCreatedTS {
			return fmt.Errorf("%w: expected created parameter not present", ErrMissingParameter)
		}
	} else {
		if now.Before(created.Add(-1 * tolerance)) {
			return fmt.Errorf("%w: signature not yet valid", ErrValidity)
		}

		if created.Add(e.maxAge).Before(now) {
			return fmt.Errorf("%w: signature too old", ErrValidity)
		}
	}

	for _, expIdentifier := range e.identifiers {
		if !si.hasIdentifier(expIdentifier) {
			res, _ := httpsfv.Marshal(expIdentifier)
			missingComponents = append(missingComponents, res)
		}
	}

	if len(missingComponents) > 0 {
		return fmt.Errorf("%w: missing component identifiers: %s",
			ErrMissingParameter, strings.Join(missingComponents, ", "))
	}

	for _, name := range e.requiredParameters {
		if _, present := si.parameter(name); !present {
			return fmt.Errorf("%w: required signature parameter %q is missing", ErrParameter, name)
		}
	}

	for _, name := range e.forbiddenParameters {
		if _, present := si.parameter(name); present {
			return fmt.Errorf("%w: forbidden signature parameter %q is present", ErrParameter, name)
		}
	}

	for _, param := range e.expectedParameters {
		value, present := si.parameter(param.name)
		if !present {
			return fmt.Errorf("%w: expected signature parameter %q is missing", ErrMissingParameter, param.name)
		}

		if !reflect.DeepEqual(value, param.value) {
			return fmt.Errorf("%w: unexpected value for signature parameter %q", ErrParameter, param.name)
		}
	}

	for _, id := range si.identifiers {
		if id.Value == "content-digest" {
			_, fromReq := id.Params.Get("req")

			cmv = append(cmv, contentDigester{fromRequest: fromReq})
		}
	}

	if len(cmv) == 0 {
		mv = noopMessageVerifier{}
	} else {
		mv = cmv
	}

	return mv.verify(msg)
}

func (e *verificationPolicy) assertKeyAlgorithm(si *signatureInput, keyAlg SignatureAlgorithm) error {
	algorithm, algPresent := si.algorithm()
	if algPresent && algorithm != keyAlg {
		return fmt.Errorf("%w: key algorithm %s does not match signature algorithm %s",
			ErrParameter, algorithm, keyAlg)
	}

	return nil
}

package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Report is the v1 bug-report payload contract that the LibreMail app
// (LibreMail#33) sends to POST /v1/reports as a JSON object.
//
// Required fields: appVersion, platform, report. Everything else is optional.
// Validation is deliberately loose (see validate): the endpoint rejects only
// clearly-invalid payloads (missing required fields, absurd field lengths, a
// non-RFC3339 timestamp) so that newer app versions can add fields without
// breaking ingest. Unknown fields are ignored, not rejected.
//
// Example:
//
//	{
//	  "appVersion": "1.4.2 (142)",
//	  "platform": "android",
//	  "osVersion": "Android 14",
//	  "device": "Pixel 7",
//	  "clientTimestamp": "2026-07-02T12:34:56Z",
//	  "report": "NullPointerException in SyncService...\n<logs>"
//	}
type Report struct {
	// AppVersion is the LibreMail app version, e.g. "1.4.2" or "1.4.2 (142)". Required.
	AppVersion string `json:"appVersion"`
	// Platform is the client platform, e.g. "android". Required.
	Platform string `json:"platform"`
	// Report is the free-text bug report: user description, logs, stack traces. Required.
	Report string `json:"report"`
	// OSVersion is the client OS version, e.g. "Android 14". Optional.
	OSVersion string `json:"osVersion,omitempty"`
	// Device is the device model/descriptor, e.g. "Pixel 7". Optional.
	Device string `json:"device,omitempty"`
	// ClientTimestamp is when the report was captured on the client, RFC 3339. Optional.
	ClientTimestamp string `json:"clientTimestamp,omitempty"`
}

// Per-field length caps. These are defensive only: the 256 KiB body cap
// (MaxBodyBytes) is the real ceiling, and these just reject an absurd single
// metadata value with a clear 400 rather than storing it.
const (
	maxAppVersionLen = 256
	maxPlatformLen   = 64
	maxOSVersionLen  = 128
	maxDeviceLen     = 256
)

// parseReport decodes raw into a Report and validates it. A non-nil error means
// the caller should respond 400; the error text is for internal logging only
// and must never be echoed to the client (it could reflect request contents).
//
// raw is expected to already be within MaxBodyBytes (the handler enforces the
// size cap before calling this), so no read limiting happens here.
func parseReport(raw []byte) (*Report, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Note: DisallowUnknownFields is intentionally NOT set, so forward-compatible
	// clients may add fields. We do reject trailing garbage after the object.
	var rep Report
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("unexpected trailing data after JSON value")
	}
	if err := rep.validate(); err != nil {
		return nil, err
	}
	return &rep, nil
}

// validate enforces the loose v1 schema rules and returns the first problem
// found, or nil if the report is acceptable.
func (r *Report) validate() error {
	appVersion := strings.TrimSpace(r.AppVersion)
	platform := strings.TrimSpace(r.Platform)

	switch {
	case appVersion == "":
		return errors.New("appVersion is required")
	case len(appVersion) > maxAppVersionLen:
		return errors.New("appVersion is too long")
	case platform == "":
		return errors.New("platform is required")
	case len(platform) > maxPlatformLen:
		return errors.New("platform is too long")
	case strings.TrimSpace(r.Report) == "":
		return errors.New("report is required")
	case len(r.OSVersion) > maxOSVersionLen:
		return errors.New("osVersion is too long")
	case len(r.Device) > maxDeviceLen:
		return errors.New("device is too long")
	}

	if r.ClientTimestamp != "" {
		if _, err := time.Parse(time.RFC3339, r.ClientTimestamp); err != nil {
			return fmt.Errorf("clientTimestamp must be RFC3339: %w", err)
		}
	}
	return nil
}

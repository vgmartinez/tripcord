package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// Schema identifiers for the v1 documents.
const (
	SchemaEvent   = "tripcord.event/v1"
	SchemaFinding = "tripcord.finding/v1"
	SchemaSession = "tripcord.session/v1"
)

// EventKind classifies a session fact.
// The sample uses tool_call. read, write, net, and message are the
// English ids for the spec's lectura, escritura, red, and mensaje.
// The wire schema does not close this set.
type EventKind string

const (
	EventKindToolCall EventKind = "tool_call"
	EventKindRead     EventKind = "read"
	EventKindWrite    EventKind = "write"
	EventKindNet      EventKind = "net"
	EventKindMessage  EventKind = "message"
)

// String returns the wire value.
func (k EventKind) String() string { return string(k) }

// Source is the harness that produced an event. Only Harness is
// required; a local, non-cloud event may have no surface or origin to
// report. Surface here is a free string such as "cloud", not a rule
// surface id. Origin here is a free string such as "hook:PreToolUse",
// not Session origin.
type Source struct {
	Harness Harness `json:"harness"`
	Surface string  `json:"surface,omitempty"`
	Version string  `json:"version,omitempty"`
	Origin  string  `json:"origin,omitempty"`
}

// EventSession is the session context copied onto an event. Only ID is
// required; a local session outside a git repo may have no repo,
// branch, or actor to report.
type EventSession struct {
	ID     string `json:"id"`
	Repo   string `json:"repo,omitempty"`
	Branch string `json:"branch,omitempty"`
	Actor  string `json:"actor,omitempty"`
	// Parent has no omitempty: nil always marshals as the literal "null"
	// (no parent session), matching the spec sample. The event schema
	// does not require this key, so a decoder may also see it absent.
	Parent *string `json:"parent"`
}

// NetEvent is one network observation.
// The event sample only shows an empty net array, so the JSON Schema
// leaves this object open. Host, method, and URL are the working fields.
// Unknown keys are discarded on decode.
type NetEvent struct {
	Host   string `json:"host,omitempty"`
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
}

// CredentialRef is a credential observation without the secret value.
// Fingerprint, last4, and provider follow the stored-secret record in
// the spec. The JSON Schema leaves this object open. Unknown keys,
// including a raw secret, are discarded on decode.
type CredentialRef struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	Last4       string `json:"last4,omitempty"`
	Provider    string `json:"provider,omitempty"`
}

// Event is one session fact (tripcord.event/v1). Schema, ID, TS,
// Source.Harness, Session.ID, and Kind are required; every other field
// is optional, so a minimal local event can omit tool, command, paths,
// net, credentials, redactions, and raw_ref.
type Event struct {
	Schema      string          `json:"schema"`
	ID          string          `json:"id"`
	TS          time.Time       `json:"ts"`
	Source      Source          `json:"source"`
	Session     EventSession    `json:"session"`
	Kind        EventKind       `json:"kind"`
	Tool        string          `json:"tool,omitempty"`
	Command     string          `json:"command,omitempty"`
	Paths       []string        `json:"paths"`
	Net         []NetEvent      `json:"net"`
	Credentials []CredentialRef `json:"credentials"`
	Redactions  int             `json:"redactions"`
	RawRef      string          `json:"raw_ref,omitempty"`
}

// MarshalJSON emits empty arrays for nil slices so a value matches the schema.
func (e Event) MarshalJSON() ([]byte, error) {
	if e.Paths == nil {
		e.Paths = []string{}
	}
	if e.Net == nil {
		e.Net = []NetEvent{}
	}
	if e.Credentials == nil {
		e.Credentials = []CredentialRef{}
	}
	type alias Event
	return json.Marshal(alias(e))
}

// Validate checks the fields the event schema requires: schema, id, ts,
// a product source harness, a session id, and a kind. Every other field
// is optional; when Redactions is set, it must not be negative.
func (e Event) Validate() error {
	if e.Schema != SchemaEvent {
		return fmt.Errorf("event: schema %q", e.Schema)
	}
	if e.ID == "" {
		return fmt.Errorf("event: empty id")
	}
	if e.TS.IsZero() {
		return fmt.Errorf("event: missing ts")
	}
	if !e.Source.Harness.IsProduct() {
		return fmt.Errorf("event: harness %q: unknown product", e.Source.Harness)
	}
	if e.Session.ID == "" {
		return fmt.Errorf("event: empty session id")
	}
	if e.Kind == "" {
		return fmt.Errorf("event: empty kind")
	}
	if e.Redactions < 0 {
		return fmt.Errorf("event: redactions %d", e.Redactions)
	}
	return nil
}

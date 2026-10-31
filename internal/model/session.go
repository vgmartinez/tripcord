package model

import (
	"encoding/json"
	"fmt"
)

// Origin is where a session was recorded.
type Origin string

const (
	OriginLocal    Origin = "local"
	OriginCloud    Origin = "cloud"
	OriginImported Origin = "imported"
)

var origins = []Origin{OriginLocal, OriginCloud, OriginImported}

// String returns the wire value.
func (o Origin) String() string { return string(o) }

// Valid reports whether o is local, cloud, or imported.
func (o Origin) Valid() bool {
	for _, item := range origins {
		if item == o {
			return true
		}
	}
	return false
}

// ParseOrigin parses a wire value.
func ParseOrigin(s string) (Origin, error) {
	o := Origin(s)
	if !o.Valid() {
		return "", fmt.Errorf("origin %q: unknown", s)
	}
	return o, nil
}

// Session groups events (tripcord.session/v1).
// The spec names this document and does not publish a sample.
// A chained event hash from the forensics section is not a field here.
type Session struct {
	Schema string  `json:"schema"`
	ID     string  `json:"id"`
	Origin Origin  `json:"origin"`
	Repo   string  `json:"repo,omitempty"`
	Branch string  `json:"branch,omitempty"`
	Actor  string  `json:"actor,omitempty"`
	Parent *string `json:"parent"`
	Events []Event `json:"events"`
}

// MarshalJSON emits an empty events array when Events is nil.
func (s Session) MarshalJSON() ([]byte, error) {
	if s.Events == nil {
		s.Events = []Event{}
	}
	type alias Session
	return json.Marshal(alias(s))
}

// Validate checks the session fields and each nested event.
func (s Session) Validate() error {
	if s.Schema != SchemaSession {
		return fmt.Errorf("session: schema %q", s.Schema)
	}
	if s.ID == "" {
		return fmt.Errorf("session: empty id")
	}
	if !s.Origin.Valid() {
		return fmt.Errorf("session: origin %q: unknown", s.Origin)
	}
	if s.Parent != nil && *s.Parent == "" {
		return fmt.Errorf("session: parent is empty")
	}
	for i, ev := range s.Events {
		if err := ev.Validate(); err != nil {
			return fmt.Errorf("session: event %d: %w", i, err)
		}
	}
	return nil
}

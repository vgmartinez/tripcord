package prcontext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Event is the part of a GitHub pull_request payload pr-context reads.
type Event struct {
	Login string
	// AuthorType is GitHub's pull_request.user.type ("Bot", "User", ...).
	// Empty means the event did not include the field.
	AuthorType string
	Branch     string
	Base       string
	Head       string
}

// ParseEvent reads a GitHub workflow event. The file may be the whole
// event (with a pull_request member) or the pull_request object itself.
// Missing fields are left empty; the caller decides which are required.
func ParseEvent(data []byte) (Event, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Event{}, &InputError{Msg: "event file is empty"}
	}
	var root struct {
		PullRequest json.RawMessage `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return Event{}, &InputError{Msg: fmt.Sprintf("event JSON: %v", err)}
	}
	payload := data
	if len(bytes.TrimSpace(root.PullRequest)) > 0 && string(bytes.TrimSpace(root.PullRequest)) != "null" {
		payload = root.PullRequest
	}
	var pr struct {
		User struct {
			Login string  `json:"login"`
			Type  *string `json:"type"`
		} `json:"user"`
		Head struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
		} `json:"base"`
	}
	if err := json.Unmarshal(payload, &pr); err != nil {
		return Event{}, &InputError{Msg: fmt.Sprintf("event JSON: %v", err)}
	}
	ev := Event{Login: pr.User.Login, Branch: pr.Head.Ref, Base: pr.Base.SHA, Head: pr.Head.SHA}
	if pr.User.Type != nil {
		ev.AuthorType = strings.TrimSpace(*pr.User.Type)
	}
	if ev.Login == "" && ev.Branch == "" && ev.Base == "" && ev.Head == "" {
		return Event{}, &InputError{Msg: "event has no pull_request"}
	}
	for _, field := range []struct{ name, value string }{
		{"pull_request.user.login", ev.Login},
		{"pull_request.user.type", ev.AuthorType},
		{"pull_request.head.ref", ev.Branch},
		{"pull_request.base.sha", ev.Base},
		{"pull_request.head.sha", ev.Head},
	} {
		if strings.ContainsAny(field.value, "\x00\r\n") {
			return Event{}, &InputError{Msg: field.name + " contains a control character"}
		}
	}
	return ev, nil
}

// InputError is an unusable event, flag, or repository. It is reported
// as exit code 3.
type InputError struct {
	Msg string
}

func (e *InputError) Error() string { return e.Msg }

// ValidateRev rejects a revision that git would parse as an option or as
// revision syntax beyond a single ref. base and head are joined into
// base..head by the caller, so neither one may contain "..".
func ValidateRev(name, value string) error {
	switch {
	case value == "":
		return &InputError{Msg: name + " is empty"}
	case strings.HasPrefix(value, "-"):
		return &InputError{Msg: name + " must not start with '-'"}
	case strings.ContainsAny(value, "\x00\r\n \t"):
		return &InputError{Msg: name + " contains whitespace or a control character"}
	case strings.Contains(value, ".."):
		return &InputError{Msg: name + " must not contain '..'"}
	case strings.ContainsAny(value, "^:~\\@?*[{"):
		return &InputError{Msg: name + " contains git revision syntax"}
	default:
		return nil
	}
}

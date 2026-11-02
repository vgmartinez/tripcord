package prcontext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Review is one GitHub pull request review the event exposed.
type Review struct {
	// State is the review's state field, such as APPROVED. The casing
	// is kept as it appeared; callers normalize it.
	State string
	// Login is user.login. Empty when the review has no user.
	Login string
	// UserType is user.type. Empty when the event omitted it.
	UserType string
	// CommitID is the commit the review was submitted against. Empty
	// when the payload omitted it. An approval of an older commit does
	// not approve the pull request head.
	CommitID string
	// SubmittedAt is the review's submitted_at timestamp, unchanged.
	// Empty when the payload omitted it; callers then keep array order.
	SubmittedAt string
}

// ReviewSet is the review data a pull request event exposed.
// Available is true only when the payload contains a reviews array,
// including an empty array. A lone review object is recorded in Reviews
// but leaves Available false: one review does not prove the others.
type ReviewSet struct {
	Available bool
	Reviews   []Review
}

// ParseReviewArray reads a JSON array of GitHub review objects, the
// shape of GET /pulls/{n}/reviews concatenated across pages. The array
// is the complete set, including when it is empty. Any other JSON value,
// including an object or an empty file, is an InputError.
func ParseReviewArray(data []byte) (ReviewSet, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return ReviewSet{}, &InputError{Msg: "reviews file must be a JSON array"}
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return ReviewSet{}, &InputError{Msg: fmt.Sprintf("reviews file: %v", err)}
	}
	arr, ok := root.([]any)
	if !ok {
		return ReviewSet{}, &InputError{Msg: "reviews file must be a JSON array"}
	}
	reviews, err := reviewsFromArray(arr)
	if err != nil {
		return ReviewSet{}, err
	}
	return ReviewSet{Available: true, Reviews: reviews}, nil
}

// ParseReviews reads review data from a GitHub event. The payload may be
// the event, the pull_request object, or a reviews array. A missing,
// null, or non-array reviews field leaves Available false. Invalid JSON
// is an InputError. A payload with no review fields is an empty set,
// not an error.
func ParseReviews(data []byte) (ReviewSet, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return ReviewSet{}, nil
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return ReviewSet{}, &InputError{Msg: fmt.Sprintf("event JSON: %v", err)}
	}
	set, err := reviewSetFrom(root)
	if err != nil {
		return ReviewSet{}, err
	}
	return set, nil
}

func reviewSetFrom(root any) (ReviewSet, error) {
	if arr, ok := root.([]any); ok {
		reviews, err := reviewsFromArray(arr)
		if err != nil {
			return ReviewSet{}, err
		}
		return ReviewSet{Available: true, Reviews: reviews}, nil
	}
	obj, ok := root.(map[string]any)
	if !ok || obj == nil {
		return ReviewSet{}, nil
	}
	if raw, exists := obj["reviews"]; exists {
		if arr, ok := raw.([]any); ok {
			reviews, err := reviewsFromArray(arr)
			if err != nil {
				return ReviewSet{}, err
			}
			return ReviewSet{Available: true, Reviews: reviews}, nil
		}
		return ReviewSet{}, nil
	}
	if raw, exists := obj["pull_request"]; exists {
		if _, isObj := raw.(map[string]any); isObj {
			set, err := reviewSetFrom(raw)
			if err != nil {
				return ReviewSet{}, err
			}
			if set.Available {
				return set, nil
			}
		}
	}
	if raw, exists := obj["review"]; exists {
		review, ok, err := reviewFrom(raw)
		if err != nil {
			return ReviewSet{}, err
		}
		if ok {
			return ReviewSet{Reviews: []Review{review}}, nil
		}
	}
	return ReviewSet{}, nil
}

func reviewsFromArray(arr []any) ([]Review, error) {
	out := make([]Review, 0, len(arr))
	for _, item := range arr {
		review, ok, err := reviewFrom(item)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, review)
		}
	}
	return out, nil
}

func reviewFrom(raw any) (Review, bool, error) {
	obj, ok := raw.(map[string]any)
	if !ok || obj == nil {
		return Review{}, false, nil
	}
	review := Review{}
	if state, ok := obj["state"].(string); ok {
		review.State = state
	}
	if user, ok := obj["user"].(map[string]any); ok && user != nil {
		if login, ok := user["login"].(string); ok {
			review.Login = login
		}
		if kind, ok := user["type"].(string); ok {
			review.UserType = kind
		}
	}
	if commitID, ok := obj["commit_id"].(string); ok {
		review.CommitID = commitID
	}
	if submitted, ok := obj["submitted_at"].(string); ok {
		review.SubmittedAt = submitted
	}
	for _, field := range []struct{ name, value string }{
		{"review.state", review.State},
		{"review.user.login", review.Login},
		{"review.user.type", review.UserType},
		{"review.commit_id", review.CommitID},
		{"review.submitted_at", review.SubmittedAt},
	} {
		if strings.ContainsAny(field.value, "\x00\r\n") {
			return Review{}, false, &InputError{Msg: field.name + " contains a control character"}
		}
	}
	return review, true, nil
}

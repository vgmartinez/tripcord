package argv

import "testing"

func TestValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
		kind Kind
	}{
		{"scalar", "-e", "-e", Scalar},
		{"number", float64(1), "1", Scalar},
		{"list", []any{"-e"}, "-e", CoercedList},
		{"nested list", []any{[]any{"-e"}}, "-e", CoercedList},
		{"mixed list", []any{"-y", "pkg@1"}, "-y,pkg@1", CoercedList},
		{"null inside list", []any{"-e", nil, "x"}, "-e,,x", CoercedList},
		{"map", map[string]any{"arg": "-e"}, Opaque, OpaqueMap},
		{"map inside list", []any{map[string]any{"arg": "-e"}}, Opaque, OpaqueMap},
		{"top-level null", nil, "", Invalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, kind := Value(tc.in, false)
			if got != tc.want || kind != tc.kind {
				t.Fatalf("Value(%#v) = %q, %v; want %q, %v", tc.in, got, kind, tc.want, tc.kind)
			}
		})
	}
}

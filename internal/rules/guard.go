package rules

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
)

// configKeys are the keys ConfigInput always binds in config.
var configKeys = []string{"id", "harness", "scope", "path", "sha256", "kind", "missing_scripts", "script_locations"}

// checkGuards rejects expressions that read optional data without
// first testing that it is there.
//
// payload and task hold untrusted documents in which any field may be
// missing, and a missing field makes the whole expression false (see
// Expr.Eval). Without a guard, a negated or deny-style condition would
// then fail open. So every field read below payload or task, below a
// comprehension variable, or below event outside eventFields must be
// dominated by a has() test of that field (or a `"key" in x` test): on
// the left of &&, negated on the left of ||, or in the condition of ?:.
// Indexing is allowed only with a constant string key on a variable's
// fields, under the same guard. config reads must name one of the keys
// ConfigInput binds; eventFields are bound on every input. dyn(x) is
// transparent for this check: dyn(payload).a needs the same guard as
// payload.a. Selecting a field off any other function's result, or off
// a map, list, or struct literal or a comprehension, is rejected
// outright, since it cannot be traced back to a variable for has() to
// guard.
func checkGuards(expr ast.Expr) error {
	g := &guards{optional: map[string]bool{VarPayload: true, VarTask: true, VarEvent: true}}
	g.check(expr, nil)
	if len(g.errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(g.errs, "; "))
}

type guards struct {
	// optional holds the variable names whose fields may be missing.
	optional map[string]bool
	errs     []string
}

func (g *guards) fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !slices.Contains(g.errs, msg) {
		g.errs = append(g.errs, msg)
	}
}

// check walks e. known holds the field paths proven present where e
// is evaluated.
func (g *guards) check(e ast.Expr, known []string) {
	switch e.Kind() {
	case ast.SelectKind:
		sel := e.AsSelect()
		g.check(sel.Operand(), known)
		if sel.IsTestOnly() {
			return
		}
		g.read(e, known)
	case ast.CallKind:
		call := e.AsCall()
		args := call.Args()
		switch call.FunctionName() {
		case operators.LogicalAnd:
			g.check(args[0], known)
			g.check(args[1], append(slices.Clone(known), facts(args[0], true)...))
			return
		case operators.LogicalOr:
			g.check(args[0], known)
			g.check(args[1], append(slices.Clone(known), facts(args[0], false)...))
			return
		case operators.Conditional:
			g.check(args[0], known)
			g.check(args[1], append(slices.Clone(known), facts(args[0], true)...))
			g.check(args[2], append(slices.Clone(known), facts(args[0], false)...))
			return
		case operators.Index:
			g.check(args[0], known)
			g.check(args[1], known)
			g.read(e, known)
			return
		}
		if call.IsMemberFunction() {
			g.check(call.Target(), known)
		}
		for _, a := range args {
			g.check(a, known)
		}
	case ast.ComprehensionKind:
		c := e.AsComprehension()
		g.check(c.IterRange(), known)
		g.check(c.AccuInit(), known)
		saved := maps.Clone(g.optional)
		g.optional[c.IterVar()] = true
		if c.HasIterVar2() {
			g.optional[c.IterVar2()] = true
		}
		g.check(c.LoopCondition(), known)
		g.check(c.LoopStep(), known)
		g.optional = saved
		g.check(c.Result(), known)
	case ast.ListKind:
		for _, el := range e.AsList().Elements() {
			g.check(el, known)
		}
	case ast.MapKind:
		for _, en := range e.AsMap().Entries() {
			me := en.AsMapEntry()
			g.check(me.Key(), known)
			g.check(me.Value(), known)
		}
	case ast.StructKind:
		for _, f := range e.AsStruct().Fields() {
			g.check(f.AsStructField().Value(), known)
		}
	case ast.IdentKind, ast.LiteralKind, ast.UnspecifiedExprKind:
	default:
		panic(fmt.Sprintf("rules: unhandled CEL expression kind %d", e.Kind()))
	}
}

// read checks one field read or index, e.
func (g *guards) read(e ast.Expr, known []string) {
	root, fields, ok, blockedByCall := fieldPath(e)
	if !ok || root == "" {
		switch {
		case e.Kind() == ast.CallKind:
			// A list index or a computed key cannot be guarded with
			// has(), and out of range it is silently false.
			g.fail("index a variable's fields only with a constant string key; use exists() or all() for lists")
		case blockedByCall:
			// A field selected off a function result other than dyn(), or
			// off a map, list, or struct literal or a comprehension,
			// cannot be traced back to a variable, so has() cannot guard
			// it either. dyn(x) is transparent and walks through to x
			// instead of landing here.
			g.fail("select a field from a variable or from dyn() of one, not from another function's result or a literal; name the variable directly so the guard can be checked")
		}
		return
	}
	switch {
	case root == VarConfig:
		if len(fields) == 1 && !slices.Contains(configKeys, fields[0]) {
			g.fail("config.%s: config has only %s", fields[0], strings.Join(configKeys, ", "))
		}
	case root == VarEvent && slices.Contains(eventFields, strings.Join(fields, ".")):
	case g.optional[root]:
		p := joinPath(root, fields)
		if !slices.Contains(known, p) {
			g.fail("%s may be missing; guard it with has(%s)", p, p)
		}
	}
}

// fieldPath returns the variable and field names e reads, as in
// payload.a["b"] -> payload, [a b]. dyn(x) is transparent: it is
// unwrapped to x instead of ending the chain, so dyn(payload).a is the
// same path as payload.a. ok is false when e is not a chain of field
// reads, constant string indexes, and dyn() wrappers on a variable;
// root is still set when the chain starts at a variable. blockedByCall
// is true when resolution stopped at a function call other than dyn()
// or a constant-key index, or at a map, list, or struct literal or a
// comprehension: that result cannot be traced back to a variable, so
// has() cannot guard whatever it holds.
func fieldPath(e ast.Expr) (root string, fields []string, ok bool, blockedByCall bool) {
	ok = true
	for {
		switch e.Kind() {
		case ast.IdentKind:
			slices.Reverse(fields)
			return e.AsIdent(), fields, ok, false
		case ast.SelectKind:
			sel := e.AsSelect()
			fields = append(fields, sel.FieldName())
			e = sel.Operand()
		case ast.CallKind:
			call := e.AsCall()
			switch {
			case call.FunctionName() == operators.Index:
				key := call.Args()[1]
				s, isStr := constString(key)
				if !isStr {
					ok = false
				}
				fields = append(fields, s)
				e = call.Args()[0]
			case isDyn(call):
				e = call.Args()[0]
			default:
				return "", nil, false, true
			}
		default:
			// A map, list, or struct literal, or a comprehension, is not
			// a variable. Selecting a field off it fails open: a missing
			// field is silently false, and has() cannot name it.
			return "", nil, false, true
		}
	}
}

// isDyn reports whether call is the dyn() stdlib function: an identity
// function that only changes the static type CEL's checker assigns its
// argument, to let a select or index compile where the declared type
// would otherwise reject it.
func isDyn(call ast.CallExpr) bool {
	return !call.IsMemberFunction() && call.FunctionName() == "dyn" && len(call.Args()) == 1
}

func constString(e ast.Expr) (string, bool) {
	if e.Kind() != ast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}

func joinPath(root string, fields []string) string {
	return strings.Join(append([]string{root}, fields...), ".")
}

// facts returns the field paths proven present when e evaluates to
// truth, with every prefix of each path.
func facts(e ast.Expr, truth bool) []string {
	if e.Kind() == ast.SelectKind && e.AsSelect().IsTestOnly() {
		if !truth {
			return nil
		}
		sel := e.AsSelect()
		root, fields, ok, _ := fieldPath(sel.Operand())
		if !ok || root == "" {
			return nil
		}
		return prefixes(root, append(fields, sel.FieldName()))
	}
	if e.Kind() != ast.CallKind {
		return nil
	}
	call := e.AsCall()
	args := call.Args()
	switch call.FunctionName() {
	case operators.LogicalNot:
		return facts(args[0], !truth)
	case operators.LogicalAnd:
		if truth {
			return append(facts(args[0], true), facts(args[1], true)...)
		}
	case operators.LogicalOr:
		if !truth {
			return append(facts(args[0], false), facts(args[1], false)...)
		}
	case operators.In:
		key, isStr := constString(args[0])
		if !truth || !isStr {
			return nil
		}
		root, fields, ok, _ := fieldPath(args[1])
		if !ok || root == "" {
			return nil
		}
		return prefixes(root, append(fields, key))
	}
	return nil
}

func prefixes(root string, fields []string) []string {
	out := make([]string, len(fields))
	for i := range fields {
		out[i] = joinPath(root, fields[:i+1])
	}
	return out
}

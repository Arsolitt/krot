package staticmerge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Arsolitt/krot/internal/model"
)

// compactSeparator joins entries inserted without layout around them.
var compactSeparator = []byte(",")

// insertion is one pending text insertion at a byte offset of the base.
type insertion struct {
	text []byte
	off  int
}

// vlessEntry is one appended vless users-array element. The flow is copied
// from the base array so appended users are served like the legacy ones.
type vlessEntry struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

// hysteria2Entry is one appended hysteria2 users-array element.
type hysteria2Entry struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// targetState tracks the credentials one merge target already serves: the
// base users array's own credentials plus everything appended for the same
// tag. UUIDs are compared case-insensitively, passwords exactly.
type targetState struct {
	uuids     map[string]bool
	passwords map[string]bool
}

// newTargetState returns a dedup state that serves nothing yet.
func newTargetState() *targetState {
	return &targetState{uuids: map[string]bool{}, passwords: map[string]bool{}}
}

// claim returns the credential to append for u under the declared type, or
// false when the credential is empty or already served by the target. A
// claimed credential is recorded as served.
func (s *targetState) claim(inType model.InboundType, u *model.User) (string, bool) {
	if inType == model.InboundHysteria2 {
		if u.Hy2Password == "" || s.passwords[u.Hy2Password] {
			return "", false
		}
		s.passwords[u.Hy2Password] = true
		return u.Hy2Password, true
	}
	id := u.VLESSUUID
	key := strings.ToLower(id)
	if id == "" || s.uuids[key] {
		return "", false
	}
	s.uuids[key] = true
	return id, true
}

// observe records the credential a base users-array entry carries, if any.
func (s *targetState) observe(entry map[string]json.RawMessage) {
	if id, ok := rawString(entry[keyUUID]); ok && id != "" {
		s.uuids[strings.ToLower(id)] = true
	}
	if password, ok := rawString(entry[keyPassword]); ok && password != "" {
		s.passwords[password] = true
	}
}

// target is one resolved merge target: the base inbound whose users array
// receives the appended entries, that array's spans and the credentials the
// target already serves.
type target struct {
	in       *baseInbound
	state    *targetState
	tag      string
	flow     string
	elems    []span
	users    span
	hasUsers bool
}

// targetFor resolves the merge target named by tag, caching it so a repeated
// declaration of the same tag appends only what earlier ones did not.
func targetFor(doc *baseDoc, cache map[string]*target, tag string) (*target, error) {
	if cached, ok := cache[tag]; ok {
		return cached, nil
	}
	in, ok := doc.byTag(tag)
	if !ok {
		return nil, errField(tag, keyTag, "base config has no inbound with this tag")
	}
	t := &target{in: in, tag: tag, state: newTargetState()}
	users, ok := in.memberSpan(keyUsers)
	if !ok {
		cache[tag] = t
		return t, nil
	}
	elems, err := scanArray(doc.raw[users.start:users.end], users.start)
	if err != nil {
		return nil, fmt.Errorf("inbound %q: %s: %w", tag, keyUsers, err)
	}
	t.hasUsers, t.users, t.elems = true, users, elems
	t.flow = firstFlow(doc.raw, elems)
	for _, elem := range elems {
		if entry, ok := rawMembers(doc.raw[elem.start:elem.end]); ok {
			t.state.observe(entry)
		}
	}
	cache[tag] = t
	return t, nil
}

// firstFlow returns the flow the base users array uses, taken from the first
// entry that carries a non-empty string flow; appended vless entries copy it
// so they are served like the legacy ones. An empty result means no entry
// uses a flow and the key is omitted.
func firstFlow(raw []byte, elems []span) string {
	for _, elem := range elems {
		entry, ok := rawMembers(raw[elem.start:elem.end])
		if !ok {
			continue
		}
		flow, ok := rawString(entry[keyFlow])
		if ok && flow != "" {
			return flow
		}
	}
	return ""
}

// entries returns the compact entry for every input user the target does not
// serve yet, in input order, claiming each credential as it goes.
func (t *target) entries(decl *model.InboundDecl, users []model.User) ([]json.RawMessage, error) {
	entries := make([]json.RawMessage, 0, len(users))
	for i := range users {
		credential, ok := t.state.claim(decl.Type, &users[i])
		if !ok {
			continue
		}
		entry, err := t.entry(decl.Type, &users[i], credential)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// entry renders one users-array element of the declared type's shape.
func (t *target) entry(inType model.InboundType, u *model.User, credential string) (json.RawMessage, error) {
	if inType == model.InboundHysteria2 {
		return marshalCompact(hysteria2Entry{Name: u.Name, Password: credential})
	}
	return marshalCompact(vlessEntry{Name: u.Name, UUID: credential, Flow: t.flow})
}

// insertion derives the offset and the text appended for a set of entries:
// entries laid out like the base's own elements after a non-empty array, a
// compact comma-joined list for an empty array, and a whole trailing users
// member for an inbound that carries none.
func (t *target) insertion(raw []byte, entries []json.RawMessage) (insertion, error) {
	switch {
	case !t.hasUsers:
		end, ok := t.in.lastMemberEnd()
		if !ok {
			return insertion{}, fmt.Errorf("inbound %q: base inbound object has no members", t.tag)
		}
		text := []byte{','}
		text = append(text, `"users":[`...)
		text = appendJoined(text, entries, compactSeparator)
		return insertion{off: end, text: append(text, ']')}, nil
	case len(t.elems) == 0:
		text := appendJoined(nil, entries, compactSeparator)
		return insertion{off: t.users.start + 1, text: text}, nil
	default:
		indent := entryIndent(raw, t.elems)
		var text []byte
		for _, entry := range entries {
			text = append(text, ',', '\n')
			text = append(text, indent...)
			text = append(text, entry...)
		}
		return insertion{off: t.elems[len(t.elems)-1].end, text: text}, nil
	}
}

// buildInsertion returns the insertion for one declared target. The second
// result is false when the target already serves every input user, in which
// case the base is left untouched.
func buildInsertion(
	doc *baseDoc, decl *model.InboundDecl, users []model.User, cache map[string]*target,
) (insertion, bool, error) {
	t, err := targetFor(doc, cache, decl.Tag)
	if err != nil {
		return insertion{}, false, err
	}
	entries, err := t.entries(decl, users)
	if err != nil {
		return insertion{}, false, fmt.Errorf("inbound %q: %w", decl.Tag, err)
	}
	if len(entries) == 0 {
		return insertion{}, false, nil
	}
	ins, err := t.insertion(doc.raw, entries)
	if err != nil {
		return insertion{}, false, err
	}
	return ins, true, nil
}

// entryIndent returns the indentation appended entries imitate: the pure-space
// prefix of the base array's last element line when that element sits on its
// own indented line, otherwise none, as in compact layouts. The caller
// guarantees a non-empty element list.
func entryIndent(raw []byte, elems []span) string {
	last := elems[len(elems)-1]
	prefix := raw[bytes.LastIndexByte(raw[:last.start], '\n')+1 : last.start]
	for _, b := range prefix {
		if b != ' ' && b != '\t' {
			return ""
		}
	}
	return string(prefix)
}

// appendJoined appends the entries to dst, separated by sep.
func appendJoined(dst []byte, entries []json.RawMessage, sep []byte) []byte {
	for i, entry := range entries {
		if i > 0 {
			dst = append(dst, sep...)
		}
		dst = append(dst, entry...)
	}
	return dst
}

// marshalCompact renders v as a single-line JSON value without HTML escaping,
// so appended names and credentials stay verbatim.
func marshalCompact(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode user entry: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// splice applies every insertion to the base bytes in one pass, ordered by
// offset; the base slice is only read, never written.
func splice(base []byte, insertions []insertion) []byte {
	sort.SliceStable(insertions, func(i, j int) bool { return insertions[i].off < insertions[j].off })
	size := len(base)
	for _, ins := range insertions {
		size += len(ins.text)
	}
	out := make([]byte, 0, size)
	prev := 0
	for _, ins := range insertions {
		out = append(out, base[prev:ins.off]...)
		out = append(out, ins.text...)
		prev = ins.off
	}
	return append(out, base[prev:]...)
}

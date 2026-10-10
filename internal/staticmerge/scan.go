package staticmerge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// JSON member names of the sing-box config subset the merge reads. Every
// other member of the base survives rendering untouched.
const (
	keyInbounds        = "inbounds"
	keyTag             = "tag"
	keyType            = "type"
	keyListenPort      = "listen_port"
	keyTLS             = "tls"
	keyServerName      = "server_name"
	keyReality         = "reality"
	keyPrivateKey      = "private_key"
	keyShortID         = "short_id"
	keyTransport       = "transport"
	keyUsers           = "users"
	keyCertificatePath = "certificate_path"
	keyObfs            = "obfs"
	keyPassword        = "password"
	keyUUID            = "uuid"
	keyName            = "name"
	keyFlow            = "flow"
)

// span is the half-open byte range [start,end) of a JSON value in the base.
type span struct {
	start int
	end   int
}

// baseDoc is a read-only view over the operator-owned base config: the raw
// bytes plus the byte spans of the top-level inbounds array elements.
type baseDoc struct {
	raw         []byte
	inbounds    []baseInbound
	hasInbounds bool
}

// baseInbound is one element of the base's top-level inbounds array: its byte
// span and the byte spans of its top-level members, keyed by member name.
type baseInbound struct {
	fields map[string]span
	span   span
}

// parseBase scans base for the top-level inbounds array and the byte spans of
// its elements. The base must be one JSON object carrying an inbounds array.
func parseBase(base []byte) (*baseDoc, error) {
	if !json.Valid(base) {
		return nil, errors.New("base config: invalid JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(base))
	if err := expectDelim(dec, '{', "top level"); err != nil {
		return nil, fmt.Errorf("base config: %w", err)
	}
	doc := &baseDoc{raw: base}
	for dec.More() {
		nameTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("base config: read member name: %w", err)
		}
		name, ok := nameTok.(string)
		if !ok {
			return nil, fmt.Errorf("base config: member name is %v, want string", nameTok)
		}
		member, err := nextValueSpan(dec)
		if err != nil {
			return nil, fmt.Errorf("base config: read member %q: %w", name, err)
		}
		if name == keyInbounds {
			if err := doc.scanInbounds(member); err != nil {
				return nil, err
			}
		}
	}
	if !doc.hasInbounds {
		return nil, errors.New("base config: missing top-level inbounds array")
	}
	return doc, nil
}

// scanInbounds records the elements of the base's top-level inbounds array. A
// duplicated top-level member keeps the last occurrence, matching
// encoding/json decoding.
func (d *baseDoc) scanInbounds(member span) error {
	if d.raw[member.start] != '[' {
		return fmt.Errorf("base config: %s: got %s, want array", keyInbounds, valueKind(d.raw[member.start]))
	}
	elems, err := scanArray(d.raw[member.start:member.end], member.start)
	if err != nil {
		return fmt.Errorf("base config: %s: %w", keyInbounds, err)
	}
	d.inbounds = nil
	for i, elem := range elems {
		fields, err := objectSpans(d.raw[elem.start:elem.end], elem.start)
		if err != nil {
			return fmt.Errorf("base config: %s[%d]: %w", keyInbounds, i, err)
		}
		d.inbounds = append(d.inbounds, baseInbound{span: elem, fields: fields})
	}
	d.hasInbounds = true
	return nil
}

// byTag returns the base inbound whose tag member equals tag.
func (d *baseDoc) byTag(tag string) (*baseInbound, bool) {
	for i := range d.inbounds {
		in := &d.inbounds[i]
		if got, ok := in.text(d.raw, keyTag); ok && got == tag {
			return in, true
		}
	}
	return nil, false
}

// memberSpan returns the byte span of the named top-level member of the
// inbound.
func (b *baseInbound) memberSpan(name string) (span, bool) {
	member, ok := b.fields[name]
	return member, ok
}

// member returns the raw bytes of the member at the nested member path, when
// every step of the path exists.
func (b *baseInbound) member(raw []byte, path ...string) (json.RawMessage, bool) {
	if len(path) == 0 {
		return nil, false
	}
	member, ok := b.fields[path[0]]
	if !ok {
		return nil, false
	}
	value := raw[member.start:member.end]
	for _, name := range path[1:] {
		members, ok := rawMembers(value)
		if !ok {
			return nil, false
		}
		value, ok = members[name]
		if !ok {
			return nil, false
		}
	}
	return value, true
}

// text returns the string at the nested member path of the inbound.
func (b *baseInbound) text(raw []byte, path ...string) (string, bool) {
	value, ok := b.member(raw, path...)
	if !ok {
		return "", false
	}
	return rawString(value)
}

// integer returns the integer at the nested member path of the inbound.
func (b *baseInbound) integer(raw []byte, path ...string) (int, bool) {
	value, ok := b.member(raw, path...)
	if !ok {
		return 0, false
	}
	return rawInt(value)
}

// lastMemberEnd returns the offset where a new trailing member is spliced in:
// the end of the inbound member that ends last. The second result is false
// for an object without members.
func (b *baseInbound) lastMemberEnd() (int, bool) {
	end := 0
	for _, member := range b.fields {
		end = max(end, member.end)
	}
	return end, end != 0
}

// scanArray returns the byte spans of the elements of the JSON array raw,
// shifted by off into base-config coordinates.
func scanArray(raw []byte, off int) ([]span, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := expectDelim(dec, '[', "array"); err != nil {
		return nil, err
	}
	var elems []span
	for dec.More() {
		elem, err := nextValueSpan(dec)
		if err != nil {
			return nil, fmt.Errorf("read array element: %w", err)
		}
		elems = append(elems, span{start: elem.start + off, end: elem.end + off})
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("read array end: %w", err)
	}
	return elems, nil
}

// objectSpans returns the byte spans of the members of the JSON object raw,
// keyed by member name and shifted by off into base-config coordinates.
func objectSpans(raw []byte, off int) (map[string]span, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := expectDelim(dec, '{', "object"); err != nil {
		return nil, err
	}
	members := make(map[string]span)
	for dec.More() {
		nameTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read member name: %w", err)
		}
		name, ok := nameTok.(string)
		if !ok {
			return nil, fmt.Errorf("read member name: got %v, want string", nameTok)
		}
		value, err := nextValueSpan(dec)
		if err != nil {
			return nil, fmt.Errorf("read member %q: %w", name, err)
		}
		members[name] = span{start: value.start + off, end: value.end + off}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("read object end: %w", err)
	}
	return members, nil
}

// nextValueSpan decodes the next JSON value from dec and recovers its exact
// byte span by measuring back from the stream position after the value.
func nextValueSpan(dec *json.Decoder) (span, error) {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return span{}, fmt.Errorf("decode value: %w", err)
	}
	end := int(dec.InputOffset())
	return span{start: end - len(raw), end: end}, nil
}

// expectDelim consumes the next token and requires it to be the given
// delimiter, naming what the caller expected it to open.
func expectDelim(dec *json.Decoder, want json.Delim, what string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read %s start: %w", what, err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != want {
		return fmt.Errorf("got %v, want %s", tok, what)
	}
	return nil
}

// rawString returns the string held by raw; the second result is false when
// raw is absent or holds a different JSON type.
func rawString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// rawInt returns the integer held by raw; the second result is false when raw
// is absent, not a number or not an integer.
func rawInt(raw json.RawMessage) (int, bool) {
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}

// rawMembers decodes raw as a JSON object into its member values.
func rawMembers(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, false
	}
	return members, true
}

// rawStrings returns the strings held by raw, accepting either a JSON array
// of strings or a single JSON string: the sing-box spellings of a short_id
// list, where a string means the single id.
func rawStrings(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	switch raw[0] {
	case '[':
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, false
		}
		return list, true
	case '"':
		single, ok := rawString(raw)
		if !ok {
			return nil, false
		}
		return []string{single}, true
	default:
		return nil, false
	}
}

// valueKind names the JSON value a leading byte introduces, for error text.
func valueKind(b byte) string {
	switch b {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	default:
		return "scalar"
	}
}

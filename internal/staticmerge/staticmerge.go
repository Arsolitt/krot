// Package staticmerge renders the effective sing-box configuration of a node
// that runs an operator-owned base config (KROT_STATIC_CONFIG): the base with
// the control plane's active users appended to the inbounds the node declares
// as merge targets.
//
// Rendering validates every declaration against the base first — the declared
// protocol, port, SNI and pinned credentials must agree with what the base
// carries — and then splices user entries into the base's JSON text. All base
// bytes outside the appended entries survive verbatim, and nothing is written
// to disk: the caller decides what to do with the rendered bytes.
package staticmerge

import "github.com/Arsolitt/krot/internal/model"

// Options is one merge request: the operator-owned base config, the data
// directory relative certificate paths resolve against, the node's inbound
// declarations and the control plane's active users. Base is only read.
type Options struct {
	Base    []byte
	DataDir string
	Decls   []model.InboundDecl
	Users   []model.User
}

// Validate checks every declaration against the base config: the target tag
// must name a base inbound whose protocol, port, SNI and pinned credentials
// agree with the declaration. Errors name the merge target tag and the field
// that disagrees. It reads the base and, for hysteria2 targets, the
// certificate the base references.
func Validate(opts Options) error {
	doc, err := parseBase(opts.Base)
	if err != nil {
		return err
	}
	return validateAll(doc, opts.Decls, opts.DataDir)
}

// Render returns the effective node config: the base bytes with, per declared
// target, the input users appended at the end of that inbound's users array,
// and nothing else changed. The base slice is never modified and nothing is
// written. With no declarations or no users the base is returned verbatim.
func Render(opts Options) ([]byte, error) {
	doc, err := parseBase(opts.Base)
	if err != nil {
		return nil, err
	}
	if err := validateAll(doc, opts.Decls, opts.DataDir); err != nil {
		return nil, err
	}
	if len(opts.Decls) == 0 || len(opts.Users) == 0 {
		return opts.Base, nil
	}
	cache := make(map[string]*target, len(opts.Decls))
	insertions := make([]insertion, 0, len(opts.Decls))
	for i := range opts.Decls {
		ins, ok, err := buildInsertion(doc, &opts.Decls[i], opts.Users, cache)
		if err != nil {
			return nil, err
		}
		if ok {
			insertions = append(insertions, ins)
		}
	}
	if len(insertions) == 0 {
		return opts.Base, nil
	}
	return splice(opts.Base, insertions), nil
}

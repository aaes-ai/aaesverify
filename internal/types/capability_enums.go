package types

// Location describes where a secret lives, rather than carrying it. The gateway
// and the policy engine handle references; only the broker resolves one, and the
// agent never receives either.
type Location int

const (
	// LocInline means AAES holds the secret material in its own encrypted store.
	LocInline Location = iota
	// LocKMS means the material lives in the customer's cloud secret manager and
	// AAES holds only a handle.
	LocKMS
	// LocIdP means no long-lived secret exists: authority is obtained by token
	// exchange at the customer's identity provider per decision.
	LocIdP
)

func (l Location) String() string {
	switch l {
	case LocInline:
		return "inline"
	case LocKMS:
		return "kms"
	case LocIdP:
		return "idp"
	}
	return "unknown"
}

// Injection describes how a resolved secret is presented to a tool.
type Injection int

const (
	// InjectHeader places the secret in a request header, e.g. Authorization.
	InjectHeader Injection = iota
	// InjectQuery places it in a named query parameter.
	InjectQuery
	// InjectBody places it in a named JSON body field.
	InjectBody
	// InjectMCP places it in a tool-session credential field.
	InjectMCP
)

func (i Injection) String() string {
	switch i {
	case InjectHeader:
		return "header"
	case InjectQuery:
		return "query"
	case InjectBody:
		return "body"
	case InjectMCP:
		return "mcp"
	}
	return "unknown"
}

// DataClassification drives handling and retention requirements.
type DataClassification int

const (
	DataPublic DataClassification = iota
	DataInternal
	DataPII
	DataPHI
	DataFinancial
)

func (d DataClassification) String() string {
	switch d {
	case DataPublic:
		return "public"
	case DataInternal:
		return "internal"
	case DataPII:
		return "pii"
	case DataPHI:
		return "phi"
	case DataFinancial:
		return "financial"
	}
	return "unknown"
}

// Valid reports whether the value is one of the defined classifications.
//
// The zero value is DataPublic, so an unset field reads as the classification
// with the FEWEST handling requirements. That is fine as a zero value for a
// struct that never left the process, but it is not fine for a registration: a
// value off the end of the enum, or one produced by a decode of a number no
// version of this package ever defined, must be refused rather than folded into
// "public". Capability.Validate is what refuses it.
func (d DataClassification) Valid() bool {
	switch d {
	case DataPublic, DataInternal, DataPII, DataPHI, DataFinancial:
		return true
	}
	return false
}

// CapabilityKind separates procedural knowledge from credentialed executables,
// because the two are governed differently: skills like code, tools like
// infrastructure.
type CapabilityKind int

const (
	CapTool CapabilityKind = iota
	CapSkill
)

func (k CapabilityKind) String() string {
	if k == CapSkill {
		return "skill"
	}
	return "tool"
}

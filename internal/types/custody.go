package types

import (
	"fmt"
)

// CustodyKind names where a credential lives, which is a customer choice per
// resource rather than a property of the platform.
type CustodyKind int

const (
	// CustodyInline is AAES holding the material in its own encrypted store.
	CustodyInline CustodyKind = iota
	// CustodyCustomerVault is a reference into the customer's secret manager.
	// AAES holds a pointer and never the root secret.
	CustodyCustomerVault
	// CustodyIdentityFederation means no long-lived secret exists: authority is a
	// short-lived token minted per decision from the resource owner's identity.
	CustodyIdentityFederation
	// CustodyPassThrough means the actor holds its own credential and AAES only
	// records the decision. This is OBSERVATION, not enforcement, and coverage
	// must exclude it.
	CustodyPassThrough
	// CustodyCustomerBroker is a customer-hosted broker that calls AAES for the
	// decision and then uses the credential locally.
	CustodyCustomerBroker
)

func (c CustodyKind) String() string {
	switch c {
	case CustodyInline:
		return "inline"
	case CustodyCustomerVault:
		return "customer_vault"
	case CustodyIdentityFederation:
		return "identity_federation"
	case CustodyPassThrough:
		return "pass_through"
	case CustodyCustomerBroker:
		return "customer_broker"
	}
	return fmt.Sprintf("unknown(%d)", int(c))
}

// Enforcement reports whether an action under this custody model is actually
// prevented when refused. Only the models where AAES controls the moment of use
// are enforcement; the rest are observation and cannot be counted as coverage.
func (c CustodyKind) Enforcement() bool {
	switch c {
	case CustodyPassThrough:
		return false
	default:
		return true
	}
}

// ConnectorKind names the surface a capability is reached through.
type ConnectorKind int

const (
	ConnHTTP ConnectorKind = iota
	ConnMCP
	ConnCLI
	ConnSQL
	ConnEmail
	ConnTelephony
	ConnBrowser
)

func (c ConnectorKind) String() string {
	switch c {
	case ConnHTTP:
		return "http"
	case ConnMCP:
		return "mcp"
	case ConnCLI:
		return "cli"
	case ConnSQL:
		return "sql"
	case ConnEmail:
		return "email"
	case ConnTelephony:
		return "telephony"
	case ConnBrowser:
		return "browser"
	}
	return fmt.Sprintf("unknown(%d)", int(c))
}

// CustodyKinds lists every custody model. It exists so a parser or a renderer
// cannot silently omit one: a model that is left out of this list becomes
// unparseable, which reads as "not recorded" and is therefore treated as
// observation rather than enforcement.
func CustodyKinds() []CustodyKind {
	return []CustodyKind{
		CustodyInline,
		CustodyCustomerVault,
		CustodyIdentityFederation,
		CustodyPassThrough,
		CustodyCustomerBroker,
	}
}

// ParseCustodyKind maps a recorded custody string back to its kind. The boolean
// reports whether the string named a known model, so a caller can distinguish
// "recorded as pass-through" from "not recorded at all" — a distinction that
// matters because only the first is a deliberate choice by an operator.
func ParseCustodyKind(raw string) (CustodyKind, bool) {
	for _, k := range CustodyKinds() {
		if k.String() == raw {
			return k, true
		}
	}
	return CustodyInline, false
}

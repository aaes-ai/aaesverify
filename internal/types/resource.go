package types

import (
	"fmt"
	"strings"
	"time"
)

// ResourceKind names what an action touches. It is a closed vocabulary: a kind
// AAES cannot name is refused rather than filed under "other", because "other"
// is where a register of record goes to stop being one.
type ResourceKind int

const (
	// ResBucket is object storage: a bucket, a container, a blob store.
	ResBucket ResourceKind = iota
	// ResTable is a database table, view or collection.
	ResTable
	// ResQueue is a message queue or a topic.
	ResQueue
	// ResRepo is a source repository.
	ResRepo
	// ResSite is a website or a web application.
	ResSite
	// ResMailbox is a mailbox or a mail distribution list.
	ResMailbox
	// ResChannel is a chat channel or a workspace.
	ResChannel
	// ResNumber is a telephone number.
	ResNumber
	// ResMCPServer is a Model Context Protocol server.
	ResMCPServer
	// ResGraph is a graph database or a graph namespace.
	ResGraph
	// ResAPI is a registered API or a service endpoint not covered above.
	ResAPI
	// ResBrowserProfile is a browser profile or a managed browser session an
	// agent drives. It is a work surface: the customer's browser platform owns
	// the session and AAES brokers the credential (ADR B-lite in
	// docs/positioning/SCOPE-AND-BOUNDARIES.md).
	ResBrowserProfile
	// ResDesktop is a desktop, workstation or virtual machine an agent acts on.
	// Like a browser profile it is a work surface owned by the customer's
	// platform; AAES holds the entitlement and the evidence, never the screen.
	ResDesktop
)

// ResourceKindUnspecified is what ParseResourceKind returns BESIDE a failed
// parse. It is not a kind: it is outside the vocabulary, String renders it as
// "unknown(-1)" and Resource.Validate refuses it. It exists so a valid kind
// never travels beside a false boolean; the zero value is ResBucket, and a
// caller that ignored the boolean would otherwise file the resource under the
// one kind nobody asked for.
const ResourceKindUnspecified ResourceKind = -1

func (k ResourceKind) String() string {
	switch k {
	case ResBucket:
		return "bucket"
	case ResTable:
		return "table"
	case ResQueue:
		return "queue"
	case ResRepo:
		return "repo"
	case ResSite:
		return "site"
	case ResMailbox:
		return "mailbox"
	case ResChannel:
		return "channel"
	case ResNumber:
		return "number"
	case ResMCPServer:
		return "mcp_server"
	case ResGraph:
		return "graph"
	case ResBrowserProfile:
		return "browser_profile"
	case ResDesktop:
		return "desktop"
	case ResAPI:
		return "api"
	}
	return fmt.Sprintf("unknown(%d)", int(k))
}

// ParseResourceKind maps a recorded kind back to its value. Matching is
// case-insensitive and surrounding whitespace is ignored.
//
// On failure the returned kind is ResourceKindUnspecified, never ResBucket.
func ParseResourceKind(s string) (ResourceKind, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	for _, k := range ResourceKindVocabulary() {
		if k.String() == trimmed {
			return k, true
		}
	}
	return ResourceKindUnspecified, false
}

// ResourceKindVocabulary lists every kind, in declaration order, so a parser or
// a renderer cannot silently omit one.
func ResourceKindVocabulary() []ResourceKind {
	return []ResourceKind{
		ResBucket,
		ResTable,
		ResQueue,
		ResRepo,
		ResSite,
		ResMailbox,
		ResChannel,
		ResNumber,
		ResMCPServer,
		ResGraph,
		ResAPI,
		ResBrowserProfile,
		ResDesktop,
	}
}

// Resource is one registered thing an action may touch: a bucket, a table, a
// mailbox, a repo, an API, an MCP server.
//
// A resource record is a REGISTRATION. AAES does NOT try to verify that the
// locator exists, that it is reachable, or that the data really carries the
// declared class. A locator is a claim made by an accountable human, and the
// value the registry adds is not verification: it is that every decision
// records the resource id and the data class it was taken against inside its
// own sealed intent, so a later edit to a registration cannot rewrite what a
// past action was authorised to touch. The owner is mandatory for the same
// reason -- a claim nobody is accountable for is not a registration.
type Resource struct {
	ResourceID string
	TenantID   string
	Kind       ResourceKind
	// Locator names where the resource lives: an ARN, a table name, a repo URL,
	// a mailbox address, a channel id, a phone number, an MCP server URL. It is
	// what an operator reviews; AAES never resolves it to a network call of its
	// own.
	Locator string
	// DataClass is the classification the owner declares for the data at the
	// locator. It is registered data, not observed data: AAES cannot see the
	// contents and does not pretend to.
	DataClass DataClassification
	// Owner is the accountable human. An unowned resource has nobody to review
	// it, so it is refused.
	Owner string
	// Residency is optional: "eu", "us", "on-prem" or whatever vocabulary the
	// deployment uses. AAES records the string and does not interpret it.
	Residency string
	CreatedAt time.Time
}

// Validate enforces what can be known about a resource before it is
// registered: the identifiers, the kind, the locator and the classification.
//
// It deliberately does NOT check that the locator exists, is reachable, or
// holds data of the declared class. Those are claims by the owner, and the
// registry's job is to record the claim, not to pretend to verify it. What the
// check does guarantee is that a resource with no id, no tenant, no owner, no
// locator or a kind and class AAES cannot name never reaches a decision, so no
// sealed intent can carry a dimension nobody can interpret later.
func (r Resource) Validate() error {
	if strings.TrimSpace(r.ResourceID) == "" || strings.TrimSpace(r.TenantID) == "" || strings.TrimSpace(r.Owner) == "" {
		return errf("resource %q requires ResourceID, TenantID and Owner; an unowned or unattributable resource is not a registration",
			r.ResourceID)
	}
	if _, known := ParseResourceKind(r.Kind.String()); !known {
		return errf("resource %q names an unknown kind %d; AAES refuses to govern a thing it cannot name",
			r.ResourceID, int(r.Kind))
	}
	if strings.TrimSpace(r.Locator) == "" {
		return errf("resource %q has no locator; the locator is what the owner reviews and what tells a reader where the data lives",
			r.ResourceID)
	}
	if !r.DataClass.Valid() {
		return errf("resource %q has an unknown data classification %d; a classification AAES cannot name is not one it may record as public",
			r.ResourceID, int(r.DataClass))
	}
	return nil
}

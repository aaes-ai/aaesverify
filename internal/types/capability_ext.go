package types

// CapabilityExt extends a capability with the fields the connector framework and
// the custody models need. It is a separate file so the original struct stays
// readable; the fields belong on Capability.
//
// BINDING CONVENTION (added with the full platform):
//   - Custody, SecretRefID, Inject and InjectName describe HOW the credential is
//     obtained and presented.
//   - Connector names WHICH surface is used to reach the resource.
//   - Endpoint and Method are the REGISTERED destination; a caller never names it.
//   - EffectKeyStep, when set, names the payload field that carries the caller's
//     step key, which is how a retry is recognised.
type CapabilityBinding struct {
	Custody     CustodyKind
	Connector   ConnectorKind
	SecretRefID string
	Inject      Injection
	InjectName  string
	Endpoint    string
	Method      string
	// EffectKeyStep is the payload field name carrying the caller's stable step
	// name. Empty means the connector derives one from the capability and the
	// work, which makes the action once-per-work by default.
	EffectKeyStep string
}

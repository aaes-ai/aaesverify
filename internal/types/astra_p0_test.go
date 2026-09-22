package types

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestWorkRejectsNonFiniteBudgetAndSpend(t *testing.T) {
	w := Work{WorkID: "w1", TenantID: "t1", Sponsor: "human-1", BudgetUSD: math.NaN(), State: WorkOpen}
	if err := w.Validate(); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("NaN budget: %v", err)
	}
	w.BudgetUSD = math.Inf(1)
	if err := w.Validate(); err == nil {
		t.Fatal("infinite budget was accepted")
	}
	w.BudgetUSD = 10
	if err := w.CanSpend(math.NaN(), time.Now()); err == nil {
		t.Fatal("NaN spend was accepted")
	}
}

func TestEffectKeyRejectsSeparatorInParts(t *testing.T) {
	if err := (EffectKey{WorkID: "a\x1fb", StepKey: "c"}).Validate(); err == nil {
		t.Fatal("separator in WorkID was accepted")
	}
	if err := (EffectKey{WorkID: "a", StepKey: "b\x1fc"}).Validate(); err == nil {
		t.Fatal("separator in StepKey was accepted")
	}
}

func TestActorSponsorMustMatchPrimaryManager(t *testing.T) {
	a := ActorRef{
		ActorID: "agent-1", TenantID: "t1", Kind: KindAgent, Sponsor: "alice",
		Managers:       SingleManagerSet("bob", KindHuman),
		ManagersSource: ManagerSourceSet,
	}
	if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("contradictory sponsor and manager set: %v", err)
	}
	a.Sponsor = "bob"
	if err := a.Validate(); err != nil {
		t.Fatalf("agreeing sponsor and set: %v", err)
	}
}

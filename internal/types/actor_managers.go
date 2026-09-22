package types

import "strings"

func (a ActorRef) EffectiveManagers() ManagerSet {
	if len(a.Managers) > 0 {
		return a.Managers.Copy()
	}
	if a.Kind != KindAgent || strings.TrimSpace(a.Sponsor) == "" {
		return nil
	}
	return SingleManagerSet(a.Sponsor, KindHuman)
}

func (a ActorRef) EffectiveManagerSource() ManagerSource {
	if len(a.Managers) > 0 {
		return a.ManagersSource
	}
	if strings.TrimSpace(a.Sponsor) == "" {
		return ManagerSourceLegacy
	}
	return ManagerSourceLegacy
}

func (a ActorRef) ManagedBy(actorID string) bool {
	_, ok := a.EffectiveManagers().Find(actorID)
	return ok
}

func (a ActorRef) PrimaryManager() (ManagerEntry, bool) {
	return a.EffectiveManagers().Primary()
}

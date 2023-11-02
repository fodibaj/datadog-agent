// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package workloadmeta

// Filter allows a subscriber to filter events by entity kind, event source, and
// event type.
//
// A nil filter matches all events.
type Filter struct {
	kinds                  map[Kind]struct{}
	source                 Source
	eventType              EventType
	includePauseContainers bool
}

// FilterParams are the parameters used to create a Filter
type FilterParams struct {
	Kinds                  []Kind
	Source                 Source
	EventType              EventType
	IncludePauseContainers bool
}

// NewFilter creates a new filter for subscribing to workloadmeta events.
//
// Only events for entities with one of the given kinds will be delivered.  If
// kinds is nil or empty, events for entities of any kind will be delivered.
//
// Similarly, only events for entities collected from the given source will be
// delivered, and the entities in the events will contain data only from that
// source.  For example, if source is SourceRuntime, then only events from the
// runtime will be delivered, and they will not contain any additional metadata
// from orchestrators or cluster orchestrators. Use SourceAll to collect data
// from all sources. SourceAll is the default.
//
// Only events of the given type will be delivered. Use EventTypeAll to collect
// data from all the event types. EventTypeAll is the default.
func NewFilter(filterParams *FilterParams) *Filter {
	var kindSet map[Kind]struct{}
	kinds := filterParams.Kinds
	if len(kinds) > 0 {
		kindSet = make(map[Kind]struct{})
		for _, k := range kinds {
			kindSet[k] = struct{}{}
		}
	}

	// This is enforced in the matching functions, but putting here for clarity
	if filterParams.Source == "" {
		filterParams.Source = SourceAll
	}

	return &Filter{
		kinds:                  kindSet,
		source:                 filterParams.Source,
		eventType:              filterParams.EventType,
		includePauseContainers: filterParams.IncludePauseContainers,
	}
}

// MatchKind returns true if the filter matches the passed Kind. If the filter
// is nil, or has no kinds, it always matches.
func (f *Filter) MatchKind(k Kind) bool {
	if f == nil || len(f.kinds) == 0 {
		return true
	}

	_, ok := f.kinds[k]

	return ok
}

// MatchSource returns true if the filter matches the passed source. If the
// filter is nil, or has SourceAll, it always matches.
func (f *Filter) MatchSource(source Source) bool {
	return f.Source() == SourceAll || f.Source() == source
}

// MatchEventType returns true if the filter matches the passed EventType. If
// the filter is nil, or has EventTypeAll, it always matches.
func (f *Filter) MatchEventType(eventType EventType) bool {
	return f.EventType() == EventTypeAll || f.EventType() == eventType
}

// MatchIncludePauseContainers returns true if the filter has the includePauseContainers param set to true. If the filter
// is nil, it does not match.
func (f *Filter) MatchIncludePauseContainers() bool {
	return f.IncludePauseContainer()
}

// Source returns the source this filter is filtering by. If the filter is nil,
// returns SourceAll.
func (f *Filter) Source() Source {
	if f == nil {
		return SourceAll
	}

	return f.source
}

// EventType returns the event type this filter is filtering by. If the filter
// is nil, it returns EventTypeAll.
func (f *Filter) EventType() EventType {
	if f == nil {
		return EventTypeAll
	}

	return f.eventType
}

// IncludePauseContainer returns whether the filter allows pause containers through. If the filter
// is nil, it returns false.
func (f *Filter) IncludePauseContainer() bool {
	if f == nil {
		return false
	}

	return f.includePauseContainers
}

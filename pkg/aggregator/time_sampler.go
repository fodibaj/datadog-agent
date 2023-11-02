// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package aggregator

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/cache"

	"github.com/DataDog/datadog-agent/pkg/aggregator/ckey"
	"github.com/DataDog/datadog-agent/pkg/aggregator/internal/limiter"
	"github.com/DataDog/datadog-agent/pkg/aggregator/internal/tags"
	"github.com/DataDog/datadog-agent/pkg/aggregator/internal/tags_limiter"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// SerieSignature holds the elements that allow to know whether two similar `Serie`s
// from the same bucket can be merged into one. Series must have the same contextKey.
type SerieSignature struct {
	mType      metrics.APIMetricType
	nameSuffix string
}

// TimeSamplerID is a type ID for sharded time samplers.
type TimeSamplerID int

// TimeSampler aggregates metrics by buckets of 'interval' seconds
type TimeSampler struct {
	interval                    int64
	contextResolver             *timestampContextResolver
	metricsByTimestamp          map[int64]metrics.ContextMetrics
	counterLastSampledByContext map[ckey.ContextKey]float64
	lastCutOffTime              int64
	sketchMap                   sketchMap
	interner                    *cache.KeyedInterner
	// id is a number to differentiate multiple time samplers
	// since we start running more than one with the demultiplexer introduction
	id TimeSamplerID

	// Accumulate the current retentions up to the current
	// flush, then flush out the prior retentions from there.
	retentions, priorRetentions cache.SmallRetainer
	hostname                    string
}

// NewTimeSampler returns a newly initialized TimeSampler
func NewTimeSampler(id TimeSamplerID, interval int64, tagStore *tags.Store, contextsLimiter *limiter.Limiter, tagsLimiter *tags_limiter.Limiter, hostname string,
	interner *cache.KeyedInterner) *TimeSampler {
	if interval == 0 {
		interval = bucketSize
	}

	log.Infof("Creating TimeSampler #%d", id)

	s := &TimeSampler{
		interval:                    interval,
		contextResolver:             newTimestampContextResolver(tagStore, contextsLimiter, tagsLimiter, interner),
		metricsByTimestamp:          map[int64]metrics.ContextMetrics{},
		counterLastSampledByContext: map[ckey.ContextKey]float64{},
		sketchMap:                   make(sketchMap),
		interner:                    interner,
		id:                          id,
		hostname:                    hostname,
	}

	return s
}

func (s *TimeSampler) calculateBucketStart(timestamp float64) int64 {
	return int64(timestamp) - int64(timestamp)%s.interval
}

func (s *TimeSampler) isBucketStillOpen(bucketStartTimestamp, timestamp int64) bool {
	return bucketStartTimestamp+s.interval > timestamp
}

func (s *TimeSampler) sample(metricSample *metrics.MetricSample, timestamp float64) {
	// use the timestamp provided in the sample if any
	if metricSample.Timestamp > 0 {
		timestamp = metricSample.Timestamp
	}

	// Keep track of the context
	contextKey, ok := s.contextResolver.trackContext(metricSample, timestamp)
	if !ok {
		return
	}

	bucketStart := s.calculateBucketStart(timestamp)

	switch metricSample.Mtype {
	case metrics.DistributionType:
		// Add references to the context for this distribution, and take the references for the
		// metric samples.
		refs, _ := s.contextResolver.resolver.referenceContext(contextKey)
		refs.Import(&metricSample.References)
		s.sketchMap.insert(bucketStart, contextKey, metricSample.Value, metricSample.SampleRate, &refs)

	default:
		// Save the references for the next flush.
		s.retentions.Import(&metricSample.References)
		// If it's a new bucket, initialize it
		bucketMetrics, ok := s.metricsByTimestamp[bucketStart]
		if !ok {
			bucketMetrics = metrics.MakeContextMetrics()
			s.metricsByTimestamp[bucketStart] = bucketMetrics
		}
		// Update LastSampled timestamp for counters
		if metricSample.Mtype == metrics.CounterType {
			s.counterLastSampledByContext[contextKey] = timestamp
		}

		// Add sample to bucket
		if err := bucketMetrics.AddSample(contextKey, metricSample, timestamp, s.interval, nil); err != nil {
			log.Debugf("TimeSampler #%d Ignoring sample '%s' on host '%s' and tags '%s': %s", s.id, metricSample.Name, metricSample.Host, metricSample.Tags, err)
		}
	}
}

func (s *TimeSampler) newSketchSeries(ck ckey.ContextKey, points []metrics.SketchPoint, refs cache.InternRetainer) *metrics.SketchSeries {
	ctx, _ := s.contextResolver.get(ck)
	ss := &metrics.SketchSeries{
		Interval:   s.interval,
		Points:     points,
		ContextKey: ck,
	}
	ss.Name = ctx.Name // s.interner.LoadOrStoreString(ctx.Name, cache.OriginTimeSampler+".Name", &ss.References)
	ss.Tags = ctx.Tags().Apply(func(tag string) string {
		return s.interner.LoadOrStoreString(tag, cache.OriginTimeSampler+".Tags", &ss.References)
	})
	ss.Host = s.interner.LoadOrStoreString(ctx.Host, cache.OriginTimeSampler+".Host", &ss.References)
	ss.References.Import(refs)
	return ss
}

func (s *TimeSampler) flushSeries(cutoffTime int64, series metrics.SerieSink) {
	// Map to hold the expired contexts that will need to be deleted after the flush so that we stop sending zeros
	counterContextsToDelete := map[ckey.ContextKey]struct{}{}
	contextMetricsFlusher := metrics.NewContextMetricsFlusher()

	if len(s.metricsByTimestamp) > 0 {
		for bucketTimestamp, contextMetrics := range s.metricsByTimestamp {
			// disregard when the timestamp is too recent
			if s.isBucketStillOpen(bucketTimestamp, cutoffTime) {
				continue
			}

			// Add a 0 sample to all the counters that are not expired.
			// It is ok to add 0 samples to a counter that was already sampled for real in the bucket, since it won't change its value
			s.countersSampleZeroValue(bucketTimestamp, contextMetrics, counterContextsToDelete)
			contextMetricsFlusher.Append(float64(bucketTimestamp), contextMetrics)

			delete(s.metricsByTimestamp, bucketTimestamp)
		}
	} else if s.lastCutOffTime+s.interval <= cutoffTime {
		// Even if there is no metric in this flush, recreate empty counters,
		// but only if we've passed an interval since the last flush

		contextMetrics := metrics.MakeContextMetrics()

		s.countersSampleZeroValue(cutoffTime-s.interval, contextMetrics, counterContextsToDelete)
		contextMetricsFlusher.Append(float64(cutoffTime-s.interval), contextMetrics)
	}

	// serieBySignature is reused for each call of dedupSerieBySerieSignature to avoid allocations.
	serieBySignature := make(map[SerieSignature]*metrics.Serie)
	s.flushContextMetrics(contextMetricsFlusher, func(rawSeries []*metrics.Serie) {
		// Note: rawSeries is reused at each call
		s.dedupSerieBySerieSignature(rawSeries, series, serieBySignature)
	})

	// Delete the contexts associated to an expired counter
	for context := range counterContextsToDelete {
		delete(s.counterLastSampledByContext, context)
	}
}

func (s *TimeSampler) dedupSerieBySerieSignature(
	rawSeries []*metrics.Serie,
	serieSink metrics.SerieSink,
	serieBySignature map[SerieSignature]*metrics.Serie) {

	// clear the map. Reuse serieBySignature
	for k := range serieBySignature {
		delete(serieBySignature, k)
	}

	// rawSeries have the same context key.
	for _, serie := range rawSeries {
		serieSignature := SerieSignature{serie.MType, cache.CheckDefault(serie.NameSuffix)}

		if existingSerie, ok := serieBySignature[serieSignature]; ok {
			existingSerie.Points = append(existingSerie.Points, serie.Points[0])
		} else {
			// Resolve context and populate new Serie
			context, ok := s.contextResolver.get(serie.ContextKey)
			if !ok {
				log.Errorf("TimeSampler #%d Ignoring all metrics on context key '%v': inconsistent context resolver state: the context is not tracked", s.id, serie.ContextKey)
				continue
			}
			suffix := cache.CheckDefault(serie.NameSuffix)
			serie.Name = s.interner.LoadOrStoreString(cache.CheckDefault(context.Name)+suffix,
				cache.OriginTimeSampler+".serie.Name", &serie.References)
			serie.Tags = context.Tags().Apply(func(tag string) string {
				return s.interner.LoadOrStoreString(tag, cache.OriginTimeSampler+".serie.Tags", &serie.References)
			})
			serie.Host = s.interner.LoadOrStoreString(cache.CheckDefault(context.Host), cache.OriginTimeSampler+".serie.Host",
				&serie.References)
			serie.NoIndex = context.noIndex
			serie.Interval = s.interval
			serie.Source = context.source

			serieBySignature[serieSignature] = serie
		}
	}

	for _, serie := range serieBySignature {
		serieSink.Append(serie)
	}
}

func (s *TimeSampler) flushSketches(cutoffTime int64, sketchesSink metrics.SketchesSink) {
	pointsByCtx := make(map[ckey.ContextKey][]metrics.SketchPoint)
	refsByCtx := make(map[ckey.ContextKey]cache.SmallRetainer)

	s.sketchMap.flushBefore(cutoffTime, func(ck ckey.ContextKey, p metrics.SketchPoint, r cache.InternRetainer) {
		if p.Sketch == nil {
			return
		}
		pointsByCtx[ck] = append(pointsByCtx[ck], p)
		retainer := refsByCtx[ck]
		retainer.Import(r)
		refsByCtx[ck] = retainer
	})
	for ck, points := range pointsByCtx {
		retainer := refsByCtx[ck]
		sketchesSink.Append(s.newSketchSeries(ck, points, &retainer))
	}
}

func (s *TimeSampler) flush(timestamp float64, series metrics.SerieSink, sketches metrics.SketchesSink, retainer cache.InternRetainer) {
	// Compute a limit timestamp
	cutoffTime := s.calculateBucketStart(timestamp)

	s.flushSeries(cutoffTime, series)
	s.flushSketches(cutoffTime, sketches)

	// expiring contexts
	s.contextResolver.expireContexts(timestamp-config.Datadog.GetFloat64("dogstatsd_context_expiry_seconds"),
		func(k ckey.ContextKey) bool {
			_, ok := s.counterLastSampledByContext[k]
			return ok
		})
	s.lastCutOffTime = cutoffTime

	totalContexts := s.contextResolver.length()
	aggregatorDogstatsdContexts.Set(int64(totalContexts))
	tlmDogstatsdContexts.Set(float64(totalContexts))

	byMtype := s.contextResolver.countsByMtype()
	for i, count := range byMtype {
		mtype := metrics.MetricType(i).String()
		aggregatorDogstatsdContextsByMtype[i].Set(int64(count))
		tlmDogstatsdContextsByMtype.Set(float64(count), mtype)
	}

	// Return the prior cycle's retentions.
	retainer.Import(&s.priorRetentions)
	s.priorRetentions.Import(&s.retentions)
	s.sendTelemetry(timestamp, series)
}

// flushContextMetrics flushes the contextMetrics inside contextMetricsFlusher, handles its errors,
// and call several times `callback`, each time with series with same context key
func (s *TimeSampler) flushContextMetrics(contextMetricsFlusher *metrics.ContextMetricsFlusher, callback func([]*metrics.Serie)) {
	errors := contextMetricsFlusher.FlushAndClear(callback)
	for ckey, err := range errors {
		context, ok := s.contextResolver.get(ckey)
		if !ok {
			log.Errorf("Can't resolve context of error '%s': inconsistent context resolver state: context with key '%v' is not tracked", err, ckey)
			continue
		}
		log.Infof("No value returned for dogstatsd metric '%s' on host '%s' and tags '%s': %s", context.Name, context.Host, context.Tags(), err)
	}
}

func (s *TimeSampler) countersSampleZeroValue(timestamp int64, contextMetrics metrics.ContextMetrics, counterContextsToDelete map[ckey.ContextKey]struct{}) {
	expirySeconds := config.Datadog.GetFloat64("dogstatsd_expiry_seconds")
	for counterContext, lastSampled := range s.counterLastSampledByContext {
		if expirySeconds+lastSampled > float64(timestamp) {
			sample := &metrics.MetricSample{
				Name:       "",
				Value:      0.0,
				RawValue:   "0.0",
				Mtype:      metrics.CounterType,
				Tags:       []string{},
				Host:       "",
				SampleRate: 1,
				Timestamp:  float64(timestamp),
			}
			// Add a zero value sample to the counter
			// It is ok to add a 0 sample to a counter that was already sampled in the bucket, it won't change its value
			contextMetrics.AddSample(counterContext, sample, float64(timestamp), s.interval, nil) //nolint:errcheck

			// Update the tracked context so that the contextResolver doesn't expire counter contexts too early
			// i.e. while we are still sending zeros for them
			err := s.contextResolver.updateTrackedContext(counterContext, float64(timestamp))
			if err != nil {
				log.Errorf("Error updating context: %s", err)
			}
		} else {
			// Register the context to be deleted
			counterContextsToDelete[counterContext] = struct{}{}
		}
	}
}

func (s *TimeSampler) sendTelemetry(timestamp float64, series metrics.SerieSink) {
	if !config.Datadog.GetBool("telemetry.enabled") {
		return
	}

	// If multiple samplers are used, this avoids the need to
	// aggregate the stats agent-side, and allows us to see amount of
	// tags duplication between shards.
	tags := []string{
		fmt.Sprintf("sampler_id:%d", s.id),
	}

	if config.Datadog.GetBool("telemetry.dogstatsd_origin") {
		s.contextResolver.sendOriginTelemetry(timestamp, series, s.hostname, tags)
	}

	if config.Datadog.GetBool("telemetry.dogstatsd_limiter") {
		s.contextResolver.sendLimiterTelemetry(timestamp, series, s.hostname, tags)
	}
}

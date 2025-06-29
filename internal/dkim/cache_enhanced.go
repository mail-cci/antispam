package dkim

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

// default selectors and domains used for cache warming
var (
	commonSelectors       = []string{"default", "selector1", "selector2", "mail", "dkim"}
	commonProviderDomains = []string{"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"}
)

// CacheSignatureResult caches DKIM signature verification results
func CacheSignatureResult(domain, selector string, result *types.DKIMSignatureResult, ttl time.Duration) {
	if result == nil || rdb == nil {
		return
	}

	cacheKey := fmt.Sprintf("dkim:result:%s:%s", selector, domain)

	// Create cache entry with signature result
	cacheEntry := types.DKIMCacheEntry{
		Key: types.DKIMCacheKey{
			Type:     "signature_result",
			Domain:   domain,
			Selector: selector,
			Hash:     cacheKey,
		},
		Value:      result,
		Expiration: time.Now().Add(ttl).Unix(),
		TTL:        int64(ttl.Seconds()),
		HitCount:   0,
		Size:       int64(len(fmt.Sprintf("%+v", result))),
	}

	if err := rdb.Set(context.Background(), cacheKey, cacheEntry, ttl).Err(); err != nil {
		if logger != nil {
			logger.Debug("failed to cache signature result",
				zap.String("cache_key", cacheKey),
				zap.Error(err))
		}
	} else if logger != nil {
		logger.Debug("cached signature result",
			zap.String("cache_key", cacheKey),
			zap.Bool("valid", result.Valid),
			zap.Duration("ttl", ttl))
	}
}

// GetCachedSignatureResult retrieves cached signature verification result
func GetCachedSignatureResult(domain, selector string) *types.DKIMSignatureResult {
	if rdb == nil {
		return nil
	}

	cacheKey := fmt.Sprintf("dkim:result:%s:%s", selector, domain)

	var entry types.DKIMCacheEntry
	if err := rdb.Get(context.Background(), cacheKey).Scan(&entry); err != nil {
		if performanceMonitor != nil {
			performanceMonitor.RecordCacheMiss()
		}
		return nil
	}

	if entry.Expiration < time.Now().Unix() {
		return nil
	}

	entry.HitCount++
	rdb.Set(context.Background(), cacheKey, entry, time.Duration(entry.TTL)*time.Second)

	if result, ok := entry.Value.(*types.DKIMSignatureResult); ok {
		if performanceMonitor != nil {
			performanceMonitor.RecordCacheHit()
		}
		return result
	}

	return nil
}

// PreloadCommonSelectors warms the cache for a predefined list of provider
// domains and selectors. This helps reduce DNS latency for popular services.
func PreloadCommonSelectors() {
	if rdb == nil {
		return
	}

	for _, domain := range commonProviderDomains {
		for _, selector := range commonSelectors {
			lookupDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _, _ = lookupTXTWithCache(ctx, lookupDomain)
			cancel()
		}
	}
	if logger != nil {
		logger.Info("preloaded common DKIM selectors", zap.Int("domains", len(commonProviderDomains)))
	}
}

// CacheVerificationResult stores a DKIM verification result keyed by the
// message hash. The result is serialized as JSON for portability.
func CacheVerificationResult(hash string, result *types.DKIMResult, ttl time.Duration) {
	if rdb == nil || result == nil || hash == "" {
		return
	}

	key := fmt.Sprintf("dkim:verification:%s", hash)
	data, err := json.Marshal(result)
	if err != nil {
		if logger != nil {
			logger.Debug("failed to marshal verification result", zap.Error(err))
		}
		return
	}
	if err := rdb.Set(context.Background(), key, data, ttl).Err(); err != nil {
		if logger != nil {
			logger.Debug("failed to cache verification result", zap.String("key", key), zap.Error(err))
		}
	} else if logger != nil {
		logger.Debug("cached verification result", zap.String("key", key), zap.Duration("ttl", ttl))
	}
}

// GetCachedVerificationResult retrieves a cached DKIM verification result by
// message hash. It returns nil on cache miss or decode error.
func GetCachedVerificationResult(hash string) *types.DKIMResult {
	if rdb == nil || hash == "" {
		return nil
	}

	key := fmt.Sprintf("dkim:verification:%s", hash)
	val, err := rdb.Get(context.Background(), key).Bytes()
	if err != nil {
		if err != redis.Nil && logger != nil {
			logger.Debug("verification result cache miss", zap.String("key", key), zap.Error(err))
		}
		return nil
	}

	var res types.DKIMResult
	if err := json.Unmarshal(val, &res); err != nil {
		if logger != nil {
			logger.Debug("failed to unmarshal cached verification", zap.String("key", key), zap.Error(err))
		}
		return nil
	}
	if performanceMonitor != nil {
		performanceMonitor.RecordCacheHit()
	}
	return &res
}

// PrewarmCache implements cache warming strategies
func PrewarmCache(domains []string) {
	if len(domains) == 0 {
		return
	}

	if logger != nil {
		logger.Info("starting cache prewarming",
			zap.Int("domain_count", len(domains)))
	}

	// Prewarm common selectors for each domain
	for _, domain := range domains {
		for _, selector := range commonSelectors {
			lookupDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

			// Async DNS lookup to warm cache
			go func(d string) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				_, _, _ = lookupTXTWithCache(ctx, d)
			}(lookupDomain)
		}
	}

	if logger != nil {
		logger.Info("cache prewarming initiated",
			zap.Int("total_lookups", len(domains)*len(commonSelectors)))
	}
}

// GetCacheStats returns comprehensive cache statistics
func GetCacheStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Local cache statistics
	if localCache != nil {
		localStats := localCache.GetStats()
		stats["local_cache"] = map[string]interface{}{
			"hits":        localStats.Hits,
			"misses":      localStats.Misses,
			"evictions":   localStats.Evictions,
			"total_size":  localStats.TotalSize,
			"entry_count": localStats.EntryCount,
		}
	}

	// Performance monitor statistics
	if performanceMonitor != nil {
		perfStats := performanceMonitor.GetStats()
		stats["performance"] = map[string]interface{}{
			"processing_time_us": perfStats.ProcessingTime,
			"dns_lookup_time_us": perfStats.DNSLookupTime,
			"cache_hit_rate":     perfStats.CacheHitRate,
			"parallel_workers":   perfStats.ParallelWorkers,
			"early_termination":  perfStats.EarlyTermination,
		}
	}

	return stats
}

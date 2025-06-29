package dkim

import (
	"context"
	"fmt"
	"time"

	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
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

	var cacheEntry types.DKIMCacheEntry
	if err := rdb.Get(context.Background(), cacheKey).Scan(&cacheEntry); err != nil {
		return nil
	}

	// Check expiration
	if cacheEntry.Expiration < time.Now().Unix() {
		return nil
	}

	// Update hit count
	cacheEntry.HitCount++
	rdb.Set(context.Background(), cacheKey, cacheEntry, time.Duration(cacheEntry.TTL)*time.Second)

	if result, ok := cacheEntry.Value.(*types.DKIMSignatureResult); ok {
		if logger != nil {
			logger.Debug("signature result cache hit",
				zap.String("cache_key", cacheKey),
				zap.Int64("hit_count", cacheEntry.HitCount))
		}
		return result
	}

	return nil
}

// PrewarmCache implements cache warming strategies
func PrewarmCache(domains []string) {
	if len(domains) == 0 || workerPool == nil || !workerPool.running {
		return
	}

	if logger != nil {
		logger.Info("starting cache prewarming",
			zap.Int("domain_count", len(domains)))
	}

	// Prewarm common selectors for each domain
	commonSelectors := []string{"default", "selector1", "selector2", "mail", "dkim"}

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

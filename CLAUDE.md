# CLAUDE.md

This file provides comprehensive guidance to Claude Code (claude.ai/code) when working with the antispam system.

## Project Overview

High-performance antispam email filtering system written in Go that analyzes incoming email traffic using multiple verification techniques. The system is designed to handle high volume efficiently while maintaining low latency and high accuracy.

### Key Features
- Real-time email analysis via milter protocol
- Multi-layered spam detection (SPF, DKIM, DMARC, RBL, Content Analysis)
- Redis-based caching for performance
- RESTful API for management
- Prometheus metrics for monitoring
- Feedback system for continuous improvement

## Architecture

### System Design
```
Postfix → Milter Workers → Analysis Pipeline → Decision Engine → Response
                ↓                    ↓                ↓
            Redis Cache         External APIs    Metrics/Logs
```

### Core Components

#### 1. **Milter Server** (`internal/milter/`)
- Handles incoming connections from Postfix
- Implements email parsing and MIME handling
- Manages worker pool for concurrent processing
- Handles bounce emails (empty FROM) correctly

#### 2. **Authentication Modules**
- **SPF** (`internal/spf/`): Validates sender IP authorization
    - Full RFC 7208 implementation
    - Recursive include/redirect support
    - TTL-aware caching
- **DKIM** (`internal/dkim/`): Verifies email signatures
    - Multiple signature support
    - Key caching in Redis
- **DMARC** (`internal/dmarc/`): Policy enforcement
    - Alignment checking
    - Report generation

#### 3. **Reputation Systems**
- **RBL** (`internal/rbl/`): Realtime blacklist checking
    - Parallel queries to multiple lists
    - Circuit breaker for failed services
- **SURBL** (`internal/surbl/`): URL reputation
    - Content URL extraction
    - Domain normalization
- **Lists** (`internal/lists/`): Local white/blacklists
    - Redis-based for O(1) lookups
    - Auto-whitelist functionality

#### 4. **Content Analysis**
- **Rules Engine** (`internal/rules/`): Regex pattern matching
    - Hot-reloadable rules
    - Categorized scoring
- **Statistical Analysis** (`internal/analysis/`): Content metrics
    - Character distribution
    - Language detection
    - Phishing patterns
- **Antivirus** (`internal/antivirus/`): ClamAV integration
    - Stream scanning
    - Hash caching

#### 5. **Decision Engine** (`internal/scoring/`)
- Weighted scoring system
- Per-domain thresholds
- Dynamic weight adjustment
- Feedback integration

#### 6. **API Server** (`internal/api/`)
- RESTful endpoints for management
- Metrics export
- Feedback collection
- Real-time statistics

## Commands

### Development
```bash
# Build
go build -o antispam ./cmd/antispam

# Run with custom config
./antispam -config=/path/to/config.yaml

# Run tests
go test -v ./...

# Run with race detector
go test -race ./...

# Benchmark
go test -bench=. ./...

# Test milter integration
scripts/test_milter.sh
```

### Production
```bash
# Build optimized binary
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o antispam ./cmd/antispam

# Run with systemd
sudo systemctl start antispam
sudo systemctl status antispam

# Check logs
tail -f logs/milter.log
tail -f logs/api.log
```

## Configuration

### Essential Settings
```yaml
# Performance tuning
milter:
  workers: 100          # Number of concurrent workers
  queue_size: 1000      # Buffered queue size
  timeout: 10s          # Global timeout per email

performance:
  parallel_checks: true # Run verifications in parallel
  dns_workers: 50      # DNS resolver pool size
  cache_local: true    # Enable local cache layer

# Module weights
scoring:
  weights:
    spf_fail: 5.0
    dkim_fail: 3.0
    rbl_hit: 4.0
    content_spam: 2.0
  
  thresholds:
    reject: 15.0
    quarantine: 8.0
    greylist: 5.0
```

## API Endpoints

### Management
```
GET    /api/v1/health          - Health check
GET    /api/v1/stats           - Real-time statistics
GET    /api/v1/metrics         - Prometheus metrics

# Lists management
GET    /api/v1/whitelist       - Get whitelist entries
POST   /api/v1/whitelist       - Add to whitelist
DELETE /api/v1/whitelist/:id   - Remove from whitelist

# Rules management  
GET    /api/v1/rules           - List all rules
POST   /api/v1/rules           - Create new rule
PUT    /api/v1/rules/:id       - Update rule
DELETE /api/v1/rules/:id       - Delete rule

# Feedback
POST   /api/v1/feedback        - Report spam/ham verdict
GET    /api/v1/feedback/stats  - Feedback statistics
```

## Performance Optimization

### Caching Strategy
1. **Redis Cache Layers**:
    - SPF: Cache by IP+domain (1 hour TTL)
    - DKIM: Cache public keys (4 hours TTL)
    - RBL: Cache by IP (15 min for hits, 1 hour for misses)
    - Decisions: Cache by email hash (5 minutes)

2. **Local Memory Cache**:
    - Hot whitelist entries
    - Compiled regex patterns
    - Frequent DNS lookups

### Parallel Processing
```go
// Example parallel verification
func (p *Processor) AnalyzeEmail(ctx context.Context, email *Email) *Result {
    var wg sync.WaitGroup
    results := make(chan ModuleResult, 6)
    
    // Launch parallel checks
    for _, module := range p.modules {
        wg.Add(1)
        go func(m Module) {
            defer wg.Done()
            results <- m.Check(ctx, email)
        }(module)
    }
    
    // Wait with timeout
    done := make(chan struct{})
    go func() {
        wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        // All complete
    case <-ctx.Done():
        // Timeout
    }
}
```

## Testing Guidelines

### Unit Tests
- Test each module independently
- Mock external dependencies (DNS, Redis)
- Use table-driven tests
- Cover edge cases (bounces, malformed emails)

### Integration Tests
- Use docker-compose for dependencies
- Test full email flow
- Verify scoring accuracy
- Load testing with sample corpus

### Performance Tests
```bash
# Benchmark individual modules
go test -bench=BenchmarkSPF ./internal/spf/
go test -bench=BenchmarkDKIM ./internal/dkim/

# Load test
scripts/load_test.sh 1000  # Send 1000 test emails
```

## Debugging

### Common Issues

1. **High Latency**
    - Check DNS resolver performance
    - Verify Redis connection pooling
    - Look for blocking operations
    - Review parallel processing

2. **Memory Usage**
    - Check for goroutine leaks
    - Verify email parser cleanup
    - Monitor cache sizes
    - Review worker pool sizing

3. **False Positives**
    - Review scoring weights
    - Check whitelist entries
    - Analyze feedback data
    - Verify SPF/DKIM results

### Debug Mode
```yaml
log:
  level: "debug"
  
debug:
  trace_decisions: true
  log_scores: true
  save_samples: true
```

## Code Standards

### Error Handling
```go
// Always wrap errors with context
if err != nil {
    return fmt.Errorf("spf check failed for %s: %w", domain, err)
}

// Use structured logging
logger.Error("processing failed",
    zap.String("message_id", msgID),
    zap.Error(err),
    zap.Float64("score", score))
```

### Performance Patterns
```go
// Use sync.Pool for frequently allocated objects
var emailPool = sync.Pool{
    New: func() interface{} {
        return &Email{
            headers: make(textproto.MIMEHeader),
        }
    },
}

// Preallocate slices when size is known
results := make([]Result, 0, len(modules))
```

### Concurrency
```go
// Always use context for cancellation
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// Limit concurrent operations
sem := make(chan struct{}, maxConcurrent)
for _, item := range items {
    sem <- struct{}{}
    go func(i Item) {
        defer func() { <-sem }()
        process(i)
    }(item)
}
```

## Deployment Checklist

### Pre-Production
- [ ] Configure Redis persistence
- [ ] Set up log rotation
- [ ] Configure Prometheus scraping
- [ ] Test with production-like load
- [ ] Verify all RBL/SURBL access
- [ ] Set up monitoring alerts
- [ ] Document custom rules
- [ ] Plan feedback collection

### Production
- [ ] Enable graceful shutdown
- [ ] Configure rate limiting
- [ ] Set up backup Redis
- [ ] Monitor memory usage
- [ ] Track processing latency
- [ ] Collect feedback metrics
- [ ] Regular rule updates
- [ ] Performance tuning

## Module Development

### Adding New Verification Module
```go
// 1. Define interface
type Verifier interface {
    Name() string
    Check(ctx context.Context, email *Email) (float64, error)
    Priority() int
}

// 2. Implement module
type MyVerifier struct {
    cache  *redis.Client
    config *Config
}

func (v *MyVerifier) Check(ctx context.Context, email *Email) (float64, error) {
    // Implementation
}

// 3. Register in pipeline
pipeline.Register(&MyVerifier{})
```

### Best Practices
1. Always respect context cancellation
2. Cache expensive operations
3. Fail gracefully with sensible defaults
4. Emit metrics for monitoring
5. Use structured logging
6. Write comprehensive tests
7. Document configuration options
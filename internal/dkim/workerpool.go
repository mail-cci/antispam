package dkim

import (
	"context"
	"runtime"

	"github.com/mail-cci/antispam/internal/types"
)

// verifyRequest wraps a verification task sent to the pool.
type verifyRequest struct {
	raw           []byte
	correlationID string
	resp          chan verifyResponse
}

type verifyResponse struct {
	result *types.DKIMResult
	err    error
}

// NewDKIMWorkerPool creates a worker pool with sane defaults.
func NewDKIMWorkerPool(cfg types.DKIMWorkerPoolConfig) *DKIMWorkerPool {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = runtime.NumCPU()
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = cfg.WorkerCount * 2
	}
	pool := &DKIMWorkerPool{
		config:    cfg,
		workQueue: make(chan *verifyRequest, cfg.QueueSize),
	}
	return pool
}

// Start launches worker goroutines.
func (p *DKIMWorkerPool) Start() {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.running = true
	p.mu.Unlock()

	for i := 0; i < p.config.WorkerCount; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// Stop stops all workers and waits for them to finish.
func (p *DKIMWorkerPool) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	p.cancel()
	close(p.workQueue)
	p.mu.Unlock()
	p.wg.Wait()
}

func (p *DKIMWorkerPool) worker() {
	defer p.wg.Done()
	for {
		select {
		case req, ok := <-p.workQueue:
			if !ok {
				return
			}
			if performanceMonitor != nil {
				performanceMonitor.RecordWorkerStart()
			}
			res, err := verifyInternal(req.raw, req.correlationID)
			if performanceMonitor != nil {
				performanceMonitor.RecordWorkerEnd()
				stats := performanceMonitor.GetStats()
				if res != nil {
					if res.PerformanceInfo == nil {
						res.PerformanceInfo = &types.DKIMPerformanceInfo{}
					}
					res.PerformanceInfo.ParallelWorkers = stats.ParallelWorkers
				}
			}
			req.resp <- verifyResponse{result: res, err: err}
		case <-p.ctx.Done():
			return
		}
	}
}

// Submit sends a verification task to the pool and waits for the result.
func (p *DKIMWorkerPool) Submit(raw []byte, correlationID string) (*types.DKIMResult, error) {
	req := &verifyRequest{raw: raw, correlationID: correlationID, resp: make(chan verifyResponse, 1)}
	p.workQueue <- req
	resp := <-req.resp
	return resp.result, resp.err
}

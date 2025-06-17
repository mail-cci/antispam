package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EmailProcessing = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "email_processing_total",
		Help: "Total number of processed emails",
	}, []string{"status", "sender_domain", "recipient_domain"})

	ProcessingTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "email_processing_time_seconds",
		Help:    "Time taken to process emails",
		Buckets: []float64{0.1, 0.5, 1, 2.5, 5},
	}, []string{"type"})

	APIDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "api_request_duration_seconds",
		Help:    "Duration of HTTP requests",
		Buckets: []float64{0.1, 0.5, 1, 2.5, 5},
	}, []string{"path", "method", "status"})

	DatabaseQueries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "database_queries_total",
		Help: "Total database queries",
	}, []string{"query_type", "success"})

	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "active_connections",
		Help: "Current number of active connections",
	})
	DomainsNotFound = promauto.NewCounter(prometheus.CounterOpts{
		Name: "domains_not_found_total",
		Help: "Total number of domains not found",
	})
)

func Init() {
	// Registro automático vía promauto
}

package fixtures

import "go.uber.org/zap"

func logNatsURL(log *zap.Logger, natsURL, addr string) {
	log.Info("start", zap.String("url", natsURL)) // ruleid: sgate-go-credentials-in-log
	log.Info("start", zap.String("addr", addr))   // ok: sgate-go-credentials-in-log
}

func logMaskedURL(log *zap.Logger, natsURL string) {
	log.Info("start", zap.String("url", maskURL(natsURL))) // ok: sgate-go-credentials-in-log
}

func logDSN(log *zap.Logger, dsn string) {
	log.Error("dsn", zap.String("dsn", dsn)) // ruleid: sgate-go-credentials-in-log
}

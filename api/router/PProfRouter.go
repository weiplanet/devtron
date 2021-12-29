package router

import (
	"github.com/devtron-labs/devtron/api/restHandler"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"net/http"
	"net/http/pprof"
)

type PProfRouter interface {
	initPProfRouter(router *mux.Router)
}

type PProfRouterImpl struct {
	logger                    *zap.SugaredLogger
	releaseMetricsRestHandler restHandler.ReleaseMetricsRestHandler
}

func NewPProfRouterImpl(logger *zap.SugaredLogger,
	releaseMetricsRestHandler restHandler.ReleaseMetricsRestHandler) *PProfRouterImpl {
	return &PProfRouterImpl{
		logger:                    logger,
		releaseMetricsRestHandler: releaseMetricsRestHandler,
	}
}

func (impl PProfRouterImpl) initPProfRouter(router *mux.Router) {

	router.Handle("/", http.HandlerFunc(pprof.Index))
	router.Handle("/cmdline", http.HandlerFunc(pprof.Cmdline))
	router.Handle("/profile", http.HandlerFunc(pprof.Profile))
	router.Handle("/symbol", http.HandlerFunc(pprof.Symbol))
	router.Handle("/trace", http.HandlerFunc(pprof.Trace))
	router.Handle("/goroutine", pprof.Handler("goroutine"))
	router.Handle("/threadcreate", pprof.Handler("threadcreate"))
	router.Handle("/heap", pprof.Handler("heap"))
	router.Handle("/block", pprof.Handler("block"))
	router.Handle("/mutex", pprof.Handler("mutex"))
	router.Handle("/allocs", pprof.Handler("allocs"))
}

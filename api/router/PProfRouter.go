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

	router.Handle("/pprof/", http.HandlerFunc(pprof.Index))
	router.Handle("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	router.Handle("/pprof/profile", http.HandlerFunc(pprof.Profile))
	router.Handle("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	router.Handle("/pprof/trace", http.HandlerFunc(pprof.Trace))

}

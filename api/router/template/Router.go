package template

import (
	"github.com/devtron-labs/devtron/api/restHandler/template"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type TemplatesRouter interface {
	initTemplatesRouter(router *mux.Router)
}

type TemplatesRouterImpl struct {
	handler template.TemplatesRestHandler
	logger  *zap.SugaredLogger
}

func NewTemplatesRouter(handler template.TemplatesRestHandler, logger *zap.SugaredLogger) *TemplatesRouterImpl {
	return &TemplatesRouterImpl{
		handler: handler,
		logger:  logger,
	}
}

func (t TemplatesRouterImpl) initTemplatesRouter(router *mux.Router) {
	router.Path("/app/{appId}/type/linkout").
		Methods("GET").
		HandlerFunc(t.handler.FetchLinkoutTemplatesByAppId)

	router.Path("/app/{appIds}").
		Methods("DELETE").
		HandlerFunc(t.handler.DeleteTemplatesByAppId)

	router.Path("/app/{ids}").
		Methods("DELETE").
		HandlerFunc(t.handler.DeleteTemplatesById)

	router.Path("/app/{appId}").
		Methods("GET").
		HandlerFunc(t.handler.FetchTemplatesByAppId)

	router.Path("/upsert").
		Methods("POST").
		HandlerFunc(t.handler.Save)
}
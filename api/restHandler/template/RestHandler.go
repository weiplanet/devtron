package template

import (
	"encoding/json"
	restHandler "github.com/devtron-labs/devtron/api/restHandler"
	"github.com/devtron-labs/devtron/pkg/template"
	"github.com/devtron-labs/devtron/pkg/user"
	"github.com/devtron-labs/devtron/util/rbac"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"strings"
)

type TemplatesRequest struct {
	Templates []template.TemplateBean
}

type TemplatesRestHandler interface {
	FetchTemplatesByAppId(w http.ResponseWriter, r *http.Request)
	Save(w http.ResponseWriter, r *http.Request)
	FetchLinkoutTemplatesByAppId(w http.ResponseWriter, r *http.Request)
	DeleteTemplatesById(w http.ResponseWriter, r *http.Request)
	DeleteTemplatesByAppId(w http.ResponseWriter, r *http.Request)
}

type TemplatesRestHandlerImpl struct {
	templateService template.TemplatesService
	logger          *zap.SugaredLogger
	enforcerUtil    rbac.EnforcerUtil
	enforcer        rbac.Enforcer
	userAuthService user.UserService
}

func NewTemplatesRestHandlerImpl(templatesService template.TemplatesService,
	logger *zap.SugaredLogger,
	enforcerUtil rbac.EnforcerUtil,
	enforcer rbac.Enforcer) *TemplatesRestHandlerImpl {
	return &TemplatesRestHandlerImpl{
		templateService: templatesService,
		logger:          logger,
		enforcer:        enforcer,
		enforcerUtil:    enforcerUtil,
	}
}

func (t TemplatesRestHandlerImpl) FetchTemplatesByAppId(w http.ResponseWriter, r *http.Request) {
	userId, err := t.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		t.logger.Errorw("request err, get app", "err", err, "appId", appId)
		restHandler.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	object := t.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := t.enforcer.Enforce(token, rbac.ResourceApplications, rbac.ActionUpdate, object); !ok {
		restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	templates, err := t.templateService.FetchTemplatesByAppId([]int{appId})
	if err != nil {
		t.logger.Errorw("service err, get app", "err", err, "appId", appId)
		restHandler.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	restHandler.WriteJsonResp(w, err, templates, http.StatusOK)
}

func (t TemplatesRestHandlerImpl) FetchLinkoutTemplatesByAppId(w http.ResponseWriter, r *http.Request) {
	userId, err := t.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {

	}
	token := r.Header.Get("token")
	object := t.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := t.enforcer.Enforce(token, rbac.ResourceApplications, rbac.ActionGet, object); !ok {
		restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	templates, err := t.templateService.FetchLinkoutTemplates(appId)
	if err != nil {
		t.logger.Errorw("service err, get app", "err", err, "appId", appId)
		restHandler.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	restHandler.WriteJsonResp(w, err, templates, http.StatusOK)
}

func (t TemplatesRestHandlerImpl) Save(w http.ResponseWriter, r *http.Request) {
	userId, err := t.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}

	var templates TemplatesRequest
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&templates)
	if err != nil {
		t.logger.Errorw("request err, create templates", "err", err, "create templates")
		restHandler.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	appIds := map[int]bool{}
	for _, tpl := range templates.Templates {
		if ok := appIds[tpl.AppId]; !ok {
			appIds[tpl.AppId] = true
		}
	}
	token := r.Header.Get("token")
	for appId, _ := range appIds {
		object := t.enforcerUtil.GetAppRBACNameByAppId(appId)
		if ok := t.enforcer.Enforce(token, rbac.ResourceApplications, rbac.ActionUpdate, object); !ok {
			if ok := t.enforcer.Enforce(token, rbac.ResourceApplications, rbac.ActionCreate, object); !ok {
				restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
				return
			}
		}
	}
	err = t.templateService.Save(templates.Templates)
	if err != nil {
		t.logger.Errorw("err saving, create templates", "err", err, "create templates", templates)
		restHandler.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	restHandler.WriteJsonResp(w, nil, nil, http.StatusOK)
}

func (t TemplatesRestHandlerImpl) DeleteTemplatesById(w http.ResponseWriter, r *http.Request) {
	userId, err := t.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	varIds := strings.Split(vars["ids"], ",")
	if err != nil {
		t.logger.Errorw("request err, get templated by Id", "err", err, "appId", varIds)
		restHandler.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	var ids []int
	for _, varId := range varIds {
		id, err := strconv.Atoi(varId)
		if err != nil {
			t.logger.Errorw("request err, get templates by id", "err", err, "appId", varIds)
			restHandler.WriteJsonResp(w, err, nil, http.StatusBadRequest)
			return
		}
		ids = append(ids, id)
	}
	tpls, err := t.templateService.FetchTemplates(ids)
	if err != nil {
		if err != nil {
			t.logger.Errorw("request err, get templated by Id", "err", err, "appId", varIds)
			restHandler.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
	}
	var appIds []int
	for _, tpl := range tpls {
		appIds = append(appIds, tpl.AppId)
	}
	token := r.Header.Get("token")
	for _, appId := range appIds {
		object := t.enforcerUtil.GetAppRBACNameByAppId(appId)
		if ok := t.enforcer.Enforce(token, rbac.ResourceApplications, rbac.ActionUpdate, object); !ok {
			restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
			return
		}
	}

	templates, err := t.templateService.FetchTemplatesByAppId(appIds)
	if err != nil {
		t.logger.Errorw("service err, get templated by Id", "err", err, "appId", appIds)
		restHandler.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	restHandler.WriteJsonResp(w, err, templates, http.StatusOK)
}

func (t TemplatesRestHandlerImpl) DeleteTemplatesByAppId(w http.ResponseWriter, r *http.Request) {
	userId, err := t.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	varAppIds := strings.Split(vars["appIds"], ",")
	if err != nil {
		t.logger.Errorw("request err, get templates by appId", "err", err, "appId", varAppIds)
		restHandler.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	var appIds []int
	for _, appId := range varAppIds {
		aId, err := strconv.Atoi(appId)
		if err != nil {
			t.logger.Errorw("request err, get template by appId", "err", err, "appId", varAppIds)
			restHandler.WriteJsonResp(w, err, nil, http.StatusBadRequest)
			return
		}
		appIds = append(appIds, aId)
	}
	token := r.Header.Get("token")
	for _, appId := range appIds {
		object := t.enforcerUtil.GetAppRBACNameByAppId(appId)
		if ok := t.enforcer.Enforce(token, rbac.ResourceApplications, rbac.ActionUpdate, object); !ok {
			restHandler.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
			return
		}
	}

	templates, err := t.templateService.FetchTemplatesByAppId(appIds)
	if err != nil {
		t.logger.Errorw("service err, get templates by appId", "err", err, "appId", appIds)
		restHandler.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	restHandler.WriteJsonResp(w, err, templates, http.StatusOK)
}

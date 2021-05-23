package template

import (
	"fmt"
	"github.com/devtron-labs/devtron/internal/sql/repository/template"
	"go.uber.org/zap"
	"strings"
)

type TemplateBean struct {
	Id           int    `json:"id"`
	AppId        int    `json:"app_id"`
	EnvId        int    `json:"env_id"`
	ClusterId    int    `json:"cluster_id"`
	Template     string `json:"template"`
	TemplateType string `json:"template_type"`
	Type         int    `json:"type"`
	Active       bool   `json:"active"`
}

type TemplatesService interface {
	FetchLinkoutTemplates(appId int) ([]TemplateBean, error)
	FetchTemplatesByAppId(appIds []int) ([]TemplateBean, error)
	FetchTemplates(ids []int) ([]TemplateBean, error)
	Save(templates []TemplateBean) error
	Delete(ids []int) error
	DeleteByAppId(appIds []int) error
}

type TemplatesServiceImpl struct {
	templateRepository template.TemplatesRepository
	logger             *zap.SugaredLogger
}

func NewTemplatesServiceImpl(templateRepository template.TemplatesRepository, logger *zap.SugaredLogger) *TemplatesServiceImpl {
	return &TemplatesServiceImpl{
		templateRepository: templateRepository,
		logger:             logger,
	}
}

func (t TemplatesServiceImpl) FetchTemplates(ids []int) ([]TemplateBean, error) {
	templates, err := t.templateRepository.Find(ids)
	if err != nil {
		return make([]TemplateBean, 0), err
	}
	var templatesBeans []TemplateBean
	for _, tpl := range templates {
		templatesBeans = append(templatesBeans, toTemplateBean(tpl))
	}
	return templatesBeans, nil
}

func (t TemplatesServiceImpl) FetchTemplatesByAppId(appIds []int) ([]TemplateBean, error) {
	templates, err := t.templateRepository.FindByAppId(appIds)
	if err != nil {
		return make([]TemplateBean, 0), err
	}
	var templatesBeans []TemplateBean
	for _, tpl := range templates {
		templatesBeans = append(templatesBeans, toTemplateBean(tpl))
	}
	return templatesBeans, nil
}

func (t TemplatesServiceImpl) FetchLinkoutTemplates(appId int) ([]TemplateBean, error) {
	templates, err := t.templateRepository.FindByAppIdAndType(appId, template.LinkoutType)
	if err != nil {
		return make([]TemplateBean, 0), err
	}
	var linkouts []TemplateBean
	for _, tpl := range templates {
		linkouts = append(linkouts, toTemplateBean(tpl))
	}
	return linkouts, nil
}

func (t TemplatesServiceImpl) Save(templates []TemplateBean) error {
	var templateModelsForSave []template.Templates
	var templateModelsForUpdate []template.Templates
	for _, tplBean := range templates {
		if tplBean.Id == 0 {
			templateModelsForSave = append(templateModelsForSave, toTemplateModel(tplBean))
		} else {
			templateModelsForUpdate = append(templateModelsForUpdate, toTemplateModel(tplBean))
		}

	}
	err := t.templateRepository.Save(templateModelsForSave)
	err2 := t.templateRepository.Update(templateModelsForUpdate)
	var errs []string
	if err != nil {
		errs = append(errs, err.Error())
	}
	if err2 != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf(strings.Join(errs, ","))
}

func (t TemplatesServiceImpl) Delete(ids []int) error {
	return t.templateRepository.Delete(ids)
}

func (t TemplatesServiceImpl) DeleteByAppId(appIds []int) error {
	return t.templateRepository.DeleteByAppId(appIds)
}

func toTemplateBean(templates template.Templates) TemplateBean {
	return TemplateBean{
		Id:           templates.Id,
		AppId:        templates.AppId,
		EnvId:        templates.EnvId,
		ClusterId:    templates.ClusterId,
		Template:     templates.Template,
		TemplateType: templates.TemplateType,
		Type:         templates.Type,
		Active:       templates.Active,
	}
}

func toTemplateModel(templates TemplateBean) template.Templates {
	return template.Templates{
		Id:           templates.Id,
		AppId:        templates.AppId,
		EnvId:        templates.EnvId,
		ClusterId:    templates.ClusterId,
		Template:     templates.Template,
		TemplateType: templates.TemplateType,
		Type:         templates.Type,
		Active:       templates.Active,
	}
}

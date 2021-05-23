package template

import (
	"github.com/devtron-labs/devtron/internal/sql/models"
	"github.com/go-pg/pg"
)

const LinkoutType = 1

type Templates struct {
	tableName    struct{} `sql:"templates" pg:",discard_unknown_columns"`
	Id           int      `sql:"id,pk"`
	AppId        int      `sql:"app_id"`
	EnvId        int      `sql:"env_id"`
	ClusterId    int      `sql:"cluster_id"`
	Template     string   `sql:"template"`
	TemplateType string   `sql:"template_type"`
	Type         int      `sql:"type"`
	Active       bool     `sql:"active"`
	models.AuditLog
}

type TemplatesRepository interface {
	Find(ids []int) ([]Templates, error)
	FindByAppId(appIds []int) ([]Templates, error)
	FindByAppIdAndType(appId int, templateType int) ([]Templates, error)
	Save(templates []Templates) error
	Update(templates []Templates) error
	DeleteByAppId(appIds []int) error
	Delete(ids []int) error
}

func (t TemplatesRepositoryImpl) Update(templates []Templates) error {
	_, err := t.dbConnection.Model(&templates).WherePK().Update()
	return err
}

func (t TemplatesRepositoryImpl) Find(ids []int) ([]Templates, error) {
	var templates []Templates
	err := t.dbConnection.Model(&templates).
		Column("templates.*").
		Where("id IN (?)", ids).
		Where("active", true).
		Select()
	return templates, err
}

func (t TemplatesRepositoryImpl) FindByAppId(appIds []int) ([]Templates, error) {
	var templates []Templates
	err := t.dbConnection.Model(&templates).
		Column("templates.*").
		Where("app_id IN (?)", appIds).
		Where("active", true).
		Select()
	return templates, err
}

func (t TemplatesRepositoryImpl) FindByAppIdAndType(appId int, templateType int) ([]Templates, error) {
	var templates []Templates
	err := t.dbConnection.Model(&templates).
		Column("templates.*").
		Where("app_id = ?", appId).
		Where("type = ?", 1).
		Where("active", true).
		Select()
	return templates, err
}

func (t TemplatesRepositoryImpl) Save(templates []Templates) error {
	_, err := t.dbConnection.Model(&templates).Insert()
	return err
}

type TemplatesRepositoryImpl struct {
	dbConnection *pg.DB
}

func (t TemplatesRepositoryImpl) DeleteByAppId(appIds []int) error {
	_, err := t.dbConnection.Model((*Templates)(nil)).Where("app_id IN (?)", appIds).Delete()
	return err
}

func (t TemplatesRepositoryImpl) Delete(ids []int) error {
	var templates []Templates
	for _, id := range ids {
		templates = append(templates, Templates{Id: id})
	}
	_, err := t.dbConnection.Model(&templates).WherePK().Delete()
	return err
}



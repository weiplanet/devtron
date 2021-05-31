package rbac

import (
	"fmt"
	"github.com/casbin/casbin"
	"go.uber.org/zap"
	"testing"
)

func TestEnforcerImpl_enforceByEmail_applicationAccess_cicdpipeline_create_ForManager(t *testing.T) {

	type fields struct {
		Enforcer       *casbin.Enforcer
		logger         *zap.SugaredLogger
	}
	type args struct {
		vals []interface{}
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "manager/all - create ci/cd pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionCreate, "dev/application"})},
			want: true,
		},
		{
			name: "manager/specific - create ci/cd pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionCreate, "dev/application"})},
			want: true,
		},
		{
			name: "manager/specific - create ci/cd pipeline negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionCreate, "dev/applications"})},
			want: false,
		},
		{
			name: "manager/specific - create cd environment pipeline negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionCreate, "demo-devtron/applications"})},
			want: false,
		},
		{
			name: "manager/specific - create cd environment pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionCreate, "demo-devtron/application"})},
			want: true,
		},
		{
			name: "manager/all - create cd environment pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionCreate, "demo-devtron/applications"})},
			want: true,
		},
		{
			name: "manager/all - update ci/cd pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionUpdate, "dev/application"})},
			want: true,
		},
		{
			name: "manager/specific - update ci/cd pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionUpdate, "dev/application"})},
			want: true,
		},
		{
			name: "manager/specific - update ci/cd pipeline negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionUpdate, "dev/applications"})},
			want: false,
		},
		{
			name: "manager/specific - update cd environment pipeline negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionUpdate, "demo-devtron/applications"})},
			want: false,
		},
		{
			name: "manager/specific - update cd environment pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionUpdate, "demo-devtron/application"})},
			want: true,
		},
		{
			name: "manager/all - update cd environment pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionUpdate, "demo-devtron/applications"})},
			want: true,
		},
		{
			name: "manager/all - get ci/cd pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionGet, "dev/application"})},
			want: true,
		},
		{
			name: "manager/specific - get ci/cd pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionGet, "dev/application"})},
			want: true,
		},
		{
			name: "manager/specific - get ci/cd pipeline negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceApplications, ActionGet, "dev/applications"})},
			want: false,
		},
		{
			name: "manager/specific - get cd environment pipeline negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionGet, "demo-devtron/applications"})},
			want: false,
		},
		{
			name: "manager/specific - get cd environment pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "application", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_application"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionGet, "demo-devtron/application"})},
			want: true,
		},
		{
			name: "manager/all - get cd environment pipeline",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceEnvironment, ActionGet, "demo-devtron/applications"})},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EnforcerImpl{
				Enforcer:       tt.fields.Enforcer,
				logger:         tt.fields.logger,
			}
			//fmt.Println("#########")
			//fmt.Println(tt.fields.Enforcer.GetPolicy())
			//fmt.Println(tt.fields.Enforcer.GetGroupingPolicy())
			//fmt.Println("#########")
			if got := e.enforceByEmail(tt.fields.Enforcer, tt.args.vals...); got != tt.want {
				fmt.Println(tt.fields.Enforcer.GetPolicy())
				t.Errorf("enforceByEmail() = %v, want %v", got, tt.want)
			}
			tt.fields.Enforcer = nil
		})
	}
}

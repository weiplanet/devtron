package rbac

import (
	"fmt"
	"github.com/argoproj/argo-cd/util/session"
	"github.com/casbin/casbin"
	"go.uber.org/zap"
	"testing"
)

func TestEnforcerImpl_enforceByEmail_groupAccess_ForManager(t *testing.T) {
	type fields struct {
		Enforcer       *casbin.Enforcer
		SessionManager *session.SessionManager
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
			name: "manager/application - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: true,
		},
		{
			name: "manager/application - create group negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev1"})},
			want: false,
		},
		{
			name: "manager/all - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: true,
		},
		{
			name: "manager/all - create group negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev1"})},
			want: false,
		},
		{
			name: "manager/all - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: true,
		},
		{
			name: "manager/all - update group negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev1"})},
			want: false,
		},
		{
			name: "manager/application - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: true,
		},
		{
			name: "manager/application - update group negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev1"})},
			want: false,
		},
		{
			name: "manager/all - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: true,
		},
		{
			name: "manager/application - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: true,
		},
		{
			name: "manager/application - get group negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev1"})},
			want: false,
		},
		{
			name: "manager/all - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: true,
		},
		{
			name: "manager/application - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: true,
		},
		{
			name: "manager/application - delete group negative",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev1"})},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EnforcerImpl{
				Enforcer:       tt.fields.Enforcer,
				SessionManager: tt.fields.SessionManager,
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

func TestEnforcerImpl_enforceByEmail_groupAccess_ForAdmin(t *testing.T) {
	type fields struct {
		Enforcer       *casbin.Enforcer
		SessionManager *session.SessionManager
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
			name: "admin/application - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "admin/all - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "admin/all - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: false,
		},
		{
			name: "admin/application - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: false,
		},
		{
			name: "admin/all - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: false,
		},
		{
			name: "admin/application - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: false,
		},
		{
			name: "admin/all - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: false,
		},
		{
			name: "admin/application - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:admin_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EnforcerImpl{
				Enforcer:       tt.fields.Enforcer,
				SessionManager: tt.fields.SessionManager,
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


func TestEnforcerImpl_enforceByEmail_groupAccess_ForTrigger(t *testing.T) {
	type fields struct {
		Enforcer       *casbin.Enforcer
		SessionManager *session.SessionManager
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
			name: "trigger/application - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "trigger/all - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "trigger/all - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: false,
		},
		{
			name: "trigger/application - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: false,
		},
		{
			name: "trigger/all - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: false,
		},
		{
			name: "trigger/application - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: false,
		},
		{
			name: "trigger/all - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: false,
		},
		{
			name: "trigger/application - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EnforcerImpl{
				Enforcer:       tt.fields.Enforcer,
				SessionManager: tt.fields.SessionManager,
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


func TestEnforcerImpl_enforceByEmail_groupAccess_ForView(t *testing.T) {
	type fields struct {
		Enforcer       *casbin.Enforcer
		SessionManager *session.SessionManager
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
			name: "view/application - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "view/all - create group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "view/all - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: false,
		},
		{
			name: "view/application - update group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: false,
		},
		{
			name: "view/all - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: false,
		},
		{
			name: "view/application - get group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: false,
		},
		{
			name: "view/all - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: false,
		},
		{
			name: "view/application - delete group",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{{"g", "abc@abc.com", "role:view_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EnforcerImpl{
				Enforcer:       tt.fields.Enforcer,
				SessionManager: tt.fields.SessionManager,
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
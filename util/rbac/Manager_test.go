package rbac

import (
	"fmt"
	"github.com/argoproj/argo-cd/util/session"
	"github.com/casbin/casbin"
	"go.uber.org/zap"
	"testing"
)

func TestEnforcerImpl_enforceByEmail_ForManager(t *testing.T) {
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
			name: "test user create access with access to specific application",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: true,
		},
		{
			name: "test user create access with access to all applications",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: true,
		},
		{
			name: "test user update access with access to all application",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: true,
		},
		{
			name: "test user update access with access to specifc application",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionUpdate, "dev"})},
			want: true,
		},
		{
			name: "test user get access with access to all application",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: true,
		},
		{
			name: "test user get access with access to specifc application",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionGet, "dev"})},
			want: true,
		},
		{
			name: "test user delete access with access to all application",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: true,
		},
		{
			name: "test user delete access with access to specifc application",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionDelete, "dev"})},
			want: true,
		},
		{
			name: "negative test user create access with access to specific application - admin",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:admin_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "negative test user create access with access to specific application - trigger",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:trigger_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: false,
		},
		{
			name: "negative test user create access with access to specific application - view",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "devtron", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:view_dev_demo-devtron_devtron"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
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

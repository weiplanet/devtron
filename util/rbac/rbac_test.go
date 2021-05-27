package rbac

import (
	"fmt"
	"github.com/argoproj/argo-cd/util/session"
	"github.com/casbin/casbin"
	jsonadapter "github.com/casbin/json-adapter"
	"github.com/devtron-labs/devtron/api/bean"
	"go.uber.org/zap"
	"strings"
	"testing"
)

func TestEnforcerImpl_enforceByEmail(t *testing.T) {
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
			name: "basic test",
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, "dev", "", "demo-devtron")
					addPolicies(e, [][]string{[]string{"g", "abc@abc.com", "role:manager_dev_devtron-demo_"}})
					return e
				}(),
				logger:   &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{"abc@abc.com", ResourceUser, ActionCreate, "dev"})},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EnforcerImpl{
				Enforcer:       tt.fields.Enforcer,
				SessionManager: tt.fields.SessionManager,
				logger:         tt.fields.logger,
			}
			if got := e.enforceByEmail(tt.fields.Enforcer, tt.args.vals...); got != tt.want {
				//fmt.Println(tt.fields.Enforcer.GetPolicy())
				//fmt.Println(tt.fields.Enforcer.GetGroupingPolicy())
				t.Errorf("enforceByEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newEnforcer() *casbin.Enforcer {
	var b []byte
	a := jsonadapter.NewAdapter(&b)
	enforcer := casbin.NewEnforcer("../../auth_model.conf", a, true)
	//addPolicies(enforcer, policies)
	return enforcer
}

func addPolicies(enforcer *casbin.Enforcer, policies [][]string) {
	enforcer.LoadPolicy()
	for _, policy := range policies {
		if strings.EqualFold(policy[0], "p") {
			enforcer.AddPolicy(policy[1], policy[2], policy[3], policy[4], "allow")
		} else if strings.EqualFold(policy[0], "g") {
			enforcer.AddGroupingPolicy(policy[1], policy[2])
		}
	}
	enforcer.SavePolicy()
	enforcer.LoadPolicy()
}

func getMangerPolicies() [][]string {
	return [][]string{
		[]string{"p", "role:manager_dev_devtron-demo_", "applications", "*", "dev/*"},
		[]string{"p", "role:manager_dev_devtron-demo_", "environment", "*", "devtron-demo/*"},
		[]string{"p", "role:manager_dev_devtron-demo_", "team", "*", "dev"},
		[]string{"p", "role:manager_dev_devtron-demo_", "user", "*", "dev"},
		[]string{"p", "role:manager_dev_devtron-demo_", "notification", "*", "dev"},
		[]string{"p", "role:manager_dev_devtron-demo_", "global-environment", "*", "devtron-demo"},
		[]string{"g", "abc@abc.com", "role:manager_dev_devtron-demo_"},
	}
}

func toInterface(input []string) []interface{} {
	out := make([]interface{}, len(input))
	for index, in := range input {
		out[index] = in
	}
	return out
}

func applyAllDefaultPolicies(enforcer *casbin.Enforcer, team, entity, env string) {
	policies, err := GenerateDefaultPolicies(team, entity, env)
	if err != nil {
		panic(err)
	}
	for _, policy := range policies {
		applyPolicies(enforcer, policy)
	}
}

func applyPolicies(enforcer *casbin.Enforcer, request bean.PolicyRequest) {
	for _, p := range request.Data {
		if strings.ToLower(string(p.Type)) == "p" && p.Sub != "" && p.Res != "" && p.Act != "" && p.Obj != "" {
			sub := strings.ToLower(string(p.Sub))
			res := strings.ToLower(string(p.Res))
			act := strings.ToLower(string(p.Act))
			obj := strings.ToLower(string(p.Obj))
			success := enforcer.AddPolicy([]string{sub, res, act, obj, "allow"})
			if !success {
				panic(fmt.Errorf("error adding %v\n", p))
			}
		} else if strings.ToLower(string(p.Type)) == "g" && p.Sub != "" && p.Obj != "" {
			sub := strings.ToLower(string(p.Sub))
			obj := strings.ToLower(string(p.Obj))
			success := enforcer.AddGroupingPolicy([]string{sub, obj})
			if !success {
				panic(fmt.Errorf("error adding %v\n", p))
			}
		}
	}
	enforcer.SavePolicy()
	enforcer.LoadPolicy()
}
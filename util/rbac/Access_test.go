package rbac

import (
	"encoding/csv"
	"fmt"
	"github.com/argoproj/argo-cd/util/session"
	"github.com/casbin/casbin"
	"go.uber.org/zap"
	"io"
	"log"
	"os"
	"testing"
)

func TestEnforcerImpl_enforceByEmail_groupAccess_For_Manager(t *testing.T) {
	type fields struct {
		Enforcer       *casbin.Enforcer
		SessionManager *session.SessionManager
		logger         *zap.SugaredLogger
	}
	type args struct {
		vals []interface{}
	}
	type test struct {
		name   string
		fields fields
		args   args
		want   bool
	}
	csvfile, err := os.Open("Access_test.csv")
	if err != nil {
		log.Fatalln("Couldn't open the csv file", err)
	}
	r := csv.NewReader(csvfile)
	var tests []test
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		rand := test{name: record[0],
			fields: fields{
				Enforcer: func() *casbin.Enforcer {
					e := newEnforcer()
					applyAllDefaultPolicies(e, record[1], record[2], record[3])
					addPolicies(e, [][]string{{record[4], record[5], record[6]}})
					return e
				}(),
				logger: &zap.SugaredLogger{},
			},
			args: args{vals: toInterface([]string{record[7], record[8], record[9], record[10]})},
			want: record[11] == "true",
		}
		tests = append(tests, rand)
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

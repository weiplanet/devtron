package rbac

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/devtron-labs/devtron/api/bean"
	"text/template"
)

type resources struct {
	Team       string
	EntityName string
	Env        string
}

func defaultValue(input string) string {
	if len(input) > 0 {
		return input
	}
	return "*"
}

var fm = template.FuncMap{
	"defaultValue": defaultValue,
}

func GenerateDefaultPolicies(team string, entityName string, env string) ([]bean.PolicyRequest, error) {
	data := resources{
		Team:       team,
		EntityName: entityName,
		Env:        env,
	}

	policyTemplates := make([]string, 4)

	//manager
	policyTemplates[0] = "{\r\n    \"data\": [\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:manager_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"applications\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{defaultValue .Team}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:manager_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"environment\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{defaultValue .Env}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:manager_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"team\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{.Team}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:manager_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"user\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{.Team}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:manager_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"notification\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{.Team}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:manager_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"global-environment\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{.Env}}\"\r\n        }\r\n    ]\r\n}"
	//admin
	policyTemplates[1] = "{\r\n    \"data\": [\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:admin_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"applications\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{defaultValue .Team}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:admin_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"environment\",\r\n            \"act\": \"*\",\r\n            \"obj\": \"{{defaultValue .Env}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:admin_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"team\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{.Team}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:admin_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"global-environment\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{.Env}}\"\r\n        }\r\n    ]\r\n}"
	//trigger
	policyTemplates[2] = "{\r\n    \"data\": [\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:trigger_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"applications\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{defaultValue .Team}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:trigger_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"applications\",\r\n            \"act\": \"trigger\",\r\n            \"obj\": \"{{defaultValue .Team}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:trigger_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"environment\",\r\n            \"act\": \"trigger\",\r\n            \"obj\": \"{{defaultValue .Env}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:trigger_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"environment\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{defaultValue .Env}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:trigger_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"global-environment\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{.Env}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:trigger_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"team\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{.Team}}\"\r\n        }\r\n    ]\r\n}"
	//view
	policyTemplates[3] = "{\r\n    \"data\": [\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:view_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"applications\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{defaultValue .Team}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:view_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"environment\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{defaultValue .Env}}/{{defaultValue .EntityName}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:view_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"global-environment\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{.Env}}\"\r\n        },\r\n        {\r\n            \"type\": \"p\",\r\n            \"sub\": \"role:view_{{.Team}}_{{.Env}}_{{.EntityName}}\",\r\n            \"res\": \"team\",\r\n            \"act\": \"get\",\r\n            \"obj\": \"{{.Team}}\"\r\n        }\r\n    ]\r\n}"

	var policies []bean.PolicyRequest
	for _, v := range policyTemplates {
		tptl, err1 := template.New("policies").Funcs(fm).Parse(v)
		if err1 != nil {
			return make([]bean.PolicyRequest, 0), err1
		}
		var out bytes.Buffer
		err1 = tptl.Execute(&out, data);
		if err1 != nil {
			return make([]bean.PolicyRequest, 0), err1
		}
		fmt.Println(out.String())
		var policy bean.PolicyRequest
		err := json.Unmarshal(out.Bytes(), &policy)
		if err != nil {
			fmt.Printf("decode policy err %v for %s\nr", err, v)
			return []bean.PolicyRequest{}, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

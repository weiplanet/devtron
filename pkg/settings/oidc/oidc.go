package oidc

type Claim struct {
	Essential            bool
	Value                string
	Values               []string
}

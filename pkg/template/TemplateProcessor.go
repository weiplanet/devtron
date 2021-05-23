package template

import (
	"bytes"
	"regexp"
	"strings"
	"text/template"
)

func Regex(variable, pattern string, index int) string {
	regEx, err := regexp.Compile(pattern)
	if err != nil {
		return err.Error()
	}
	match := regEx.FindStringSubmatch(variable)
	if len(match) < index+1 {
		return ""
	}
	return match[index]
}

func Split(variable, sep string, index int) string {
	parts := strings.Split(variable, sep)
	if len(parts) < index+1 {
		return "out of bound index"
	}
	return parts[index]
}

var functions = template.FuncMap{
	"split": Split,
	"regex": Regex,
}

func ApplyTemplate(t string, data LinkoutData) string {
	tpl, err := template.New("url").Funcs(functions).Parse(t)
	if err != nil {
		return err.Error()
	}
	var out bytes.Buffer
	err = tpl.Execute(&out, data)
	if err != nil {
		return err.Error()
	}
	return out.String()
}

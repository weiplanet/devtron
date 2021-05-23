package template

import "testing"

func TestApplyTemplate(t *testing.T) {
	type args struct {
		t    string
		data LinkoutData
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "url without function",
			args: args{
				t:    "https://www.example.com/{{ .ContainerName }}/{{ .Namespace  }}",
				data: LinkoutData{ContainerName: "test", Namespace: "kube-system"},
			},
			want: "https://www.example.com/test/kube-system",
		},
		{
			name: "url with function",
			args: args{
				t:    `https://www.example.com/{{ split .ContainerName "-" 1}}/{{ regex .Namespace "string(.*)ing" 1 }}`,
				data: LinkoutData{ContainerName: "test-abc-2", Namespace: "stringmatching"},
			},
			want: "https://www.example.com/abc/match",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ApplyTemplate(tt.args.t, tt.args.data); got != tt.want {
				t.Errorf("ApplyTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}

package jwtmodels

import (
	"encoding/json"
	"testing"

	"github.com/music-tribe/azadjwtvalidation/internal/logger"
)

func TestClaims_IsValidForRole(t *testing.T) {
	l := logger.NewStdLog("warn")
	type fields struct {
		Iat   json.Number
		Exp   json.Number
		Iss   string
		Aud   string
		Sub   string
		Roles []string
	}
	type args struct {
		configRole string
		l          logger.Logger
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "expect valid for role Test.Role.1",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				configRole: "Test.Role.1",
				l:          l,
			},
			want: true,
		},
		{
			name: "expect invalid for role Test.Role.3",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				configRole: "Test.Role.3",
				l:          l,
			},
			want: false,
		},
		{
			name: "expect invalid for empty config role",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				configRole: "",
				l:          l,
			},
			want: false,
		},
		{
			name: "expect valid for empty config role and empty claim roles",
			fields: fields{
				Roles: []string{},
			},
			args: args{
				configRole: "",
				l:          l,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{
				Iat:   tt.fields.Iat,
				Exp:   tt.fields.Exp,
				Iss:   tt.fields.Iss,
				Aud:   tt.fields.Aud,
				Sub:   tt.fields.Sub,
				Roles: tt.fields.Roles,
			}
			if got := claims.IsValidForRole(tt.args.configRole, tt.args.l); got != tt.want {
				t.Errorf("Claims.IsValidForRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

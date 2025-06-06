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

func TestClaims_ValidateRoles(t *testing.T) {
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
		configRoles         []string
		configMatchAllRoles bool
		l                   logger.Logger
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "expect valid if no config roles",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				configRoles:         []string{},
				configMatchAllRoles: false,
				l:                   l,
			},
			wantErr: false,
		},
		{
			name: "expect valid if we match one config role",
			fields: fields{
				Roles: []string{"Test.Role.1"},
			},
			args: args{
				configRoles:         []string{"Test.Role.1"},
				configMatchAllRoles: false,
				l:                   l,
			},
			wantErr: false,
		},
		{
			name: "expect valid if we match one config role, configMatchAllRoles is false",
			fields: fields{
				Roles: []string{"Test.Role.1"},
			},
			args: args{
				configRoles:         []string{"Test.Role.1", "Test.Role.2"},
				configMatchAllRoles: false,
				l:                   l,
			},
			wantErr: false,
		},
		{
			name: "expect invalid if we match only one config role but configMatchAllRoles is true",
			fields: fields{
				Roles: []string{"Test.Role.1"},
			},
			args: args{
				configRoles:         []string{"Test.Role.1", "Test.Role.2"},
				configMatchAllRoles: true,
				l:                   l,
			},
			wantErr: true,
		},
		{
			name: "expect invalid if we have no roles but we have configRoles set",
			fields: fields{
				Roles: []string{},
			},
			args: args{
				configRoles:         []string{"Test.Role.1", "Test.Role.2"},
				configMatchAllRoles: true,
				l:                   l,
			},
			wantErr: true,
		},
		{
			name: "expect vailid if we have no roles and no configRoles set",
			fields: fields{
				Roles: []string{},
			},
			args: args{
				configRoles:         []string{},
				configMatchAllRoles: true,
				l:                   l,
			},
			wantErr: false,
		},
		{
			name:   "expect invalid if our roles are nil and we have configRoles",
			fields: fields{},
			args: args{
				configRoles:         []string{"Test.Role.1", "Test.Role.2"},
				configMatchAllRoles: false,
				l:                   l,
			},
			wantErr: true,
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
			if err := claims.ValidateRoles(tt.args.configRoles, tt.args.configMatchAllRoles, tt.args.l); (err != nil) != tt.wantErr {
				t.Errorf("Claims.ValidateRoles() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

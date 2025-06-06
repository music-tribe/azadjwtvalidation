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
		allowedRole string
		l           logger.Logger
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
				allowedRole: "Test.Role.1",
				l:           l,
			},
			want: true,
		},
		{
			name: "expect invalid for role Test.Role.3",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				allowedRole: "Test.Role.3",
				l:           l,
			},
			want: false,
		},
		{
			name: "expect invalid for empty allowed role",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				allowedRole: "",
				l:           l,
			},
			want: false,
		},
		{
			name: "expect valid for empty allowed role and empty claim roles",
			fields: fields{
				Roles: []string{},
			},
			args: args{
				allowedRole: "",
				l:           l,
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
			if got := claims.IsValidForRole(tt.args.allowedRole, tt.args.l); got != tt.want {
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
		allowedRoles  []string
		matchAllRoles bool
		l             logger.Logger
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "expect valid if no allowed roles",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				allowedRoles:  []string{},
				matchAllRoles: false,
				l:             l,
			},
			wantErr: false,
		},
		{
			name: "expect valid if we match one allowed role",
			fields: fields{
				Roles: []string{"Test.Role.1"},
			},
			args: args{
				allowedRoles:  []string{"Test.Role.1"},
				matchAllRoles: false,
				l:             l,
			},
			wantErr: false,
		},
		{
			name: "expect valid if we match one allowed role, matchAllRoles is false",
			fields: fields{
				Roles: []string{"Test.Role.1"},
			},
			args: args{
				allowedRoles:  []string{"Test.Role.1", "Test.Role.2"},
				matchAllRoles: false,
				l:             l,
			},
			wantErr: false,
		},
		{
			name: "expect invalid if we match only one allowed role but matchAllRoles is true",
			fields: fields{
				Roles: []string{"Test.Role.1"},
			},
			args: args{
				allowedRoles:  []string{"Test.Role.1", "Test.Role.2"},
				matchAllRoles: true,
				l:             l,
			},
			wantErr: true,
		},
		{
			name: "expect invalid if we have no roles but we have allowedRoles set",
			fields: fields{
				Roles: []string{},
			},
			args: args{
				allowedRoles:  []string{"Test.Role.1", "Test.Role.2"},
				matchAllRoles: true,
				l:             l,
			},
			wantErr: true,
		},
		{
			name: "expect vailid if we have no roles and no allowedRoles set",
			fields: fields{
				Roles: []string{},
			},
			args: args{
				allowedRoles:  []string{},
				matchAllRoles: true,
				l:             l,
			},
			wantErr: false,
		},
		{
			name:   "expect invalid if our roles are nil and we have allowedRoles",
			fields: fields{},
			args: args{
				allowedRoles:  []string{"Test.Role.1", "Test.Role.2"},
				matchAllRoles: false,
				l:             l,
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
			if err := claims.ValidateRoles(tt.args.allowedRoles, tt.args.matchAllRoles, tt.args.l); (err != nil) != tt.wantErr {
				t.Errorf("Claims.ValidateRoles() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

package jwtmodels

import (
	"encoding/json"
	"io"
	"log"
	"testing"
)

func TestClaims_IsValidForRole(t *testing.T) {
	debugLogger := log.New(io.Discard, "DEBUG: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
	type fields struct {
		Iat   json.Number
		Exp   json.Number
		Iss   string
		Aud   string
		Sub   string
		Roles []string
	}
	type args struct {
		configRole  string
		debugLogger *log.Logger
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
				configRole:  "Test.Role.1",
				debugLogger: debugLogger,
			},
			want: true,
		},
		{
			name: "expect invalid for role Test.Role.3",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				configRole:  "Test.Role.3",
				debugLogger: debugLogger,
			},
			want: false,
		},
		{
			name: "expect invalid for empty config role",
			fields: fields{
				Roles: []string{"Test.Role.1", "Test.Role.2"},
			},
			args: args{
				configRole:  "",
				debugLogger: debugLogger,
			},
			want: false,
		},
		{
			name: "expect valid for empty config role and empty claim roles",
			fields: fields{
				Roles: []string{},
			},
			args: args{
				configRole:  "",
				debugLogger: debugLogger,
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
			if got := claims.IsValidForRole(tt.args.configRole, tt.args.debugLogger); got != tt.want {
				t.Errorf("Claims.IsValidForRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

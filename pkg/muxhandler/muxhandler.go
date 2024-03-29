// Copyright 2019-2023 Demian Harvill
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package muxhandler provides the gorilla mux handler for mservice rest.

package muxhandler

import (
	"context"
	"encoding/json"
	"github.com/gaterace/mservice/pkg/acctauth"
	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/metadata"
	"io/ioutil"
	"net/http"
	"strconv"
)

type muxHandler struct {
	auth *acctauth.AccountAuth
	rtr  *mux.Router
}

// Create aa new muxHandler struct
func NewMuxHandler(acctAuth *acctauth.AccountAuth, rtr *mux.Router) *muxHandler {
	mh := muxHandler{}
	mh.auth = acctAuth
	mh.rtr = rtr

	return &mh
}

// Add the gorilla mux handlers.
func (mh *muxHandler) AddRoutes() {
	mh.rtr.HandleFunc("/api/login", mh.LoginHandler).Methods("POST")

	mh.rtr.HandleFunc("/api/account", mh.CreateAccountHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/account/{id:[0-9]+}", mh.UpdateAccountHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/account/{id:[0-9]+}/{version:[0-9]+}", mh.DeleteAccountHandler).Methods("DELETE")
	mh.rtr.HandleFunc("/api/account/id/{id:[0-9]+}", mh.AccountByIdHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/account/name/{id}", mh.AccountByNameHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/account/names", mh.AccountNamesHandler).Methods("GET")

	mh.rtr.HandleFunc("/api/user", mh.CreateUserHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/user/{id:[0-9]+}", mh.UpdateUserHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/user/pwd/{id:[0-9]+}", mh.UpdateUserPasswordHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/user/resetpwd/{id:[0-9]+}", mh.ResetUserPasswordHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/user/{id:[0-9]+}/{version:[0-9]+}", mh.DeleteUserHandler).Methods("DELETE")
	mh.rtr.HandleFunc("/api/user/id/{id:[0-9]+}", mh.UserByIdHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/user/email/{account}/{email}", mh.UserByEmailHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/account/users/{account}", mh.UsersByAccountHandler).Methods("GET")

	mh.rtr.HandleFunc("/api/claim", mh.CreateClaimNameHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/claim/{id:[0-9]+}", mh.UpdateClaimNameHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/claim/{id:[0-9]+}/{version:[0-9]+}", mh.DeleteClaimNameHandler).Methods("DELETE")
	mh.rtr.HandleFunc("/api/claim/{id:[0-9]+}", mh.ClaimNameByIdHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/claims", mh.ClaimNamesHandler).Methods("GET")

	mh.rtr.HandleFunc("/api/claimvalue", mh.CreateClaimValueHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/claimvalue/{id:[0-9]+}", mh.UpdateClaimValueHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/claimvalue/{id:[0-9]+}/{version:[0-9]+}", mh.DeleteClaimValueHandler).Methods("DELETE")
	mh.rtr.HandleFunc("/api/claimvalue/id/{id:[0-9]+}", mh.ClaimValueByIdHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/claimvalue/claim/{id:[0-9]+}", mh.ClaimValuesByClaimHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/claimvalues", mh.ClaimValuesHandler).Methods("GET")

	mh.rtr.HandleFunc("/api/role", mh.CreateRoleHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/role/{id:[0-9]+}", mh.UpdateRoleHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/role/{id:[0-9]+}/{version:[0-9]+}", mh.DeleteRoleHandler).Methods("DELETE")
	mh.rtr.HandleFunc("/api/role/id/{id:[0-9]+}", mh.RoleByIdHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/roles/{id:[0-9]+}", mh.RolesByAccountHandler).Methods("GET")

	mh.rtr.HandleFunc("/api/role/user/{role:[0-9]+}/{user:[0-9]+}", mh.AddUserToRoleHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/role/user/{role:[0-9]+}/{user:[0-9]+}", mh.RemoveUserFromRoleHandler).Methods("DELETE")
	mh.rtr.HandleFunc("/api/role/claim/{role:[0-9]+}/{claim:[0-9]+}", mh.AddClaimToRoleHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/role/claim/{role:[0-9]+}/{claim:[0-9]+}", mh.RemoveClaimFromRoleHandler).Methods("DELETE")

	mh.rtr.HandleFunc("/api/server/version", mh.ServerVersionHandler).Methods("GET")
}

// Handle Login method. Expects a POST request and LoginRequest body.  Does not require valid JWT.
func (mh *muxHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.LoginRequest{}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	var ctx context.Context

	resp, err := mh.auth.Login(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle CreateAccount. Expects a POST request and CreateAccountRequest body.
func (mh *muxHandler) CreateAccountHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.CreateAccountRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	ctx := getTokenContext(r)
	resp, err := mh.auth.CreateAccount(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return

}

// Handle UpdateAccount. Expects a PUT request and UpdateAccountRequest body.
func (mh *muxHandler) UpdateAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.UpdateAccountRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	req.AccountId = accountId

	ctx := getTokenContext(r)
	resp, err := mh.auth.UpdateAccount(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return

}

// Handle DeleteAccount. Expects a DELETE request and nil body.
func (mh *muxHandler) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountId, _ := strconv.ParseInt(vars["id"], 10, 64)
	version, _ := strconv.ParseInt(vars["version"], 10, 32)
	req := pb.DeleteAccountRequest{}

	req.AccountId = accountId
	req.Version = int32(version)

	ctx := getTokenContext(r)
	resp, err := mh.auth.DeleteAccount(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return

}

// Handle GetAccountById. Expects a GET request and nil body.
func (mh *muxHandler) AccountByIdHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.GetAccountByIdRequest{}
	req.AccountId = accountId

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountById(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetAccountByName. Expects a GET request and nil body.
func (mh *muxHandler) AccountByNameHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountName := vars["id"]
	req := pb.GetAccountByNameRequest{}
	req.AccountName = accountName

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountByName(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetAccountNames. Expects a GET request and nil body.
func (mh *muxHandler) AccountNamesHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.GetAccountNamesRequest{}
	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountNames(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle CreateAccountUser. Expects a POST request and CreateAccountUserRequest body.
func (mh *muxHandler) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.CreateAccountUserRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	ctx := getTokenContext(r)
	resp, err := mh.auth.CreateAccountUser(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle UpdateAccountUser. Expects a PUT request and UpdateAccountUserRequest body.
func (mh *muxHandler) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.UpdateAccountUserRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	req.UserId = userId

	ctx := getTokenContext(r)
	resp, err := mh.auth.UpdateAccountUser(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle UpdateAccountUserPassword. Expects a PUT request and UpdateAccountUserPasswordRequest body.
func (mh *muxHandler) UpdateUserPasswordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.UpdateAccountUserPasswordRequest{}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	req.UserId = userId

	ctx := getTokenContext(r)
	resp, err := mh.auth.UpdateAccountUserPassword(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle ResetAccountUserPassword. Expects a PUT request and ResetAccountUserPasswordRequest body.
func (mh *muxHandler) ResetUserPasswordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.ResetAccountUserPasswordRequest{}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	req.UserId = userId

	ctx := getTokenContext(r)
	resp, err := mh.auth.ResetAccountUserPassword(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle DeleteAccountUser. Expects a DELETE request and nil body.
func (mh *muxHandler) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId, _ := strconv.ParseInt(vars["id"], 10, 64)
	version, _ := strconv.ParseInt(vars["version"], 10, 32)
	req := pb.DeleteAccountUserRequest{}

	req.UserId = userId
	req.Version = int32(version)

	ctx := getTokenContext(r)
	resp, err := mh.auth.DeleteAccountUser(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetAccountUserById. Expects a GET request and nil body.
func (mh *muxHandler) UserByIdHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.GetAccountUserByIdRequest{}
	req.UserId = userId

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountUserById(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetAccountUserByEmailRequest. Expects a GET request and nil body.
func (mh *muxHandler) UserByEmailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	accountName := vars["account"]
	req := pb.GetAccountUserByEmailRequest{}
	req.AccountName = accountName
	req.Email = email

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountUserByEmail(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetAccountUsers. Expects a GET request and nil body.
func (mh *muxHandler) UsersByAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountName := vars["account"]
	req := pb.GetAccountUsersRequest{}
	req.AccountName = accountName

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountUsers(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle CreateClaimName. Expects a POST request and CreateClaimNameRequest body.
func (mh *muxHandler) CreateClaimNameHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.CreateClaimNameRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	ctx := getTokenContext(r)
	resp, err := mh.auth.CreateClaimName(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle UpdateClaimName. Expects a PUT request and UpdateClaimNameRequest body.
func (mh *muxHandler) UpdateClaimNameHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	claimId, _ := strconv.ParseInt(vars["id"], 10, 64)

	req := pb.UpdateClaimNameRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	req.ClaimNameId = claimId
	ctx := getTokenContext(r)
	resp, err := mh.auth.UpdateClaimName(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle DeleteClaimName. Expects a DELETE request and nil body.
func (mh *muxHandler) DeleteClaimNameHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	claimId, _ := strconv.ParseInt(vars["id"], 10, 64)
	version, _ := strconv.ParseInt(vars["version"], 10, 32)

	req := pb.DeleteClaimNameRequest{}

	req.ClaimNameId = claimId
	req.Version = int32(version)

	ctx := getTokenContext(r)
	resp, err := mh.auth.DeleteClaimName(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetClaimNameById. Expects a GET request and nil body.
func (mh *muxHandler) ClaimNameByIdHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	claimId, _ := strconv.ParseInt(vars["id"], 10, 64)

	req := pb.GetClaimNameByIdRequest{}
	req.ClaimNameId = claimId

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetClaimNameById(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)
}

// Handle GetClaimNames. Expects a GET request and nil body.
func (mh *muxHandler) ClaimNamesHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.GetClaimNamesRequest{}
	ctx := getTokenContext(r)

	resp, err := mh.auth.GetClaimNames(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle CreateClaimValue. Expects a POST request and CreateClaimValueRequest body.
func (mh *muxHandler) CreateClaimValueHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.CreateClaimValueRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	ctx := getTokenContext(r)
	resp, err := mh.auth.CreateClaimValue(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle UpdateClaimValue. Expects a PUT request and UpdateClaimValueRequest body.
func (mh *muxHandler) UpdateClaimValueHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	valueId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.UpdateClaimValueRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	req.ClaimValueId = valueId

	ctx := getTokenContext(r)
	resp, err := mh.auth.UpdateClaimValue(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle DeleteClaimValue. Expects a DELETE request and nil body.
func (mh *muxHandler) DeleteClaimValueHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	valueId, _ := strconv.ParseInt(vars["id"], 10, 64)
	version, _ := strconv.ParseInt(vars["version"], 10, 32)
	req := pb.DeleteClaimValueRequest{}

	req.ClaimValueId = valueId
	req.Version = int32(version)

	ctx := getTokenContext(r)
	resp, err := mh.auth.DeleteClaimValue(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetClaimValueById. Expects a GET request and nil body.
func (mh *muxHandler) ClaimValueByIdHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	valueId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.GetClaimValueByIdRequest{}
	req.ClaimValueId = valueId

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetClaimValueById(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetClaimValuesByNameId. Expects a GET request and nil body.
func (mh *muxHandler) ClaimValuesByClaimHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	claimId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.GetClaimValuesByNameIdRequest{}

	req.ClaimNameId = claimId

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetClaimValuesByNameId(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetClaimValues. Expects a GET request and nil body.
func (mh *muxHandler) ClaimValuesHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.GetClaimValuesRequest{}
	ctx := getTokenContext(r)

	resp, err := mh.auth.GetClaimValues(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle CreateAccountRole. Expects a POST request and CreateAccountRoleRequest body.
func (mh *muxHandler) CreateRoleHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.CreateAccountRoleRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	ctx := getTokenContext(r)
	resp, err := mh.auth.CreateAccountRole(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle UpdateAccountRole. Expects a PUT request and UpdateAccountRoleRequest body.
func (mh *muxHandler) UpdateRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.UpdateAccountRoleRequest{}
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	req.RoleId = roleId

	ctx := getTokenContext(r)
	resp, err := mh.auth.UpdateAccountRole(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle DeleteAccountRole. Expects a DELETE request and nil body.
func (mh *muxHandler) DeleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleId, _ := strconv.ParseInt(vars["id"], 10, 64)
	version, _ := strconv.ParseInt(vars["version"], 10, 32)

	req := pb.DeleteAccountRoleRequest{}

	req.RoleId = roleId
	req.Version = int32(version)

	ctx := getTokenContext(r)
	resp, err := mh.auth.DeleteAccountRole(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetAccountRoleById. Expects a GET request and nil body.
func (mh *muxHandler) RoleByIdHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleId, _ := strconv.ParseInt(vars["id"], 10, 64)
	req := pb.GetAccountRoleByIdRequest{}
	req.RoleId = roleId

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountRoleById(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetAccountRoles. Expects a GET request and nil body.
func (mh *muxHandler) RolesByAccountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountId, _ := strconv.ParseInt(vars["id"], 10, 64)

	req := pb.GetAccountRolesRequest{}

	req.AccountId = accountId

	ctx := getTokenContext(r)

	resp, err := mh.auth.GetAccountRoles(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle AddUserToRole. Expects a POST request and nil body.
func (mh *muxHandler) AddUserToRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleId, _ := strconv.ParseInt(vars["role"], 10, 64)
	userId, _ := strconv.ParseInt(vars["user"], 10, 64)

	req := pb.AddUserToRoleRequest{}

	req.RoleId = roleId
	req.UserId = userId

	ctx := getTokenContext(r)
	resp, err := mh.auth.AddUserToRole(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle RemoveUserFromRoleRequest. Expects a DELETE request and nil body.
func (mh *muxHandler) RemoveUserFromRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleId, _ := strconv.ParseInt(vars["role"], 10, 64)
	userId, _ := strconv.ParseInt(vars["user"], 10, 64)

	req := pb.RemoveUserFromRoleRequest{}

	req.RoleId = roleId
	req.UserId = userId

	ctx := getTokenContext(r)
	resp, err := mh.auth.RemoveUserFromRole(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle AddClaimToRole. Expects a POST request and nil body.
func (mh *muxHandler) AddClaimToRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleId, _ := strconv.ParseInt(vars["role"], 10, 64)
	claimValueId, _ := strconv.ParseInt(vars["claim"], 10, 64)

	req := pb.AddClaimToRoleRequest{}

	req.RoleId = roleId
	req.ClaimValueId = claimValueId

	ctx := getTokenContext(r)
	resp, err := mh.auth.AddClaimToRole(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle RemoveClaimFromRoleRequest. Expects a DELETE request and nil body.
func (mh *muxHandler) RemoveClaimFromRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	roleId, _ := strconv.ParseInt(vars["role"], 10, 64)
	claimValueId, _ := strconv.ParseInt(vars["claim"], 10, 64)

	req := pb.RemoveClaimFromRoleRequest{}

	req.RoleId = roleId
	req.ClaimValueId = claimValueId

	ctx := getTokenContext(r)
	resp, err := mh.auth.RemoveClaimFromRole(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Handle GetServerVersion. Expects a GET request and nil body. Does not require valid JWT.
func (mh *muxHandler) ServerVersionHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.GetServerVersionRequest{}
	req.DummyParam = 1
	ctx := getTokenContext(r)
	resp, err := mh.auth.GetServerVersion(ctx, &req)

	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

// Helper to write method response as json to ResponseWriter.
func writeResponse(resp interface{}, err error, errCode int, w http.ResponseWriter) {
	if err != nil {
		w.WriteHeader(503)
		return
	}

	if errCode == 0 {
		errCode = 200
	}

	jtext, err2 := json.MarshalIndent(resp, "", "  ")
	if err2 != nil {
		w.WriteHeader(504)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(errCode)
	_, _ = w.Write(jtext)
}

// Gets agrpc context that contains the JWT from the Authorization HTTP header, if available.
func getTokenContext(r *http.Request) context.Context {
	ctx := context.Background()
	var token string
	authHeader := r.Header.Get("Authorization")
	if (len(authHeader) > 7) && (authHeader[0:7] == "Bearer ") {
		token = authHeader[7:]
	}

	md := metadata.Pairs("token", token)

	mctx := metadata.NewIncomingContext(ctx, md)
	return mctx
}

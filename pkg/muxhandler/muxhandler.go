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
	rtr *mux.Router
}

func NewMuxHandler(acctAuth *acctauth.AccountAuth, rtr *mux.Router) *muxHandler {
	mh := muxHandler{}
	mh.auth = acctAuth
	mh.rtr = rtr

	return &mh
}

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
	mh.rtr.HandleFunc("/api/user/{id:[0-9]+}/{version:[0-9]+}", mh.DeleteUserHandler).Methods("DELETE")
	mh.rtr.HandleFunc("/api/user/id/{id:[0-9]+}", mh.UserByIdHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/user/email/{account}/{email}", mh.UserByEmailHandler).Methods("GET")
	mh.rtr.HandleFunc("/api/account/users/{account}", mh.UsersByAccountHandler).Methods("GET")

	mh.rtr.HandleFunc("/api/claim", mh.CreateClaimNameHandler).Methods("POST")
	mh.rtr.HandleFunc("/api/claim/{id:[0-9]+}", mh.UpdateClaimNameHandler).Methods("PUT")
	mh.rtr.HandleFunc("/api/claim/{id:[0-9]+}/{version:[0-9]+}", mh.DeleteClaimNameHandler).Methods("DELETE")
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

	resp, err  := mh.auth.Login(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

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

func (mh *muxHandler) UserByEmailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	accountName := vars["account"]
	req := pb.GetAccountUserByEmailRequest{}
	req.AccountName =accountName
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

func getTokenContext(r *http.Request) context.Context {
	ctx := context.Background()
	var token string
	authHeader := r.Header.Get("Authorization")
	// fmt.Printf("authHeader: %s\n", authHeader)
	if (len(authHeader) > 7) && (authHeader[0:7] == "Bearer ") {
		token = authHeader[7:]
	}

	// fmt.Printf("token: %s\n", token)
	md := metadata.Pairs("token", token)

	mctx := metadata.NewIncomingContext(ctx, md)
	return mctx
}
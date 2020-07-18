// Copyright 2019 Demian Harvill
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

// Package acctauth provides an authentication layer for mservice methods.
package acctauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/dgrijalva/jwt-go"
	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

const (
	tokenExpiredMatch   = "Token is expired"
	tokenExpiredMessage = "token is expired"
)

var NotImplemented = errors.New("not implemented")

// Message receiver for account authorization.
type AccountAuth struct {
	// For log messages.
	logger log.Logger
	// SQL database connection.
	db *sql.DB
	// Public key for JWT validation.
	rsaPSSPublicKey *rsa.PublicKey
	// Actual service implementaion that is delgated.
	acctService pb.MServiceAccountServer
}

// Create a new message receiver for account authorization.
func NewAccountAuth(acctService pb.MServiceAccountServer) *AccountAuth {
	svc := AccountAuth{}
	svc.acctService = acctService
	return &svc
}

// Set the logger for account authorization.
func (s *AccountAuth) SetLogger(logger log.Logger) {
	s.logger = logger
}

// Set the RSA public key for JWT validation.
func (s *AccountAuth) SetPublicKey(publicKeyFile string) error {
	publicKey, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		level.Error(s.logger).Log("what", "reading publicKeyFile", "error", err)
		return err
	}

	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		level.Error(s.logger).Log("what", "ParseRSAPublicKeyFromPEM", "error", err)
		return err
	}

	s.rsaPSSPublicKey = parsedKey
	return nil
}

// Set the database connection for account authorization.
func (s *AccountAuth) SetDatabaseConnection(sqlDB *sql.DB) {
	s.db = sqlDB
}

// Bind account authorization to GRPC server.
func (s *AccountAuth) NewApiServer(gServer *grpc.Server) error {
	if s != nil {
		pb.RegisterMServiceAccountServer(gServer, s)
	}
	return nil
}

// Get the Javascript Web Token (JWT) from GRPC context.
func (s *AccountAuth) GetJwtFromContext(ctx context.Context) (*map[string]interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("cannot get metadata from context")
	}

	tokens := md["token"]

	if (tokens == nil) || (len(tokens) == 0) {
		return nil, fmt.Errorf("cannot get token from context")
	}

	tokenString := tokens[0]

	// level.Debug(s.logger).Log("tokenString", tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		method := token.Method.Alg()
		if method != "PS256" {

			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// return []byte(mySigningKey), nil
		return s.rsaPSSPublicKey, nil
	})

	if err != nil {
		level.Debug(s.logger).Log("jwt_error", err)
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("expired json web token")
	}

	claims := map[string]interface{}(token.Claims.(jwt.MapClaims))

	return &claims, nil

}

// Get an int64 value from JWT claims based on key.
func GetInt64FromClaims(claims *map[string]interface{}, key string) int64 {
	var val int64

	if claims != nil {
		cval := (*claims)[key]
		if fval, ok := cval.(float64); ok {
			val = int64(fval)
		}
	}

	return val
}

// Get an string value from JWT claims based on key.
func GetStringFromClaims(claims *map[string]interface{}, key string) string {
	var val string

	if claims != nil {
		cval := (*claims)[key]
		if sval, ok := cval.(string); ok {
			val = sval
		}
	}

	return val
}

// login does not require previous authorization.
func (s *AccountAuth) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	start := time.Now().UnixNano()
	resp, err := s.acctService.Login(ctx, req)
	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "Login", "email", req.GetEmail(),
		"account", req.GetAccountName(),
		"errcode", resp.GetErrorCode(), "duration", duration)
	return resp, err
}

// create a new account
func (s *AccountAuth) CreateAccount(ctx context.Context, req *pb.CreateAccountRequest) (*pb.CreateAccountResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.CreateAccount(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateAccount",
		"account", req.GetAccountName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// update an existing account.
func (s *AccountAuth) UpdateAccount(ctx context.Context, req *pb.UpdateAccountRequest) (*pb.UpdateAccountResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.UpdateAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		actname := GetStringFromClaims(claims, "actname")
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (actname == req.GetAccountName())) {
			resp, err = s.acctService.UpdateAccount(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "UpdateAccount",
		"account", req.GetAccountName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// delete an existing account.
func (s *AccountAuth) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.DeleteAccountResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.DeleteAccount(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteAccount",
		"accountid", req.GetAccountId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get an account by account id.
func (s *AccountAuth) GetAccountById(ctx context.Context, req *pb.GetAccountByIdRequest) (*pb.GetAccountByIdResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) || ((acctmgt == "acctro") && (aid == accountId)) {
			resp, err = s.acctService.GetAccountById(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountById",
		"accountid", req.GetAccountId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get an account by account name.
func (s *AccountAuth) GetAccountByName(ctx context.Context, req *pb.GetAccountByNameRequest) (*pb.GetAccountByNameResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountByNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		// uid := GetInt64FromClaims(claims, "uid")
		actname := GetStringFromClaims(claims, "actname")
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		reqAccount := req.GetAccountName()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (actname == reqAccount)) || ((acctmgt == "acctro") && (actname == reqAccount)) {
			resp, err = s.acctService.GetAccountByName(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountByName",
		"account", req.GetAccountName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// Get account names within account.
func (s *AccountAuth) GetAccountNames(ctx context.Context, req *pb.GetAccountNamesRequest) (*pb.GetAccountNamesResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountNamesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)

	if err == nil {
		// uid := GetInt64FromClaims(claims, "uid")
		// actname := GetStringFromClaims(claims, "actname")

		acctmgt := GetStringFromClaims(claims, "acctmgt")

		if acctmgt == "admin" {
			resp, err = s.acctService.GetAccountNames(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountNames",
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// create an account user.
func (s *AccountAuth) CreateAccountUser(ctx context.Context, req *pb.CreateAccountUserRequest) (*pb.CreateAccountUserResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateAccountUserResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			resp, err = s.acctService.CreateAccountUser(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateAccountUser",
		"email", req.GetEmail(),
		"accountid", req.GetAccountId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// update an existing account user.
func (s *AccountAuth) UpdateAccountUser(ctx context.Context, req *pb.UpdateAccountUserRequest) (*pb.UpdateAccountUserResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.UpdateAccountUserResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	var ok bool

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		uid := GetInt64FromClaims(claims, "uid")
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromUserid(req.GetUserId())
			if (err == nil) && (aid == accountId) {
				ok = true
			}
		} else if acctmgt == "userrw" {
			if req.GetUserId() == uid {
				ok = true
			}
		}

		if ok {
			resp, err = s.acctService.UpdateAccountUser(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "UpdateAccountUser",
		"userid", req.GetUserId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// update an existing account user password.
func (s *AccountAuth) UpdateAccountUserPassword(ctx context.Context,
	req *pb.UpdateAccountUserPasswordRequest) (*pb.UpdateAccountUserPasswordResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.UpdateAccountUserPasswordResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	var ok bool

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		uid := GetInt64FromClaims(claims, "uid")
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromUserid(req.GetUserId())
			if (err == nil) && (aid == accountId) {
				ok = true
			}
		} else if (acctmgt == "userrw") || (acctmgt == "userpw") {
			if req.GetUserId() == uid {
				ok = true
			}
		}

		if ok {
			resp, err = s.acctService.UpdateAccountUserPassword(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "UpdateAccountUserPassword",
		"userid", req.GetUserId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// delete an existing account user.
func (s *AccountAuth) DeleteAccountUser(ctx context.Context, req *pb.DeleteAccountUserRequest) (*pb.DeleteAccountUserResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteAccountUserResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	var ok bool

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		uid := GetInt64FromClaims(claims, "uid")
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromUserid(req.GetUserId())
			if (err == nil) && (aid == accountId) {
				ok = true
			}
		} else if acctmgt == "userrw" {
			if req.GetUserId() == uid {
				ok = true
			}
		}

		if ok {
			resp, err = s.acctService.DeleteAccountUser(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteAccountUser",
		"userid", req.GetUserId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, nil
}

// get an account user by id.
func (s *AccountAuth) GetAccountUserById(ctx context.Context, req *pb.GetAccountUserByIdRequest) (*pb.GetAccountUserByIdResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountUserByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		uid := GetInt64FromClaims(claims, "uid")
		var ok bool
		var postCheckAccount bool

		if acctmgt == "admin" {
			ok = true
		} else if (acctmgt == "acctrw") || (acctmgt == "acctro") {
			ok = true
			postCheckAccount = true
		} else if ((acctmgt == "userrw") || (acctmgt == "userro")) && (uid == req.GetUserId()) {
			ok = true
		}

		if ok {
			resp, err = s.acctService.GetAccountUserById(ctx, req)

			if postCheckAccount && (resp.GetAccountUser() == nil) || (resp.GetAccountUser().GetAccountId() != aid) {
				resp.ErrorCode = 401
				resp.ErrorMessage = "not authorized"
				resp.AccountUser = nil
			}
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountUserById",
		"userid", req.GetUserId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get an account user by email.
func (s *AccountAuth) GetAccountUserByEmail(ctx context.Context, req *pb.GetAccountUserByEmailRequest) (*pb.GetAccountUserByEmailResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountUserByEmailResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		uid := GetInt64FromClaims(claims, "uid")
		var ok bool
		var postCheckAccount bool
		var postCheckUserid bool

		if acctmgt == "admin" {
			ok = true
		} else if (acctmgt == "acctrw") || (acctmgt == "acctro") {
			ok = true
			postCheckAccount = true
		} else if (acctmgt == "userrw") || (acctmgt == "userro") {
			ok = true
			postCheckUserid = true
		}

		if ok {
			resp, err = s.acctService.GetAccountUserByEmail(ctx, req)
			if !postCheckAccount && !postCheckUserid {
				return resp, err
			}
			if postCheckAccount && (resp.GetAccountUser() == nil) || (resp.GetAccountUser().GetAccountId() != aid) {
				resp.ErrorCode = 401
				resp.ErrorMessage = "not authorized"
				resp.AccountUser = nil
			}
			if postCheckUserid && (resp.GetAccountUser() == nil) || (resp.GetAccountUser().GetUserId() != uid) {
				resp.ErrorCode = 401
				resp.ErrorMessage = "not authorized"
				resp.AccountUser = nil
			}
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountUserByEmail",
		"email", req.GetEmail(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get all account users in account.
func (s *AccountAuth) GetAccountUsers(ctx context.Context, req *pb.GetAccountUsersRequest) (*pb.GetAccountUsersResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountUsersResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		actname := GetStringFromClaims(claims, "actname")
		reqAccount := req.GetAccountName()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (actname == reqAccount)) || ((acctmgt == "acctro") && (actname == reqAccount)) {
			resp, err = s.acctService.GetAccountUsers(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountUsers",
		"account", req.GetAccountName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// create a claim name.
func (s *AccountAuth) CreateClaimName(ctx context.Context, req *pb.CreateClaimNameRequest) (*pb.CreateClaimNameResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateClaimNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.CreateClaimName(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateClaimName",
		"claim", req.GetClaimName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// update an existing claim name.
func (s *AccountAuth) UpdateClaimName(ctx context.Context, req *pb.UpdateClaimNameRequest) (*pb.UpdateClaimNameResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.UpdateClaimNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.UpdateClaimName(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "UpdateClaimName",
		"claimid", req.GetClaimNameId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// delete an existing claim name.
func (s *AccountAuth) DeleteClaimName(ctx context.Context, req *pb.DeleteClaimNameRequest) (*pb.DeleteClaimNameResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteClaimNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.DeleteClaimName(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteClaimName",
		"claimid", req.GetClaimNameId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get all claim names.
func (s *AccountAuth) GetClaimNames(ctx context.Context, req *pb.GetClaimNamesRequest) (*pb.GetClaimNamesResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetClaimNamesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if (acctmgt == "admin") || (acctmgt == "acctrw") || (acctmgt == "acctro") {
			resp, err = s.acctService.GetClaimNames(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetClaimNames",
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// create claim value.
func (s *AccountAuth) CreateClaimValue(ctx context.Context, req *pb.CreateClaimValueRequest) (*pb.CreateClaimValueResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateClaimValueResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.CreateClaimValue(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateClaimValue",
		"claimval", req.GetClaimVal(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// update existing claim value.
func (s *AccountAuth) UpdateClaimValue(ctx context.Context, req *pb.UpdateClaimValueRequest) (*pb.UpdateClaimValueResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.UpdateClaimValueResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.UpdateClaimValue(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "UpdateClaimValue",
		"claimvalid", req.GetClaimValueId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// delete existing claim value.
func (s *AccountAuth) DeleteClaimValue(ctx context.Context, req *pb.DeleteClaimValueRequest) (*pb.DeleteClaimValueResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteClaimValueResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.DeleteClaimValue(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteClaimValue",
		"claimvalid", req.GetClaimValueId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get claim value by id.
func (s *AccountAuth) GetClaimValueById(ctx context.Context, req *pb.GetClaimValueByIdRequest) (*pb.GetClaimValueByIdResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetClaimValueByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if (acctmgt == "admin") || (acctmgt == "acctrw") || (acctmgt == "acctro") {
			resp, err = s.acctService.GetClaimValueById(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetClaimValueById",
		"claimvalid", req.GetClaimValueId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get all claim values for name id.
func (s *AccountAuth) GetClaimValuesByNameId(ctx context.Context,
	req *pb.GetClaimValuesByNameIdRequest) (*pb.GetClaimValuesByNameIdResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetClaimValuesByNameIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if (acctmgt == "admin") || (acctmgt == "acctrw") || (acctmgt == "acctro") {
			resp, err = s.acctService.GetClaimValuesByNameId(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetClaimValuesByNameId",
		"claimid", req.GetClaimNameId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get all claim values for all claim names.
func (s *AccountAuth) GetClaimValues(ctx context.Context, req *pb.GetClaimValuesRequest) (*pb.GetClaimValuesResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetClaimValuesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			resp, err = s.acctService.GetClaimValues(ctx, req)
		}

	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetClaimValues",
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// create account role.
func (s *AccountAuth) CreateAccountRole(ctx context.Context, req *pb.CreateAccountRoleRequest) (*pb.CreateAccountRoleResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateAccountRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			resp, err = s.acctService.CreateAccountRole(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateAccountRole",
		"accountid", req.GetAccountId(),
		"role", req.GetRoleName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// update existing account role.
func (s *AccountAuth) UpdateAccountRole(ctx context.Context, req *pb.UpdateAccountRoleRequest) (*pb.UpdateAccountRoleResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.UpdateAccountRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)
			if (err != nil) && (aid == accountId) {
				ok = true
			}
		}
		if ok {
			resp, err = s.acctService.UpdateAccountRole(ctx, req)
		}

	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "UpdateAccountRole",
		"roleid", req.GetRoleId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// delete existing account role.
func (s *AccountAuth) DeleteAccountRole(ctx context.Context, req *pb.DeleteAccountRoleRequest) (*pb.DeleteAccountRoleResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteAccountRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)
			if (err != nil) && (aid == accountId) {
				ok = true
			}
		}
		if ok {
			resp, err = s.acctService.DeleteAccountRole(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteAccountRole",
		"roleid", req.GetRoleId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get account role by id.
func (s *AccountAuth) GetAccountRoleById(ctx context.Context, req *pb.GetAccountRoleByIdRequest) (*pb.GetAccountRoleByIdResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountRoleByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()
		if acctmgt == "admin" {
			ok = true
		} else if (acctmgt == "acctrw") || (acctmgt == "acctro") {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)
			if (err != nil) && (aid == accountId) {
				ok = true
			}
		}
		if ok {
			resp, err = s.acctService.GetAccountRoleById(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountRoleById",
		"roleid", req.GetRoleId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get all account roles in account.
func (s *AccountAuth) GetAccountRoles(ctx context.Context, req *pb.GetAccountRolesRequest) (*pb.GetAccountRolesResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetAccountRolesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			resp, err = s.acctService.GetAccountRoles(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetAccountRoles",
		"accountid", req.GetAccountId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// associate an account user with an account role.
func (s *AccountAuth) AddUserToRole(ctx context.Context, req *pb.AddUserToRoleRequest) (*pb.AddUserToRoleResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.AddUserToRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()

		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)

			if (err == nil) && (aid == accountId) {
				// avoid privilege escalation
				roleMatch := s.HelperRoleContains(roleId, "acctmgt", "admin")
				if roleMatch {
					level.Warn(s.logger).Log("msg", fmt.Sprintf("AddUserToRole privilege escalation attempted, roleId: %d", roleId))
				}
				ok = !roleMatch
			}
		}
		if ok {
			resp, err = s.acctService.AddUserToRole(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "AddUserToRole",
		"roleid", req.GetRoleId(),
		"userid", req.GetUserId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// disassociate an account user from an account role.
func (s *AccountAuth) RemoveUserFromRole(ctx context.Context, req *pb.RemoveUserFromRoleRequest) (*pb.RemoveUserFromRoleResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.RemoveUserFromRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)
			if (err != nil) && (aid == accountId) {
				ok = true
			}
		}
		if ok {
			resp, err = s.acctService.RemoveUserFromRole(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "RemoveUserFromRole",
		"roleid", req.GetRoleId(),
		"userid", req.GetUserId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// associate a claim with an account role.
func (s *AccountAuth) AddClaimToRole(ctx context.Context, req *pb.AddClaimToRoleRequest) (*pb.AddClaimToRoleResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.AddClaimToRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)
			if (err != nil) && (aid == accountId) {
				// avoid privilege escalation
				claimName, claimValue, err := s.HelperClaimFromClaimValueId(req.GetClaimValueId())
				if err == nil {
					if claimName == "acctmgt" && claimValue == "admin" {
						level.Warn(s.logger).Log("msg", fmt.Sprintf("AddClaimToRole privilege escalation attempted, roleId: %d", roleId))
					} else {
						ok = true
					}
				}
			}
		}
		if ok {
			resp, err = s.acctService.AddClaimToRole(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "AddClaimToRole",
		"roleid", req.GetRoleId(),
		"claimvalid", req.GetClaimValueId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// remove a claim from an account role.
func (s *AccountAuth) RemoveClaimFromRole(ctx context.Context, req *pb.RemoveClaimFromRoleRequest) (*pb.RemoveClaimFromRoleResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.RemoveClaimFromRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)
			if (err != nil) && (aid == accountId) {
				ok = true
			}
		}
		if ok {
			resp, err = s.acctService.RemoveClaimFromRole(ctx, req)
		}

	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "RemoveClaimFromRole",
		"roleid", req.GetRoleId(),
		"claimvalid", req.GetClaimValueId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// Helper to get account id from user id.
func (s *AccountAuth) HelperAccountIdFromUserid(userId int64) (int64, error) {
	sqlstring := `SELECT inbAccountId FROM tb_AccountUser WHERE inbUserId = ? AND bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return 0, err
	}

	defer stmt.Close()

	var accountId int64
	err = stmt.QueryRow(userId).Scan(&accountId)

	if err != nil {
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		return 0, err
	}

	return accountId, nil
}

// Helper to get account id from role id.
func (s *AccountAuth) HelperAccountIdFromRoleId(roleId int64) (int64, error) {
	sqlstring := `SELECT inbAccountId FROM tb_AccountRole WHERE inbRoleId = ? AND bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return 0, err
	}

	defer stmt.Close()

	var accountId int64
	err = stmt.QueryRow(roleId).Scan(&accountId)

	if err != nil {
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		return 0, err
	}

	return accountId, nil
}

// Helper to get the claim name and claim value from claim value id
func (s *AccountAuth) HelperClaimFromClaimValueId(claimValueId int64) (string, string, error) {
	var claimName string
	var claimValue string
	sqlstring := `SELECT c.chvClaimName, v.chvClaimVal FROM tb_ClaimValue AS v JOIN tb_Claim AS c ON v.inbClaimNameId = c.inbClaimNameId  
	WHERE v.inbClaimValueId = ? AND v.bitIsDeleted = 0 AND c.bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return claimName, claimValue, err
	}

	defer stmt.Close()

	err = stmt.QueryRow(claimValueId).Scan(&claimName, &claimValue)

	return claimName, claimValue, err
}

func (s *AccountAuth) HelperRoleContains(roleId int64, claimName string, claimValue string) bool {

	sqlstring := `SELECT c.chvClaimName,  v.chvClaimVal FROM tb_RoleClaimMap AS r JOIN  tb_ClaimValue AS v ON r.inbClaimValueId = v.inbClaimValueId  
	JOIN tb_Claim AS c on v.inbClaimNameId = c.inbClaimNameId  where r.inbRoleId = ? AND r.bitIsDeleted = 0 AND 
	v.bitIsDeleted = 0 AND c.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return false
	}

	defer stmt.Close()

	rows, err := stmt.Query(roleId)
	if err != nil {
		return false
	}

	defer rows.Close()
	for rows.Next() {
		var cName string
		var cValue string

		err := rows.Scan(&cName, &cValue)
		if err != nil {
			return false
		}

		if (cName == claimName) && (cValue == claimValue) {
			return true
		}

	}

	return false
}

// get current server version and uptime - health check
func (s *AccountAuth) GetServerVersion(ctx context.Context, req *pb.GetServerVersionRequest) (*pb.GetServerVersionResponse, error) {
	return s.acctService.GetServerVersion(ctx, req)
}

// create an entity schema
func (s *AccountAuth) CreateEntitySchema(ctx context.Context, req *pb.CreateEntitySchemaRequest) (*pb.CreateEntitySchemaResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateEntitySchemaResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			resp, err = s.acctService.CreateEntitySchema(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateEntitySchema",
		"accountid", req.GetAccountId(),
		"entity", req.GetEntityName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// update an entity schema
func (s *AccountAuth) UpdateEntitySchema(ctx context.Context, req *pb.UpdateEntitySchemaRequest) (*pb.UpdateEntitySchemaResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.UpdateEntitySchemaResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			resp, err = s.acctService.UpdateEntitySchema(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "UpdateEntitySchema",
		"accountid", req.GetAccountId(),
		"entity", req.GetEntityName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err

}

// delete an entity schema
func (s *AccountAuth) DeleteEntitySchema(ctx context.Context, req *pb.DeleteEntitySchemaRequest) (*pb.DeleteEntitySchemaResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteEntitySchemaResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			resp, err = s.acctService.DeleteEntitySchema(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteEntitySchema",
		"accountid", req.GetAccountId(),
		"entity", req.GetEntityName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get an entity schema by name
func (s *AccountAuth) GetEntitySchema(ctx context.Context, req *pb.GetEntitySchemaRequest) (*pb.GetEntitySchemaResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetEntitySchemaResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) || ((acctmgt == "acctro") && (aid == accountId)) {
			resp, err = s.acctService.GetEntitySchema(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetEntitySchema",
		"accountid", req.GetAccountId(),
		"entity", req.GetEntityName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get all entity schemas for account
func (s *AccountAuth) GetEntitySchemas(ctx context.Context, req *pb.GetEntitySchemasRequest) (*pb.GetEntitySchemasResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetEntitySchemasResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) || ((acctmgt == "acctro") && (aid == accountId)) {
			resp, err = s.acctService.GetEntitySchemas(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetEntitySchemas",
		"accountid", req.GetAccountId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

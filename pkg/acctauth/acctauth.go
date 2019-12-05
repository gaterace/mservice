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
	"fmt"
	"io/ioutil"
	"log"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/dgrijalva/jwt-go"
	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

// Message receiver for account authorization.
type accountAuth struct {
	// For log messages.
	logger *log.Logger
	// SQL database connection.
	db *sql.DB
	// Public key for JWT validation.
	rsaPSSPublicKey *rsa.PublicKey
	// Actual service implementaion that is delgated.
	acctService pb.MServiceAccountServer
}

// Create a new message receiver for account authorization.
func NewAccountAuth(acctService pb.MServiceAccountServer) *accountAuth {
	svc := accountAuth{}
	svc.acctService = acctService
	return &svc
}

// Set the logger for account authorization.
func (s *accountAuth) SetLogger(logger *log.Logger) {
	s.logger = logger
}

// Set the RSA public key for JWT validation.
func (s *accountAuth) SetPublicKey(publicKeyFile string) error {
	publicKey, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		s.logger.Printf("error reading publicKeyFile: %v\n", err)
		return err
	}

	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		s.logger.Printf("error parsing publicKeyFile: %v\n", err)
		return err
	}

	s.rsaPSSPublicKey = parsedKey
	return nil
}

// Set the database connection for account authorization.
func (s *accountAuth) SetDatabaseConnection(sqlDB *sql.DB) {
	s.db = sqlDB
}

// Bind account authorization to GRPC server.
func (s *accountAuth) NewApiServer(gServer *grpc.Server) error {
	if s != nil {
		pb.RegisterMServiceAccountServer(gServer, s)
	}
	return nil
}

// Get the Javascript Web Token (JWT) from GRPC context.
func (s *accountAuth) GetJwtFromContext(ctx context.Context) (*map[string]interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("cannot get metadata from context")
	}

	tokens := md["token"]

	if (tokens == nil) || (len(tokens) == 0) {
		return nil, fmt.Errorf("cannot get token from context")
	}

	tokenString := tokens[0]

	s.logger.Printf("tokenString: %s\n", tokenString)

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
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid json web token")
	}

	claims := map[string]interface{}(token.Claims.(jwt.MapClaims))

	s.logger.Printf("claims: %v\n", claims)

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
func (s *accountAuth) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	resp, err := s.acctService.Login(ctx, req)
	return resp, err
}

// create a new account
func (s *accountAuth) CreateAccount(ctx context.Context, req *pb.CreateAccountRequest) (*pb.CreateAccountResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.CreateAccount(ctx, req)
		}
	}

	resp := &pb.CreateAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// update an existing account.
func (s *accountAuth) UpdateAccount(ctx context.Context, req *pb.UpdateAccountRequest) (*pb.UpdateAccountResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		actname := GetStringFromClaims(claims, "actname")
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (actname == req.GetAccountName())) {
			return s.acctService.UpdateAccount(ctx, req)
		}
	}

	resp := &pb.UpdateAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// delete an existing account.
func (s *accountAuth) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.DeleteAccountResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.DeleteAccount(ctx, req)
		}
	}

	resp := &pb.DeleteAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get an account by account id.
func (s *accountAuth) GetAccountById(ctx context.Context, req *pb.GetAccountByIdRequest) (*pb.GetAccountByIdResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()
		s.logger.Printf("acctmgt: %s\n", acctmgt)
		s.logger.Printf("aid: %d\n", aid)
		s.logger.Printf("accountId: %d\n", accountId)

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) || ((acctmgt == "acctro") && (aid == accountId)) {
			return s.acctService.GetAccountById(ctx, req)
		}
	}

	resp := &pb.GetAccountByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get an account by account name.
func (s *accountAuth) GetAccountByName(ctx context.Context, req *pb.GetAccountByNameRequest) (*pb.GetAccountByNameResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		uid := GetInt64FromClaims(claims, "uid")
		s.logger.Printf("uid: %d\n", uid)
		actname := GetStringFromClaims(claims, "actname")
		s.logger.Printf("actname: %s\n", actname)
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		s.logger.Printf("acctmgt: %s\n", acctmgt)
		reqAccount := req.GetAccountName()

		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (actname == reqAccount)) || ((acctmgt == "acctro") && (actname == reqAccount)) {
			s.logger.Println("authorized")
			return s.acctService.GetAccountByName(ctx, req)
		}
	}

	resp := &pb.GetAccountByNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// Get account names within account.
func (s *accountAuth) GetAccountNames(ctx context.Context, req *pb.GetAccountNamesRequest) (*pb.GetAccountNamesResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		uid := GetInt64FromClaims(claims, "uid")
		s.logger.Printf("uid: %d\n", uid)
		actname := GetStringFromClaims(claims, "actname")
		s.logger.Printf("actname: %s\n", actname)
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		s.logger.Printf("acctmgt: %s\n", acctmgt)

		if acctmgt == "admin" {
			s.logger.Println("authorized")
			return s.acctService.GetAccountNames(ctx, req)
		}
	}

	resp := &pb.GetAccountNamesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// create an account user.
func (s *accountAuth) CreateAccountUser(ctx context.Context, req *pb.CreateAccountUserRequest) (*pb.CreateAccountUserResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			return s.acctService.CreateAccountUser(ctx, req)
		}
	}

	resp := &pb.CreateAccountUserResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// update an existing account user.
func (s *accountAuth) UpdateAccountUser(ctx context.Context, req *pb.UpdateAccountUserRequest) (*pb.UpdateAccountUserResponse, error) {
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
			return s.acctService.UpdateAccountUser(ctx, req)
		}
	}

	resp := &pb.UpdateAccountUserResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// update an existing account user password.
func (s *accountAuth) UpdateAccountUserPassword(ctx context.Context, req *pb.UpdateAccountUserPasswordRequest) (*pb.UpdateAccountUserPasswordResponse, error) {
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
			return s.acctService.UpdateAccountUserPassword(ctx, req)
		}
	}

	resp := &pb.UpdateAccountUserPasswordResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// delete an existing account user.
func (s *accountAuth) DeleteAccountUser(ctx context.Context, req *pb.DeleteAccountUserRequest) (*pb.DeleteAccountUserResponse, error) {
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
			return s.acctService.DeleteAccountUser(ctx, req)
		}
	}

	resp := &pb.DeleteAccountUserResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get an account user by id.
func (s *accountAuth) GetAccountUserById(ctx context.Context, req *pb.GetAccountUserByIdRequest) (*pb.GetAccountUserByIdResponse, error) {
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
			resp, err := s.acctService.GetAccountUserById(ctx, req)
			if !postCheckAccount {
				return resp, err
			}
			if postCheckAccount && (resp.GetAccountUser() != nil) && (resp.GetAccountUser().GetAccountId() == aid) {
				return resp, err
			}
		}
	}

	resp := &pb.GetAccountUserByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get an account user by email.
func (s *accountAuth) GetAccountUserByEmail(ctx context.Context, req *pb.GetAccountUserByEmailRequest) (*pb.GetAccountUserByEmailResponse, error) {
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
			resp, err := s.acctService.GetAccountUserByEmail(ctx, req)
			if !postCheckAccount && !postCheckUserid {
				return resp, err
			}
			if postCheckAccount && (resp.GetAccountUser() != nil) && (resp.GetAccountUser().GetAccountId() == aid) {
				return resp, err
			}
			if postCheckUserid && (resp.GetAccountUser() != nil) && (resp.GetAccountUser().GetUserId() == uid) {
				return resp, err
			}
		}
	}

	resp := &pb.GetAccountUserByEmailResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get all account users in account.
func (s *accountAuth) GetAccountUsers(ctx context.Context, req *pb.GetAccountUsersRequest) (*pb.GetAccountUsersResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		actname := GetStringFromClaims(claims, "actname")
		reqAccount := req.GetAccountName()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (actname == reqAccount)) || ((acctmgt == "acctro") && (actname == reqAccount)) {
			return s.acctService.GetAccountUsers(ctx, req)
		}
	}

	resp := &pb.GetAccountUsersResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// create a claim name.
func (s *accountAuth) CreateClaimName(ctx context.Context, req *pb.CreateClaimNameRequest) (*pb.CreateClaimNameResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.CreateClaimName(ctx, req)
		}
	}

	resp := &pb.CreateClaimNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// update an existing claim name.
func (s *accountAuth) UpdateClaimName(ctx context.Context, req *pb.UpdateClaimNameRequest) (*pb.UpdateClaimNameResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.UpdateClaimName(ctx, req)
		}
	}

	resp := &pb.UpdateClaimNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// delete an existing claim name.
func (s *accountAuth) DeleteClaimName(ctx context.Context, req *pb.DeleteClaimNameRequest) (*pb.DeleteClaimNameResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.DeleteClaimName(ctx, req)
		}
	}

	resp := &pb.DeleteClaimNameResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get all claim names.
func (s *accountAuth) GetClaimNames(ctx context.Context, req *pb.GetClaimNamesRequest) (*pb.GetClaimNamesResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if (acctmgt == "admin") || (acctmgt == "acctrw") || (acctmgt == "acctro") {
			return s.acctService.GetClaimNames(ctx, req)
		}
	}

	resp := &pb.GetClaimNamesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// create claim value.
func (s *accountAuth) CreateClaimValue(ctx context.Context, req *pb.CreateClaimValueRequest) (*pb.CreateClaimValueResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.CreateClaimValue(ctx, req)
		}
	}

	resp := &pb.CreateClaimValueResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// update existing claim value.
func (s *accountAuth) UpdateClaimValue(ctx context.Context, req *pb.UpdateClaimValueRequest) (*pb.UpdateClaimValueResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.UpdateClaimValue(ctx, req)
		}
	}

	resp := &pb.UpdateClaimValueResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// delete existing claim value.
func (s *accountAuth) DeleteClaimValue(ctx context.Context, req *pb.DeleteClaimValueRequest) (*pb.DeleteClaimValueResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.DeleteClaimValue(ctx, req)
		}
	}

	resp := &pb.DeleteClaimValueResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get claim value by id.
func (s *accountAuth) GetClaimValueById(ctx context.Context, req *pb.GetClaimValueByIdRequest) (*pb.GetClaimValueByIdResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if (acctmgt == "admin") || (acctmgt == "acctrw") || (acctmgt == "acctro") {
			return s.acctService.GetClaimValueById(ctx, req)
		}
	}

	resp := &pb.GetClaimValueByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get all claim values for name id.
func (s *accountAuth) GetClaimValuesByNameId(ctx context.Context, req *pb.GetClaimValuesByNameIdRequest) (*pb.GetClaimValuesByNameIdResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if (acctmgt == "admin") || (acctmgt == "acctrw") || (acctmgt == "acctro") {
			return s.acctService.GetClaimValuesByNameId(ctx, req)
		}
	}

	resp := &pb.GetClaimValuesByNameIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get all claim values for all claim names.
func (s *accountAuth) GetClaimValues(ctx context.Context, req *pb.GetClaimValuesRequest) (*pb.GetClaimValuesResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		if acctmgt == "admin" {
			return s.acctService.GetClaimValues(ctx, req)
		}

	}
	resp := &pb.GetClaimValuesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// create account role.
func (s *accountAuth) CreateAccountRole(ctx context.Context, req *pb.CreateAccountRoleRequest) (*pb.CreateAccountRoleResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			return s.acctService.CreateAccountRole(ctx, req)
		}
	}

	resp := &pb.CreateAccountRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// update existing account role.
func (s *accountAuth) UpdateAccountRole(ctx context.Context, req *pb.UpdateAccountRoleRequest) (*pb.UpdateAccountRoleResponse, error) {
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
			return s.acctService.UpdateAccountRole(ctx, req)
		}

	}

	resp := &pb.UpdateAccountRoleResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// delete existing account role.
func (s *accountAuth) DeleteAccountRole(ctx context.Context, req *pb.DeleteAccountRoleRequest) (*pb.DeleteAccountRoleResponse, error) {
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
			return s.acctService.DeleteAccountRole(ctx, req)
		}

	}

	resp := &pb.DeleteAccountRoleResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get account role by id.
func (s *accountAuth) GetAccountRoleById(ctx context.Context, req *pb.GetAccountRoleByIdRequest) (*pb.GetAccountRoleByIdResponse, error) {
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
			return s.acctService.GetAccountRoleById(ctx, req)
		}

	}

	resp := &pb.GetAccountRoleByIdResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// get all account roles in account.
func (s *accountAuth) GetAccountRoles(ctx context.Context, req *pb.GetAccountRolesRequest) (*pb.GetAccountRolesResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		accountId := req.GetAccountId()
		if (acctmgt == "admin") || ((acctmgt == "acctrw") && (aid == accountId)) {
			return s.acctService.GetAccountRoles(ctx, req)
		}
	}

	resp := &pb.GetAccountRolesResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// associate an account user with an account role.
func (s *accountAuth) AddUserToRole(ctx context.Context, req *pb.AddUserToRoleRequest) (*pb.AddUserToRoleResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		var ok bool
		acctmgt := GetStringFromClaims(claims, "acctmgt")
		aid := GetInt64FromClaims(claims, "aid")
		roleId := req.GetRoleId()
		s.logger.Printf("AddUserToRole acctmgt: %s, aid: %d, roleId: %d", acctmgt, aid, roleId)
		if acctmgt == "admin" {
			ok = true
		} else if acctmgt == "acctrw" {
			accountId, err := s.HelperAccountIdFromRoleId(roleId)

			if (err == nil) && (aid == accountId) {
				// avoid privilege escalation
				roleMatch := s.HelperRoleContains(roleId, "acctmgt", "admin")
				if roleMatch {
					s.logger.Printf("AddUserToRole privilege escalation attempted, roleId: %d", roleId)
				}
				ok = !roleMatch
			}
		}
		if ok {
			return s.acctService.AddUserToRole(ctx, req)
		}

	}

	resp := &pb.AddUserToRoleResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// disassociate an account user from an account role.
func (s *accountAuth) RemoveUserFromRole(ctx context.Context, req *pb.RemoveUserFromRoleRequest) (*pb.RemoveUserFromRoleResponse, error) {
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
			return s.acctService.RemoveUserFromRole(ctx, req)
		}

	}

	resp := &pb.RemoveUserFromRoleResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// associate a claim with an account role.
func (s *accountAuth) AddClaimToRole(ctx context.Context, req *pb.AddClaimToRoleRequest) (*pb.AddClaimToRoleResponse, error) {
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
						s.logger.Printf("AddClaimToRole privilege escalation attemped, role: %d", roleId)
					} else {
						ok = true
					}
				}
			}
		}
		if ok {
			return s.acctService.AddClaimToRole(ctx, req)
		}

	}

	resp := &pb.AddClaimToRoleResponse{}

	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// remove a claim from an account role.
func (s *accountAuth) RemoveClaimFromRole(ctx context.Context, req *pb.RemoveClaimFromRoleRequest) (*pb.RemoveClaimFromRoleResponse, error) {
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
			return s.acctService.RemoveClaimFromRole(ctx, req)
		}

	}

	resp := &pb.RemoveClaimFromRoleResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, nil
}

// Helper to get account id from user id.
func (s *accountAuth) HelperAccountIdFromUserid(userId int64) (int64, error) {
	sqlstring := `SELECT inbAccountId FROM tb_AccountUser WHERE inbUserId = ? AND bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		return 0, err
	}

	defer stmt.Close()

	var accountId int64
	err = stmt.QueryRow(userId).Scan(&accountId)

	if err != nil {
		s.logger.Printf("dquery row failed: %v\n", err)
		return 0, err
	}

	return accountId, nil
}

// Helper to get account id from role id.
func (s *accountAuth) HelperAccountIdFromRoleId(roleId int64) (int64, error) {
	sqlstring := `SELECT inbAccountId FROM tb_AccountRole WHERE inbRoleId = ? AND bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		return 0, err
	}

	defer stmt.Close()

	var accountId int64
	err = stmt.QueryRow(roleId).Scan(&accountId)

	if err != nil {
		s.logger.Printf("dquery row failed: %v\n", err)
		return 0, err
	}

	return accountId, nil
}

// Helper to get the claim name and claim value from claim value id
func (s *accountAuth) HelperClaimFromClaimValueId(claimValueId int64) (string, string, error) {
	var claimName string
	var claimValue string
	sqlstring := `SELECT c.chvClaimName, v.chvClaimVal FROM tb_ClaimValue AS v JOIN tb_Claim AS c ON v.inbClaimNameId = c.inbClaimNameId  
	WHERE v.inbClaimValueId = ? AND v.bitIsDeleted = 0 AND c.bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		return claimName, claimValue, err
	}

	defer stmt.Close()

	err = stmt.QueryRow(claimValueId).Scan(&claimName, &claimValue)

	return claimName, claimValue, err
}

func (s *accountAuth) HelperRoleContains(roleId int64, claimName string, claimValue string) bool {

	sqlstring := `SELECT c.chvClaimName,  v.chvClaimVal FROM tb_RoleClaimMap AS r JOIN  tb_ClaimValue AS v ON r.inbClaimValueId = v.inbClaimValueId  
	JOIN tb_Claim AS c on v.inbClaimNameId = c.inbClaimNameId  where r.inbRoleId = ? AND r.bitIsDeleted = 0 AND 
	v.bitIsDeleted = 0 AND c.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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

// Copyright 2019-2022 Demian Harvill
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

// The acctservice pakage provides the implementation of the MServiceAccount.proto GRPC service.
package acctservice

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	// "fmt"
	"io/ioutil"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"

	"google.golang.org/grpc"

	"database/sql"

	_ "github.com/lib/pq"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

var NotImplemented = errors.New("not implemented")

type accountService struct {
	pb.UnimplementedMServiceAccountServer
	logger           log.Logger
	db               *sql.DB
	rsaPSSPrivateKey *rsa.PrivateKey
	leaseMinutes     int
	startSecs        int64
}

// Get a new accountService instance.
func NewAccountService() *accountService {
	svc := accountService{}
	svc.startSecs = time.Now().Unix()
	return &svc
}

// Set the logger for the accountService instance.
func (s *accountService) SetLogger(logger log.Logger) {
	s.logger = logger
}

// Set the private key for the accountService instance used to sign the Javascript Web Token.
func (s *accountService) SetPrivateKey(privateKeyFile string) error {
	privateKey, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		level.Error(s.logger).Log("what", "SetPrivateKey", "error", err)
		return err
	}
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)

	if parsedKey != nil {
		level.Debug(s.logger).Log("msg", "parsed the private key")
	}

	if err != nil {
		level.Error(s.logger).Log("what", "ParseRSAPrivateKeyFromPEM", "error", err)
		return err
	}

	s.rsaPSSPrivateKey = parsedKey

	return err
}

// Set the number of minutes the JWT will be valid after creation.
func (s *accountService) SetLeaseMinutes(minutes int) {
	s.leaseMinutes = minutes
}

// Set the database connection for the accountService instance.
func (s *accountService) SetDatabaseConnection(sqlDB *sql.DB) {
	s.db = sqlDB
}

// Create a new GRPC server using this accountService instance.
func (s *accountService) NewApiServer(gServer *grpc.Server) error {
	if s != nil {
		pb.RegisterMServiceAccountServer(gServer, s)
	}
	return nil
}

// Support for login based on account, user and password.
func (s *accountService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	resp := &pb.LoginResponse{}
	var err error

	sqlstring := `SELECT au.user_id, au.password_enc, ac.account_id 
	FROM tb_accountuser AS au
	JOIN tb_account AS ac
	ON au.account_id = ac.account_id
	WHERE ac.account_name = $1 AND au.email = $2 AND au.is_deleted = false AND ac.is_deleted = false`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var passwordEnc string
	var userId int64
	var accountId int64

	err = stmt.QueryRow(req.GetAccountName(), req.GetEmail()).Scan(&userId, &passwordEnc, &accountId)

	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		return resp, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordEnc), []byte(req.GetPassword()))
	if err != nil {
		resp.ErrorCode = 503
		resp.ErrorMessage = "password invalid"
		return resp, nil
	}

	// get roles and claims
	var userRoles []*pb.AccountRole
	userRoles, err = s.GetAccountRolesByUserId(userId)
	if err != nil {
		resp.ErrorCode = 503
		resp.ErrorMessage = "no permissions"
		return resp, nil
	}

	// fmt.Printf("userRoles: %v\n", userRoles)
	// fmt.Printf("roles count: %d\n", len(userRoles))

	// token := jwt.New(jwt.SigningMethodPS256)

	claimMap := jwt.MapClaims{}

	claimMap["uid"] = userId
	claimMap["aid"] = accountId
	claimMap["actname"] = req.GetAccountName()
	claimMap["iss"] = time.Now().Unix()
	claimMap["exp"] = time.Now().Add(time.Minute * time.Duration(s.leaseMinutes)).Unix()

	// get all the claims

	for _, role := range userRoles {
		// fmt.Printf("role: %s\n", role.GetRoleName())
		for _, claimVal := range role.GetClaimValues() {
			val := claimVal.GetClaimVal()
			key := claimVal.GetClaim().GetClaimName()
			claimMap[key] = val
			// fmt.Printf("key: %s, val: %s\n", key, val)
		}

	}

	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claimMap)

	tokenString, err := token.SignedString(s.rsaPSSPrivateKey)

	if err == nil {
		// fmt.Printf("token: %s\n", tokenString)
		resp.Jwt = tokenString
	} else {
		level.Error(s.logger).Log("what", "SignedString", "error", err)
	}

	return resp, err
}

// get current server version and uptime - health check
func (s *accountService) GetServerVersion(ctx context.Context, req *pb.GetServerVersionRequest) (*pb.GetServerVersionResponse, error) {
	resp := &pb.GetServerVersionResponse{}

	currentSecs := time.Now().Unix()
	resp.ServerVersion = "v0.9.5"
	resp.ServerUptime = currentSecs - s.startSecs

	return resp, nil
}

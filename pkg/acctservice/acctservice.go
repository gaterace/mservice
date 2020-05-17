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

// The acctservice pakage provides the implementation of the MServiceAccount.proto GRPC service.
package acctservice

import (
	"context"
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"

	"google.golang.org/grpc"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

var NotImplemented = errors.New("not implemented")

type accountService struct {
	logger           *log.Logger
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
func (s *accountService) SetLogger(logger *log.Logger) {
	s.logger = logger
}

// Set the provate key for the accountService instance used to sign the Javascript Web Token.
func (s *accountService) SetPrivateKey(privateKeyFile string) error {
	privateKey, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		s.logger.Printf("error reading privateKeyFile: %v\n", err)
		return err
	}
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)

	if parsedKey != nil {
		s.logger.Println("parsed the private key")
	}

	if err != nil {
		s.logger.Printf("error parsing privateKeyFile: %v\n", err)
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
	s.logger.Printf("Login called for %s\n", req.GetEmail())
	resp := &pb.LoginResponse{}
	var err error

	sqlstring := `SELECT au.inbUserId, au.chvPasswordEnc, ac.inbAccountId 
	FROM tb_AccountUser AS au
	JOIN tb_Account AS ac
	ON au.inbAccountId = ac.inbAccountId
	WHERE ac.chvAccountName = ? AND au.chvEmail = ? AND au.bitIsDeleted = 0 AND ac.bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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

	s.logger.Printf("userId: %d, passwordEnc: %s\n", userId, passwordEnc)

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

	s.logger.Printf("userRoles: %v\n", userRoles)

	s.logger.Printf("roles count: %d\n", len(userRoles))

	// token := jwt.New(jwt.SigningMethodPS256)

	claimMap := jwt.MapClaims{}

	claimMap["uid"] = userId
	claimMap["aid"] = accountId
	claimMap["actname"] = req.GetAccountName()
	claimMap["iss"] = time.Now().Unix()
	claimMap["exp"] = time.Now().Add(time.Minute * time.Duration(s.leaseMinutes)).Unix()

	// get all the claims

	for _, role := range userRoles {
		s.logger.Printf("role: %s\n", role.GetRoleName())
		for _, claimVal := range role.GetClaimValues() {
			val := claimVal.GetClaimVal()
			key := claimVal.GetClaim().GetClaimName()
			claimMap[key] = val
			s.logger.Printf("key: %s, val: %s\n", key, val)
		}

	}

	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claimMap)

	tokenString, err := token.SignedString(s.rsaPSSPrivateKey)

	if err == nil {
		s.logger.Printf("token: %s\n", tokenString)
		resp.Jwt = tokenString
	} else {
		s.logger.Printf("unable to generate jwt: %v\n", err)
	}

	return resp, err
}

// get current server version and uptime - health check
func (s *accountService) GetServerVersion(ctx context.Context, req *pb.GetServerVersionRequest) (*pb.GetServerVersionResponse, error) {
	s.logger.Printf("GetServerVersion called\n")
	resp := &pb.GetServerVersionResponse{}

	currentSecs := time.Now().Unix()
	resp.ServerVersion = "v0.9.2"
	resp.ServerUptime = currentSecs - s.startSecs

	return resp, nil
}

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

package acctservice

import (
	"context"
	"database/sql"

	"github.com/gaterace/dml-go/pkg/dml"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

// create an account user
func (s *accountService) CreateAccountUser(ctx context.Context, req *pb.CreateAccountUserRequest) (*pb.CreateAccountUserResponse, error) {
	s.logger.Printf("CreateAccountUser called for %s\n", req.GetEmail())
	resp := &pb.CreateAccountUserResponse{}
	var err error

	sqlstring1 := `SELECT inbAccountId FROM tb_Account WHERE inbAccountId = ? AND bitIsDeleted = 0`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring1 failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	var testAccountId int64
	err = stmt1.QueryRow(req.GetAccountId()).Scan(&testAccountId)

	if err != nil {
		resp.ErrorCode = 502
		resp.ErrorMessage = "unable to match existing account"
		s.logger.Printf("unable to match existng account: %s\n", err.Error())
		return resp, nil

	}

	sqlstring := `INSERT INTO tb_AccountUser  (
	dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, inbAccountId, chvEmail, chvUserFullName, intUserType, chvPasswordEnc)
	VALUES (NOW(), NOW(), NOW(), 0, 1,
	?, ?, ?, ?, ?)`

	// generate encrypted password
	enc, err := bcrypt.GenerateFromPassword([]byte(req.GetPasswordEnc()), 12)
	if err != nil {
		resp.ErrorCode = 502
		resp.ErrorMessage = "unable to bcrypt password"
		s.logger.Printf("unable to bcrypt password: %s\n", err.Error())
		return resp, nil
	}

	passwordEnc := string(enc)

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetAccountId(), req.GetEmail(), req.GetUserFullName(), req.GetUserType(), passwordEnc)

	if err == nil {
		userId, err := res.LastInsertId()
		if err != nil {
			s.logger.Printf("LastInsertId err: %v\n", err)
		} else {
			s.logger.Printf("userId %d", userId)
		}

		resp.UserId = userId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// update an existing account user
func (s *accountService) UpdateAccountUser(ctx context.Context, req *pb.UpdateAccountUserRequest) (*pb.UpdateAccountUserResponse, error) {
	s.logger.Printf("UpdateAccountUser called for %d\n", req.GetUserId())
	resp := &pb.UpdateAccountUserResponse{}
	var err error

	sqlstring := `UPDATE tb_AccountUser SET dtmModified = NOW(), intVersion = ?, chvEmail = ?, chvUserFullName = ?, intUserType = ?
    WHERE inbUserId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetEmail(), req.GetUserFullName(), req.GetUserType(), req.GetUserId(), req.GetVersion())
	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// update an existing account user password
func (s *accountService) UpdateAccountUserPassword(ctx context.Context, req *pb.UpdateAccountUserPasswordRequest) (*pb.UpdateAccountUserPasswordResponse, error) {
	s.logger.Printf("UpdateAccountUserPassword called for %d\n", req.GetUserId())
	resp := &pb.UpdateAccountUserPasswordResponse{}
	var err error

	s.logger.Printf("oldpwd: %s, newpwd: %s\n", req.GetPasswordOld(), req.GetPasswordEnc())

	sqlstring1 := `SELECT chvPasswordEnc FROM tb_AccountUser WHERE inbUserId = ? AND bitIsDeleted = 0`
	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring1 failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	var oldPasswordEnc string

	err = stmt1.QueryRow(req.GetUserId()).Scan(&oldPasswordEnc)

	if err != nil {
		s.logger.Printf("select chvPasswordEnc failed: %v\n", err)
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		return resp, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(oldPasswordEnc), []byte(req.GetPasswordOld()))
	if err != nil {
		resp.ErrorCode = 503
		resp.ErrorMessage = "old password invalid"
		return resp, nil
	}

	enc, err := bcrypt.GenerateFromPassword([]byte(req.GetPasswordEnc()), 12)
	if err != nil {
		resp.ErrorCode = 502
		resp.ErrorMessage = "unable to bcrypt password"
		s.logger.Printf("unable to bcrypt password: %s\n", err.Error())
		return resp, nil
	}

	passwordEnc := string(enc)

	sqlstring := `UPDATE tb_AccountUser SET dtmModified = NOW(), intVersion = ?, chvPasswordEnc = ?
	WHERE inbUserId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, passwordEnc, req.GetUserId(), req.GetVersion())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			s.logger.Printf("unable to update password")
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// delete an existing account user
func (s *accountService) DeleteAccountUser(ctx context.Context, req *pb.DeleteAccountUserRequest) (*pb.DeleteAccountUserResponse, error) {
	s.logger.Printf("DeleteAccountUser called for %d\n", req.GetUserId())
	resp := &pb.DeleteAccountUserResponse{}
	var err error

	sqlstring := `UPDATE tb_AccountUser SET dtmDeleted = NOW(), bitIsDeleted = 1, intVersion = ?
	WHERE inbUserId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetUserId(), req.GetVersion())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// get an account user by id
func (s *accountService) GetAccountUserById(ctx context.Context, req *pb.GetAccountUserByIdRequest) (*pb.GetAccountUserByIdResponse, error) {
	s.logger.Printf("GetAccountUserById called for %d\n", req.GetUserId())
	resp := &pb.GetAccountUserByIdResponse{}
	var err error

	sqlstring := `SELECT inbUserId, dtmCreated, dtmModified, intVersion, inbAccountId, chvEmail, chvUserFullName, intUserType
	FROM tb_AccountUser where inbUserId = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var user pb.AccountUser
	var created string
	var modified string

	err = stmt.QueryRow(req.GetUserId()).Scan(&user.UserId, &created, &modified, &user.Version, &user.AccountId, &user.Email, &user.UserFullName, &user.UserType)

	if err == nil {
		user.Created = dml.DateTimeFromString(created)
		user.Modified = dml.DateTimeFromString(modified)
		var roles, err = s.GetAccountRolesByUserId(user.GetUserId())
		if err == nil {
			user.AccountRoles = roles
			// s.logger.Printf("roles count: %d\n", len(roles))
		} else {
			s.logger.Printf("get account roles failed; %v\n", err)
		}
		resp.AccountUser = &user
	} else if err == sql.ErrNoRows {
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		err = nil
	} else {
		s.logger.Printf("queryRow failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		err = nil
	}

	// TODO: get account roles

	return resp, err

}

// get an account user by email
func (s *accountService) GetAccountUserByEmail(ctx context.Context, req *pb.GetAccountUserByEmailRequest) (*pb.GetAccountUserByEmailResponse, error) {
	s.logger.Printf("GetAccountUserByEmail called for %d\n", req.GetEmail())
	resp := &pb.GetAccountUserByEmailResponse{}
	var err error

	sqlstring := `SELECT u.inbUserId, u.dtmCreated, u.dtmModified, u.intVersion, u.inbAccountId, u.chvEmail, u.chvUserFullName, u.intUserType
	FROM tb_AccountUser AS u 
	JOIN tb_Account AS a
	ON u.inbAccountId = a.inbAccountId
	WHERE a.chvAccountName = ? AND u.ChvEmail = ? AND u.bitIsDeleted = 0 AND a.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var user pb.AccountUser
	var created string
	var modified string

	err = stmt.QueryRow(req.GetAccountName(), req.GetEmail()).Scan(&user.UserId, &created, &modified, &user.Version, &user.AccountId, &user.Email, &user.UserFullName, &user.UserType)

	if err == nil {
		user.Created = dml.DateTimeFromString(created)
		user.Modified = dml.DateTimeFromString(modified)
		var roles, err = s.GetAccountRolesByUserId(user.GetUserId())
		if err == nil {
			user.AccountRoles = roles
		}

		resp.AccountUser = &user
	} else if err == sql.ErrNoRows {
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		err = nil
	} else {
		s.logger.Printf("queryRow failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		err = nil
	}

	// TODO: get account roles

	return resp, err

}

// get all account users in account
func (s *accountService) GetAccountUsers(ctx context.Context, req *pb.GetAccountUsersRequest) (*pb.GetAccountUsersResponse, error) {
	s.logger.Printf("GetAccountUsers called for %d\n", req.GetAccountName())
	resp := &pb.GetAccountUsersResponse{}
	var err error

	sqlstring := `SELECT u.inbUserId, u.dtmCreated, u.dtmModified, u.intVersion, u.inbAccountId, u.chvEmail, u.chvUserFullName, u.intUserType
	FROM tb_AccountUser AS u 
	JOIN tb_Account AS a
	ON u.inbAccountId = a.inbAccountId
	WHERE a.chvAccountName = ? AND u.bitIsDeleted = 0 AND a.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	rows, err := stmt.Query(req.GetAccountName())
	if err != nil {
		s.logger.Printf("queryRow failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	defer rows.Close()
	for rows.Next() {
		var user pb.AccountUser
		var created string
		var modified string

		err = rows.Scan(&user.UserId, &created, &modified, &user.Version, &user.AccountId, &user.Email, &user.UserFullName, &user.UserType)
		if err != nil {
			s.logger.Printf("query rows scan  failed: %v\n", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}

		user.Created = dml.DateTimeFromString(created)
		user.Modified = dml.DateTimeFromString(modified)
		resp.AccountUsers = append(resp.AccountUsers, &user)

		// TODO: get account roles
	}

	return resp, err
}

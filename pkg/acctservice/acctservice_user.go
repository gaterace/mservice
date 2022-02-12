// Copyright 2019-22 Demian Harvill
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

	"github.com/go-kit/kit/log/level"

	"github.com/gaterace/dml-go/pkg/dml"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

// create an account user
func (s *accountService) CreateAccountUser(ctx context.Context, req *pb.CreateAccountUserRequest) (*pb.CreateAccountUserResponse, error) {
	resp := &pb.CreateAccountUserResponse{}
	var err error

	sqlstring1 := `SELECT account_id FROM tb_account WHERE account_id = ? AND is_deleted = 0`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
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
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		return resp, nil

	}

	sqlstring := `INSERT INTO tb_accountuser  (
	created, modified, deleted, is_deleted, version, account_id, email, user_full_name, user_type, password_enc)
	VALUES (now(), now(), now(), false, 1,
	$1, $2, $3, $4, $5) RETURNING user_id`

	// generate encrypted password
	enc, err := bcrypt.GenerateFromPassword([]byte(req.GetPasswordEnc()), 12)
	if err != nil {
		resp.ErrorCode = 502
		resp.ErrorMessage = "unable to bcrypt password"
		level.Error(s.logger).Log("what", "GenerateFromPassword", "error", err)
		return resp, nil
	}

	passwordEnc := string(enc)

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var userId int64

	err = stmt.QueryRow(req.GetAccountId(), req.GetEmail(), req.GetUserFullName(), req.GetUserType(), passwordEnc).Scan(&userId)

	if err == nil {
		resp.UserId = userId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		err = nil
	}

	return resp, err
}

// update an existing account user
func (s *accountService) UpdateAccountUser(ctx context.Context, req *pb.UpdateAccountUserRequest) (*pb.UpdateAccountUserResponse, error) {
	resp := &pb.UpdateAccountUserResponse{}
	var err error

	sqlstring := `UPDATE tb_accountuser SET modified = now(), version = $1, email = $2, user_full_name = $3, user_type = $4
    WHERE user_id = $5 AND version = $6 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
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
		level.Error(s.logger).Log("what", "Exec", "error", err)
		err = nil
	}

	return resp, err
}

// update an existing account user password
func (s *accountService) UpdateAccountUserPassword(ctx context.Context, req *pb.UpdateAccountUserPasswordRequest) (*pb.UpdateAccountUserPasswordResponse, error) {
	resp := &pb.UpdateAccountUserPasswordResponse{}
	var err error

	sqlstring1 := `SELECT password_enc FROM tb_accountuser WHERE user_id = $1 AND is_deleted = false`
	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	var oldPasswordEnc string

	err = stmt1.QueryRow(req.GetUserId()).Scan(&oldPasswordEnc)

	if err != nil {
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
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
		level.Error(s.logger).Log("what", "GenerateFromPassword", "error", err)
		return resp, nil
	}

	passwordEnc := string(enc)

	sqlstring := `UPDATE tb_accountuser SET modified = now(), version = $1, password_enc = $2
	WHERE user_id = $3 AND version = $4 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
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
			level.Error(s.logger).Log("what", "Exec", "error", err)
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		level.Error(s.logger).Log("what", "Exec", "error", err)
		err = nil
	}

	return resp, err
}

// delete an existing account user
func (s *accountService) DeleteAccountUser(ctx context.Context, req *pb.DeleteAccountUserRequest) (*pb.DeleteAccountUserResponse, error) {
	resp := &pb.DeleteAccountUserResponse{}
	var err error

	sqlstring := `UPDATE tb_accountuser SET deleted = now(), is_deleted = true, version = $1
	WHERE user_id = $2 AND version = $3 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
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
		level.Error(s.logger).Log("what", "Exec", "error", err)
		err = nil
	}

	return resp, err
}

// get an account user by id
func (s *accountService) GetAccountUserById(ctx context.Context, req *pb.GetAccountUserByIdRequest) (*pb.GetAccountUserByIdResponse, error) {
	resp := &pb.GetAccountUserByIdResponse{}
	var err error

	sqlstring := `SELECT user_id, created, modified, version, account_id, email, user_full_name, user_type
	FROM tb_accountuser where user_id = $1 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
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
			level.Error(s.logger).Log("what", "GetAccountRolesByUserId", "error", err)
		}
		resp.AccountUser = &user
	} else if err == sql.ErrNoRows {
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		err = nil
	} else {
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		err = nil
	}

	// TODO: get account roles

	return resp, err

}

// get an account user by email
func (s *accountService) GetAccountUserByEmail(ctx context.Context, req *pb.GetAccountUserByEmailRequest) (*pb.GetAccountUserByEmailResponse, error) {
	resp := &pb.GetAccountUserByEmailResponse{}
	var err error

	sqlstring := `SELECT u.user_id, u.created, u.modified, u.version, u.account_id, u.email, u.user_full_name, u.user_type
	FROM tb_accountuser AS u 
	JOIN tb_account AS a
	ON u.account_id = a.account_id
	WHERE a.account_name = $1 AND u.email = $2 AND u.is_deleted = false AND a.is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
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
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		err = nil
	}

	// TODO: get account roles

	return resp, err

}

// get all account users in account
func (s *accountService) GetAccountUsers(ctx context.Context, req *pb.GetAccountUsersRequest) (*pb.GetAccountUsersResponse, error) {
	resp := &pb.GetAccountUsersResponse{}
	var err error

	sqlstring := `SELECT u.user_id, u.created, u.modified, u.version, u.account_id, u.email, u.user_full_name, u.user_type
	FROM tb_accountuser AS u 
	JOIN tb_account AS a
	ON u.account_id = a.account_id
	WHERE a.account_name = $1 AND u.is_deleted = false AND a.is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	rows, err := stmt.Query(req.GetAccountName())
	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)
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
			level.Error(s.logger).Log("what", "Scan", "error", err)
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

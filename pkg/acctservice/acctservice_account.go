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

package acctservice

import (
	"context"
	"database/sql"
	"github.com/go-kit/kit/log/level"

	"github.com/gaterace/dml-go/pkg/dml"

	_ "github.com/go-sql-driver/mysql"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

// Create a new account.
func (s *accountService) CreateAccount(ctx context.Context, req *pb.CreateAccountRequest) (*pb.CreateAccountResponse, error) {
	resp := &pb.CreateAccountResponse{}
	var err error

	sqlstring := `INSERT INTO tb_Account (
		dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, 
		chvAccountName, chvAccountLongName, intAccountType, chvAddress1, chvAddress2,
		chvCity, chvState, chvPostalCode, chvCountryCode, chvPhone, chvEmail)
		VALUES (NOW(), NOW(), NOW(), 0, 1, 
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?, ?)`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetAccountName(), req.GetAccountLongName(), req.GetAccountType(), req.GetAddress1(),
		req.GetAddress2(), req.GetCity(), req.GetState(), req.GetPostalCode(), req.GetCountryCode(),
		req.GetPhone(), req.GetEmail())

	if err == nil {
		accountId, err := res.LastInsertId()
		if err != nil {
			level.Error(s.logger).Log("what", "LastInsertId", "error", err)
		} else {
			level.Debug(s.logger).Log("accountId", accountId)
		}

		resp.AccountId = accountId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		level.Error(s.logger).Log("what", "Exec", "error", err)
		err = nil
	}

	return resp, err
}

// update an existing account
func (s *accountService) UpdateAccount(ctx context.Context, req *pb.UpdateAccountRequest) (*pb.UpdateAccountResponse, error) {
	resp := &pb.UpdateAccountResponse{}
	var err error

	sqlstring := `UPDATE tb_Account SET dtmModified = NOW(), intVersion = ?, chvAccountName = ?, chvAccountLongName = ?,
    intAccountType = ?, chvAddress1 = ?, chvAddress2 = ?, chvCity = ?, chvState = ?, chvPostalCode = ?,
    chvCountryCode = ?, chvPhone = ?, chvEmail = ? WHERE inbAccountId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetAccountName(), req.GetAccountLongName(), req.GetAccountType(), req.GetAddress1(),
		req.GetAddress2(), req.GetCity(), req.GetState(), req.GetPostalCode(), req.GetCountryCode(),
		req.GetPhone(), req.GetEmail(), req.GetAccountId(), req.GetVersion())

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

// delete an existing account
func (s *accountService) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.DeleteAccountResponse, error) {
	resp := &pb.DeleteAccountResponse{}
	var err error

	sqlstring := `UPDATE tb_Account SET bitIsDeleted = 1, dtmDeleted = NOW(), intVersion = ? 
	WHERE inbAccountId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetAccountId(), req.GetVersion())

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

// get an account by account id
func (s *accountService) GetAccountById(ctx context.Context, req *pb.GetAccountByIdRequest) (*pb.GetAccountByIdResponse, error) {
	resp := &pb.GetAccountByIdResponse{}

	var sqlstring string = `SELECT inbAccountId, dtmCreated, dtmModified, intVersion, chvAccountName, chvAccountLongName,
	intAccountType, chvAddress1, chvAddress2, chvCity, chvState, chvPostalCode, chvCountryCode, chvPhone,
	chvEmail FROM tb_Account WHERE inbAccountId = ? AND bitIsDeleted = 0`

	var account pb.Account
	var created string
	var modified string

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	err = stmt.QueryRow(req.AccountId).Scan(&account.AccountId, &created, &modified, &account.Version,
		&account.AccountName, &account.AccountLongName, &account.AccountType, &account.Address1,
		&account.Address2, &account.City, &account.State, &account.PostalCode,
		&account.CountryCode, &account.Phone, &account.Email)
	if err == nil {
		account.Created = dml.DateTimeFromString(created)
		account.Modified = dml.DateTimeFromString(modified)
		resp.ErrorCode = 0
		resp.Account = &account

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

	return resp, err
}

// get an account by account name
func (s *accountService) GetAccountByName(ctx context.Context, req *pb.GetAccountByNameRequest) (*pb.GetAccountByNameResponse, error) {
	resp := &pb.GetAccountByNameResponse{}

	var sqlstring string = `SELECT inbAccountId, dtmCreated, dtmModified, intVersion, chvAccountName, chvAccountLongName,
	intAccountType, chvAddress1, chvAddress2, chvCity, chvState, chvPostalCode, chvCountryCode, chvPhone,
	chvEmail FROM tb_Account WHERE chvAccountName = ? AND bitIsDeleted = 0`

	var account pb.Account
	var created string
	var modified string

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	err = stmt.QueryRow(req.GetAccountName()).Scan(&account.AccountId, &created, &modified, &account.Version,
		&account.AccountName, &account.AccountLongName, &account.AccountType, &account.Address1,
		&account.Address2, &account.City, &account.State, &account.PostalCode,
		&account.CountryCode, &account.Phone, &account.Email)
	if err == nil {
		account.Created = dml.DateTimeFromString(created)
		account.Modified = dml.DateTimeFromString(modified)
		resp.ErrorCode = 0
		resp.Account = &account

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

	return resp, err
}

// get all account names
func (s *accountService) GetAccountNames(ctx context.Context, req *pb.GetAccountNamesRequest) (*pb.GetAccountNamesResponse, error) {
	resp := &pb.GetAccountNamesResponse{}

	var sqlstring string = `SELECT chvAccountName FROM tb_Account WHERE bitIsDeleted = 0`
	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	rows, err := stmt.Query()

	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	defer rows.Close()
	for rows.Next() {
		var accountName string
		err = rows.Scan(&accountName)
		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}

		resp.AccountName = append(resp.AccountName, accountName)
	}

	return resp, err
}

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

package acctservice

import (
	"context"
	"database/sql"

	"github.com/go-kit/kit/log/level"

	"github.com/gaterace/dml-go/pkg/dml"

	_ "github.com/lib/pq"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

// create account role
func (s *accountService) CreateAccountRole(ctx context.Context, req *pb.CreateAccountRoleRequest) (*pb.CreateAccountRoleResponse, error) {
	resp := &pb.CreateAccountRoleResponse{}
	var err error

	sqlstring1 := `SELECT account_id FROM tb_account WHERE account_id = $1 AND is_deleted = false`

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

	sqlstring := `INSERT INTO tb_accountrole (created, modified, deleted, is_deleted, version, account_id, role_name)
	VALUES (now(), now(), now(), false, 1, $1, $2) RETURNING role_id`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var roleId int64

	err = stmt.QueryRow(req.GetAccountId(), req.GetRoleName()).Scan(&roleId)

	if err == nil {
		resp.RoleId = roleId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		err = nil
	}

	return resp, err
}

// update existing account role
func (s *accountService) UpdateAccountRole(ctx context.Context, req *pb.UpdateAccountRoleRequest) (*pb.UpdateAccountRoleResponse, error) {
	resp := &pb.UpdateAccountRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_accountrole SET modified = now(), version = $1, role_name = $2
	WHERE role_id = $3 AND version = $4 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetRoleName(), req.GetRoleId(), req.GetVersion())

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

// delete existing account role
func (s *accountService) DeleteAccountRole(ctx context.Context, req *pb.DeleteAccountRoleRequest) (*pb.DeleteAccountRoleResponse, error) {
	resp := &pb.DeleteAccountRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_accountrole SET deleted = now(), is_deleted = true, version = $1
	WHERE role_id = $2 AND version = $3 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetRoleId(), req.GetVersion())
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

// get account role by id
func (s *accountService) GetAccountRoleById(ctx context.Context, req *pb.GetAccountRoleByIdRequest) (*pb.GetAccountRoleByIdResponse, error) {
	resp := &pb.GetAccountRoleByIdResponse{}
	var err error

	sqlstring := `SELECT role_id, created, modified, version, account_id, role_name FROM tb_accountrole
	WHERE role_id = $1 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var role pb.AccountRole
	var created string
	var modified string

	err = stmt.QueryRow(req.GetRoleId()).Scan(&role.RoleId, &created, &modified, &role.Version, &role.AccountId, &role.RoleName)

	if err == nil {
		role.Created = dml.DateTimeFromString(created)
		role.Modified = dml.DateTimeFromString(modified)

		claimVals, err := s.GetClaimValuesByRoleById(role.GetRoleId())
		if err == nil {
			role.ClaimValues = claimVals
		}
		resp.AccountRole = &role
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

// get the claim values and claims for a role.
func (s *accountService) GetClaimValuesByRoleById(roleId int64) ([]*pb.ClaimValue, error) {
	var res []*pb.ClaimValue
	var err error

	sqlstring := `SELECT cv.claim_value_id, cv.created, cv.modified, cv.version, cv.claim_name_id, cv.claim_val, cv.claim_value_description,
	cn.claim_name_id, cn.created, cn.modified, cn.version, cn.claim_name, cn.claim_description
	FROM tb_roleclaimmap AS rcm
	JOIN tb_claimvalue AS cv
	ON rcm.claim_value_id = cv.claim_value_id
	JOIN tb_claim AS cn
	ON cv.claim_name_id = cn.claim_name_id
	WHERE rcm.role_id = $1 AND rcm.is_deleted = false and cv.is_deleted = false AND cn.is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return nil, err
	}

	rows, err := stmt.Query(roleId)

	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)

		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var claimVal pb.ClaimValue
		var createdVal string
		var modifiedVal string
		var claim pb.Claim
		var createdClaim string
		var modifiedClaim string

		err = rows.Scan(&claimVal.ClaimValueId, &createdVal, &modifiedVal, &claimVal.Version, &claimVal.ClaimNameId,
			&claimVal.ClaimVal, &claimVal.ClaimValueDescription, &claim.ClaimNameId, &createdClaim, &modifiedClaim,
			&claim.Version, &claim.ClaimName, &claim.ClaimDescription)

		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			return nil, err
		}

		claimVal.Created = dml.DateTimeFromString(createdVal)
		claimVal.Modified = dml.DateTimeFromString(modifiedVal)
		claim.Created = dml.DateTimeFromString(createdClaim)
		claim.Modified = dml.DateTimeFromString(modifiedClaim)
		claimVal.Claim = &claim

		res = append(res, &claimVal)

	}

	return res, nil
}

// get the claim values and claims for all roles in an account.
func (s *accountService) GetClaimValuesByAccountId(accountId int64) (map[int64][]*pb.ClaimValue, error) {
	res := make(map[int64][]*pb.ClaimValue)
	var err error

	sqlstring := `SELECT ar.role_id, cv.claim_value_id, cv.created, cv.modified, cv.version, cv.claim_name_id, cv.claim_val, cv.claim_value_description,
	cn.claim_name_id, cn.created, cn.modified, cn.version, cn.claim_name, cn.claim_description
	FROM tb_accountrole AS ar
	JOIN tb_roleclaimmap AS rcm
	ON ar.role_id = rcm.role_id
	JOIN tb_claimvalue AS cv
	ON rcm.claim_value_id = cv.claim_value_id
	JOIN tb_claim AS cn
	ON cv.claim_name_id = cn.claim_name_id
	WHERE ar.inbAccountId = $1 AND ar.is_deleted = false AND rcm.is_deleted = false and cv.is_deleted = false AND cn.is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return res, err
	}

	rows, err := stmt.Query(accountId)

	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)

		return res, err
	}

	defer rows.Close()
	for rows.Next() {
		var claimVal pb.ClaimValue
		var roleId int64
		var createdVal string
		var modifiedVal string
		var claim pb.Claim
		var createdClaim string
		var modifiedClaim string

		err = rows.Scan(&roleId, &claimVal.ClaimValueId, &createdVal, &modifiedVal, &claimVal.Version, &claimVal.ClaimNameId,
			&claimVal.ClaimVal, &claimVal.ClaimValueDescription, &claim.ClaimNameId, &createdClaim, &modifiedClaim,
			&claim.Version, &claim.ClaimName, &claim.ClaimDescription)

		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			return res, err
		}

		claimVal.Created = dml.DateTimeFromString(createdVal)
		claimVal.Modified = dml.DateTimeFromString(modifiedVal)
		claim.Created = dml.DateTimeFromString(createdClaim)
		claim.Modified = dml.DateTimeFromString(modifiedClaim)
		claimVal.Claim = &claim

		claimVals, ok := res[roleId]
		if !ok {
			claimVals = make([]*pb.ClaimValue, 0)
		}

		claimVals = append(claimVals, &claimVal)
		res[roleId] = claimVals
	}

	return res, nil
}

// get the claim values and claims for all roles for a user.
func (s *accountService) GetClaimValuesByUserId(userId int64) (map[int64][]*pb.ClaimValue, error) {
	res := make(map[int64][]*pb.ClaimValue)
	var err error

	sqlstring := `SELECT ar.role_id, cv.claim_value_id, cv.created, cv.modified, cv.version, cv.claim_name_id, cv.claim_val, cv.claim_value_description,
	cn.claim_name_id, cn.created, cn.modified, cn.version, cn.claim_name, cn.claim_description
	FROM tb_accountrolemap AS ar
	JOIN tb_roleclaimmap AS rcm
	ON ar.role_id = rcm.role_id
	JOIN tb_claimvalue AS cv
	ON rcm.claim_value_id = cv.claim_value_id
	JOIN tb_claim AS cn
	ON cv.claim_name_id = cn.claim_name_id
	WHERE ar.user_id = $1 AND ar.is_deleted = false AND rcm.is_deleted = false and cv.is_deleted = false AND cn.is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return res, err
	}

	rows, err := stmt.Query(userId)

	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)

		return res, err
	}

	defer rows.Close()
	for rows.Next() {
		var claimVal pb.ClaimValue
		var roleId int64
		var createdVal string
		var modifiedVal string
		var claim pb.Claim
		var createdClaim string
		var modifiedClaim string

		err = rows.Scan(&roleId, &claimVal.ClaimValueId, &createdVal, &modifiedVal, &claimVal.Version, &claimVal.ClaimNameId,
			&claimVal.ClaimVal, &claimVal.ClaimValueDescription, &claim.ClaimNameId, &createdClaim, &modifiedClaim,
			&claim.Version, &claim.ClaimName, &claim.ClaimDescription)

		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			return res, err
		}

		claimVal.Created = dml.DateTimeFromString(createdVal)
		claimVal.Modified = dml.DateTimeFromString(modifiedVal)
		claim.Created = dml.DateTimeFromString(createdClaim)
		claim.Modified = dml.DateTimeFromString(modifiedClaim)
		claimVal.Claim = &claim

		claimVals, ok := res[roleId]
		if !ok {
			claimVals = make([]*pb.ClaimValue, 0)
		}

		// s.logger.Printf("claimVal: %\n", claimVal)

		claimVals = append(claimVals, &claimVal)
		res[roleId] = claimVals
	}

	return res, nil
}

// get the roles associated with a user.
func (s *accountService) GetAccountRolesByUserId(userId int64) ([]*pb.AccountRole, error) {
	var roles []*pb.AccountRole
	var err error

	claimValMap, err := s.GetClaimValuesByUserId(userId)
	if err != nil {
		level.Error(s.logger).Log("what", "GetClaimValuesByUserId", "error", err)
		return roles, err
	}

	// s.logger.Printf("claimValMap: %v\n", claimValMap)

	sqlstring := `SELECT ar.role_id, ar.created, ar.modified, ar.version, ar.account_id, ar.role_name 
    FROM tb_accountrolemap AS rm
	JOIN tb_accountrole AS ar
	ON rm.role_id = ar.role_id
	WHERE rm.user_id = $1 AND ar.is_deleted = false AND rm.is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		return roles, err
	}

	defer stmt.Close()

	rows, err := stmt.Query(userId)

	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)
		return roles, err
	}

	defer rows.Close()

	for rows.Next() {
		var role pb.AccountRole
		var created string
		var modified string

		err = rows.Scan(&role.RoleId, &created, &modified, &role.Version, &role.AccountId, &role.RoleName)
		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			return roles, err
		}

		role.Created = dml.DateTimeFromString(created)
		role.Modified = dml.DateTimeFromString(modified)

		// s.logger.Printf("adding role %s\n", role.GetRoleName())

		claimValues := claimValMap[role.GetRoleId()]
		role.ClaimValues = claimValues

		roles = append(roles, &role)
	}

	return roles, nil
}

// get all account roles in account
func (s *accountService) GetAccountRoles(ctx context.Context, req *pb.GetAccountRolesRequest) (*pb.GetAccountRolesResponse, error) {
	resp := &pb.GetAccountRolesResponse{}
	var err error

	claimValMap, err := s.GetClaimValuesByAccountId(req.GetAccountId())
	if err != nil {
		level.Error(s.logger).Log("what", "GetClaimValuesByAccountId", "error", err)
	}

	sqlstring := `SELECT role_id, created, modified, version, account_id, role_name FROM tb_accountrole
	WHERE account_id = $1 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()
	rows, err := stmt.Query(req.GetAccountId())

	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	defer rows.Close()

	for rows.Next() {
		var role pb.AccountRole
		var created string
		var modified string

		err = rows.Scan(&role.RoleId, &created, &modified, &role.Version, &role.AccountId, &role.RoleName)
		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}

		role.Created = dml.DateTimeFromString(created)
		role.Modified = dml.DateTimeFromString(modified)

		claimValues := claimValMap[role.GetRoleId()]
		role.ClaimValues = claimValues

		resp.AccountRoles = append(resp.AccountRoles, &role)
	}

	return resp, err
}

// associate an account user with an account role
func (s *accountService) AddUserToRole(ctx context.Context, req *pb.AddUserToRoleRequest) (*pb.AddUserToRoleResponse, error) {
	resp := &pb.AddUserToRoleResponse{}
	var err error

	sqlstring := `INSERT INTO tb_accountrolemap (user_id, role_id, created, deleted, is_deleted)
	VALUES ($1, $2, now(), now(), false)`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetUserId(), req.GetRoleId())
	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected != 1 {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}

		return resp, err
	}

	// might be trying to add back a previously deleted entry

	sqlstring1 := `UPDATE tb_accountrolemap SET created = now(), deleted = now(), is_deleted = false
	WHERE  user_id = $1 AND role_id = $2 AND is_deleted = true`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	res, err = stmt1.Exec(req.GetUserId(), req.GetRoleId())
	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected != 1 {
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

// disassociate an account user from an account role
func (s *accountService) RemoveUserFromRole(ctx context.Context, req *pb.RemoveUserFromRoleRequest) (*pb.RemoveUserFromRoleResponse, error) {
	resp := &pb.RemoveUserFromRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_accountrolemap SET deleted = now(), is_deleted = true WHERE user_id = $1 AND role_id = $2 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetUserId(), req.GetRoleId())
	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected != 1 {
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

// associate a claim with an account role
func (s *accountService) AddClaimToRole(ctx context.Context, req *pb.AddClaimToRoleRequest) (*pb.AddClaimToRoleResponse, error) {
	resp := &pb.AddClaimToRoleResponse{}
	var err error

	sqlstring := `INSERT INTO tb_roleclaimmap (role_id, claim_value_id, created, deleted, is_deleted)
	VALUES($1, $2, now(), now(), false)`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetRoleId(), req.GetClaimValueId())
	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected != 1 {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}

		return resp, err
	}

	// might be trying to add back a previously deleted entry

	sqlstring1 := `UPDATE tb_roleclaimmap SET created = now(), deleted = now(), is_deleted = false
	WHERE role_id = $1 AND claim_value_id = $2 AND is_deleted = true`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	res, err = stmt1.Exec(req.GetRoleId(), req.GetClaimValueId())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected != 1 {
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

// remove a claim from an account role
func (s *accountService) RemoveClaimFromRole(ctx context.Context, req *pb.RemoveClaimFromRoleRequest) (*pb.RemoveClaimFromRoleResponse, error) {
	resp := &pb.RemoveClaimFromRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_roleclaimmap SET deleted = now(), is_deleted = true
	WHERE role_id = $1 AND claim_value_id = $2 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetRoleId(), req.GetClaimValueId())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected != 1 {
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

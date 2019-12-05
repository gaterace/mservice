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

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
)

// create account role
func (s *accountService) CreateAccountRole(ctx context.Context, req *pb.CreateAccountRoleRequest) (*pb.CreateAccountRoleResponse, error) {
	s.logger.Printf("CreateAccountRole called for %s\n", req.GetRoleName())
	resp := &pb.CreateAccountRoleResponse{}
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

	sqlstring := `INSERT INTO tb_AccountRole (dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, inbAccountId, chvRoleName)
	VALUES (NOW(), NOW(), NOW(), 0, 1, ?, ?)`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetAccountId(), req.GetRoleName())
	if err == nil {
		roleId, err := res.LastInsertId()
		if err != nil {
			s.logger.Printf("LastInsertId err: %v\n", err)
		} else {
			s.logger.Printf("roleId %d", roleId)
		}

		resp.RoleId = roleId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// update existing account role
func (s *accountService) UpdateAccountRole(ctx context.Context, req *pb.UpdateAccountRoleRequest) (*pb.UpdateAccountRoleResponse, error) {
	s.logger.Printf("UpdateAccountRole called for %d\n", req.GetRoleId())
	resp := &pb.UpdateAccountRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_AccountRole SET dtmModified = NOW(), intVersion = ?, chvRoleName = ?
	WHERE inbRoleId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// delete existing account role
func (s *accountService) DeleteAccountRole(ctx context.Context, req *pb.DeleteAccountRoleRequest) (*pb.DeleteAccountRoleResponse, error) {
	s.logger.Printf("DeleteAccountRole called for %d\n", req.GetRoleId())
	resp := &pb.DeleteAccountRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_AccountRole SET dtmDeleted = NOW(), bitIsDeleted = 1, intVersion = ?
	WHERE inbRoleId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// get account role by id
func (s *accountService) GetAccountRoleById(ctx context.Context, req *pb.GetAccountRoleByIdRequest) (*pb.GetAccountRoleByIdResponse, error) {
	s.logger.Printf("GetAccountRoleById called for %d\n", req.GetRoleId())
	resp := &pb.GetAccountRoleByIdResponse{}
	var err error

	sqlstring := `SELECT inbRoleId, dtmCreated, dtmModified, intVersion, inbAccountId, chvRoleName FROM tb_AccountRole
	WHERE inbRoleId = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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
		s.logger.Printf("queryRow failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		err = nil
	}

	return resp, err
}

// get the claim values and claims for a role.
func (s *accountService) GetClaimValuesByRoleById(roleId int64) ([]*pb.ClaimValue, error) {
	s.logger.Printf("GetClaimValuesByRoleById called for %d\n", roleId)
	var res []*pb.ClaimValue
	var err error

	sqlstring := `SELECT cv.inbClaimValueId, cv.dtmCreated, cv.dtmModified, cv.intVersion, cv.inbClaimNameId, cv.chvClaimVal, cv.chvClaimValueDescription,
	cn.inbClaimNameId, cn.dtmCreated, cn.dtmModified, cn.intVersion, cn.chvClaimName, cn.chvClaimDescription
	FROM tb_RoleClaimMap AS rcm
	JOIN tb_ClaimValue AS cv
	ON rcm.inbClaimValueId = cv.inbClaimValueId
	JOIN tb_Claim AS cn
	ON cv.inbClaimNameId = cn.inbClaimNameId
	WHERE rcm.inbRoleId = ? AND rcm.bitIsDeleted = 0 and cv.bitIsDeleted = 0 AND cn.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		return nil, err
	}

	rows, err := stmt.Query(roleId)

	if err != nil {
		s.logger.Printf("query rows failed: %v\n", err)

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
			s.logger.Printf("rows scan failed: %v\n", err)
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
	s.logger.Printf("GetClaimValuesByAccountId called for %d\n", accountId)
	res := make(map[int64][]*pb.ClaimValue)
	var err error

	sqlstring := `SELECT ar.inbRoleId, cv.inbClaimValueId, cv.dtmCreated, cv.dtmModified, cv.intVersion, cv.inbClaimNameId, cv.chvClaimVal, cv.chvClaimValueDescription,
	cn.inbClaimNameId, cn.dtmCreated, cn.dtmModified, cn.intVersion, cn.chvClaimName, cn.chvClaimDescription
	FROM tb_AccountRole AS ar
	JOIN tb_RoleClaimMap AS rcm
	ON ar.inbRoleId = rcm.inbRoleId
	JOIN tb_ClaimValue AS cv
	ON rcm.inbClaimValueId = cv.inbClaimValueId
	JOIN tb_Claim AS cn
	ON cv.inbClaimNameId = cn.inbClaimNameId
	WHERE ar.inbAccountId = ? AND ar.bitIsDeleted = 0 AND rcm.bitIsDeleted = 0 and cv.bitIsDeleted = 0 AND cn.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		return res, err
	}

	rows, err := stmt.Query(accountId)

	if err != nil {
		s.logger.Printf("query rows failed: %v\n", err)

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
			s.logger.Printf("rows scan failed: %v\n", err)
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
	s.logger.Printf("GetClaimValuesByUserId called for %d\n", userId)
	res := make(map[int64][]*pb.ClaimValue)
	var err error

	sqlstring := `SELECT ar.inbRoleId, cv.inbClaimValueId, cv.dtmCreated, cv.dtmModified, cv.intVersion, cv.inbClaimNameId, cv.chvClaimVal, cv.chvClaimValueDescription,
	cn.inbClaimNameId, cn.dtmCreated, cn.dtmModified, cn.intVersion, cn.chvClaimName, cn.chvClaimDescription
	FROM tb_AccountRoleMap AS ar
	JOIN tb_RoleClaimMap AS rcm
	ON ar.inbRoleId = rcm.inbRoleId
	JOIN tb_ClaimValue AS cv
	ON rcm.inbClaimValueId = cv.inbClaimValueId
	JOIN tb_Claim AS cn
	ON cv.inbClaimNameId = cn.inbClaimNameId
	WHERE ar.inbUserId = ? AND ar.bitIsDeleted = 0 AND rcm.bitIsDeleted = 0 and cv.bitIsDeleted = 0 AND cn.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		return res, err
	}

	rows, err := stmt.Query(userId)

	if err != nil {
		s.logger.Printf("query rows failed: %v\n", err)

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
			s.logger.Printf("rows scan failed: %v\n", err)
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
	s.logger.Printf("GetAccountRolesByUserId called for %d\n", userId)
	var roles []*pb.AccountRole
	var err error

	claimValMap, err := s.GetClaimValuesByUserId(userId)
	if err != nil {
		s.logger.Printf("unable to get claim value map for user: %v\n", err)
		return roles, err
	}

	// s.logger.Printf("claimValMap: %v\n", claimValMap)

	sqlstring := `SELECT ar.inbRoleId, ar.dtmCreated, ar.dtmModified, ar.intVersion, ar.inbAccountId, ar.chvRoleName 
    FROM tb_AccountRoleMap AS rm
	JOIN tb_AccountRole AS ar
	ON rm.inbRoleId = ar.inbRoleId
	WHERE rm.inbUserId = ? AND ar.bitIsDeleted = 0 AND rm.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		return roles, err
	}

	defer stmt.Close()

	rows, err := stmt.Query(userId)

	if err != nil {
		s.logger.Printf("query failed: %v\n", err)
		return roles, err
	}

	defer rows.Close()

	for rows.Next() {
		var role pb.AccountRole
		var created string
		var modified string

		err = rows.Scan(&role.RoleId, &created, &modified, &role.Version, &role.AccountId, &role.RoleName)
		if err != nil {
			s.logger.Printf("query rows scan  failed: %v\n", err)
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
	s.logger.Printf("GetAccountRoles called for %d\n", req.GetAccountId())
	resp := &pb.GetAccountRolesResponse{}
	var err error

	claimValMap, err := s.GetClaimValuesByAccountId(req.GetAccountId())
	if err != nil {
		s.logger.Printf("unable to get claim values for account : %v\n", err)
	}

	sqlstring := `SELECT inbRoleId, dtmCreated, dtmModified, intVersion, inbAccountId, chvRoleName FROM tb_AccountRole
	WHERE inbAccountId = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()
	rows, err := stmt.Query(req.GetAccountId())

	if err != nil {
		s.logger.Printf("query failed: %v\n", err)
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
			s.logger.Printf("query rows scan  failed: %v\n", err)
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
	s.logger.Printf("AddUserToRole called for user: %d , role: %d\n", req.GetUserId(), req.GetRoleId())
	resp := &pb.AddUserToRoleResponse{}
	var err error

	sqlstring := `INSERT INTO tb_AccountRoleMap (inbUserId, inbRoleId, dtmCreated, dtmDeleted, bitIsDeleted)
	VALUES (?, ?, NOW(), NOW(), 0)`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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

	sqlstring1 := `UPDATE tb_AccountRoleMap SET dtmCreated = NOW(), dtmDeleted = NOW(), bitIsDeleted = 0
	WHERE  inbUserId = ? AND inbRoleId = ? AND bitIsDeleted = 1`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring1 failed: %v\n", err)
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
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// disassociate an account user from an account role
func (s *accountService) RemoveUserFromRole(ctx context.Context, req *pb.RemoveUserFromRoleRequest) (*pb.RemoveUserFromRoleResponse, error) {
	s.logger.Printf("RemoveUserFromRole called for %d : %d\n", req.GetUserId(), req.GetRoleId())
	resp := &pb.RemoveUserFromRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_AccountRoleMap SET dtmDeleted = NOW(), bitIsDeleted = 1 WHERE inbUserId = ? AND inbRoleId = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// associate a claim with an account role
func (s *accountService) AddClaimToRole(ctx context.Context, req *pb.AddClaimToRoleRequest) (*pb.AddClaimToRoleResponse, error) {
	s.logger.Printf("AddClaimToRole called for %d : %d\n", req.GetClaimValueId(), req.GetRoleId())
	resp := &pb.AddClaimToRoleResponse{}
	var err error

	sqlstring := `INSERT INTO tb_RoleClaimMap (inbRoleId, inbClaimValueId, dtmCreated, dtmDeleted, bitIsDeleted)
	VALUES(?, ?, NOW(), NOW(), 0)`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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

	sqlstring1 := `UPDATE tb_RoleClaimMap SET dtmCreated = NOW(), dtmDeleted = NOW(), bitIsDeleted = 0
	WHERE inbRoleId = ? AND inbClaimValueId = ? AND bitIsDeleted = 1`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring1 failed: %v\n", err)
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
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// remove a claim from an account role
func (s *accountService) RemoveClaimFromRole(ctx context.Context, req *pb.RemoveClaimFromRoleRequest) (*pb.RemoveClaimFromRoleResponse, error) {
	s.logger.Printf("RemoveClaimFromRole called for %d : %d\n", req.GetClaimValueId(), req.GetRoleId())
	resp := &pb.RemoveClaimFromRoleResponse{}
	var err error

	sqlstring := `UPDATE tb_RoleClaimMap SET dtmDeleted = NOW(), bitIsDeleted = 1
	WHERE inbRoleId = ? AND inbClaimValueId = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
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
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

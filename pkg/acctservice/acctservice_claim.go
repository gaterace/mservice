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
	pb "github.com/gaterace/mservice/pkg/mserviceaccount"

	_ "github.com/lib/pq"
)

// create a claim name
func (s *accountService) CreateClaimName(ctx context.Context, req *pb.CreateClaimNameRequest) (*pb.CreateClaimNameResponse, error) {
	resp := &pb.CreateClaimNameResponse{}
	var err error

	sqlstring := `INSERT INTO tb_claim (
		created, modified, deleted, is_deleted, version, claim_name, claim_description)
		VALUES(now(), now(), now(), false, 1, $1, $2) RETURNING claim_name_id`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var claimNameId int64

	err = stmt.QueryRow(req.GetClaimName(), req.GetClaimDescription()).Scan(&claimNameId)

	if err == nil {
		resp.ClaimNameId = claimNameId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		err = nil
	}

	return resp, err
}

// update an existing claim name
func (s *accountService) UpdateClaimName(ctx context.Context, req *pb.UpdateClaimNameRequest) (*pb.UpdateClaimNameResponse, error) {
	resp := &pb.UpdateClaimNameResponse{}
	var err error

	sqlstring := `UPDATE tb_claim SET modified = now(), version = $1, claim_name = $2, claim_description = $3
	WHERE claim_name_id = $4 AND version = $5 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetClaimName(), req.GetClaimDescription(), req.GetClaimNameId(), req.GetVersion())

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

// delete an existing claim name
func (s *accountService) DeleteClaimName(ctx context.Context, req *pb.DeleteClaimNameRequest) (*pb.DeleteClaimNameResponse, error) {
	resp := &pb.DeleteClaimNameResponse{}
	var err error

	sqlstring := `UPDATE tb_claim SET deleted = now(), is_deleted = true,  version = $1
	WHERE claim_name_id = $2 AND version = $3 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetClaimNameId(), req.GetVersion())

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

// get all claim names
func (s *accountService) GetClaimNames(ctx context.Context, req *pb.GetClaimNamesRequest) (*pb.GetClaimNamesResponse, error) {
	resp := &pb.GetClaimNamesResponse{}
	var err error

	sqlstring := `SELECT claim_name_id, created, modified, version, claim_name, claim_description
	FROM tb_claim WHERE is_deleted = false`

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
		var claim pb.Claim
		var created string
		var modified string
		err = rows.Scan(&claim.ClaimNameId, &created, &modified, &claim.Version, &claim.ClaimName, &claim.ClaimDescription)
		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}
		claim.Created = dml.DateTimeFromString(created)
		claim.Modified = dml.DateTimeFromString(modified)
		resp.Claims = append(resp.Claims, &claim)

	}

	return resp, err
}

// create claim value
func (s *accountService) CreateClaimValue(ctx context.Context, req *pb.CreateClaimValueRequest) (*pb.CreateClaimValueResponse, error) {
	resp := &pb.CreateClaimValueResponse{}
	var err error

	sqlstring1 := `SELECT claim_name_id FROM tb_claim WHERE claim_name_id = $1 AND is_deleted = false`
	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	var testClaimId int64

	err = stmt1.QueryRow(req.GetClaimNameId()).Scan(&testClaimId)

	if err != nil {
		resp.ErrorCode = 502
		resp.ErrorMessage = "unable to match existing claim name"
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		return resp, nil
	}

	sqlstring := `INSERT INTO tb_claimvalue (created, modified, deleted, is_deleted, version,
	claim_name_id, claim_val, claim_value_description) VALUES (now(), now(), now(), false, 1, $1, $2, $3) RETURNING claim_value_id`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var claimValueId int64

	err = stmt.QueryRow(req.GetClaimNameId(), req.GetClaimVal(), req.GetClaimValueDescription()).Scan(&claimValueId)

	if err == nil {
		resp.ClaimValueId = claimValueId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		level.Error(s.logger).Log("what", "QueryRow", "error", err)
		err = nil
	}

	return resp, err
}

// update existing claim value
func (s *accountService) UpdateClaimValue(ctx context.Context, req *pb.UpdateClaimValueRequest) (*pb.UpdateClaimValueResponse, error) {
	resp := &pb.UpdateClaimValueResponse{}
	var err error

	sqlstring := `UPDATE tb_claimvalue SET modified = now(), version = $1, claim_val = $2, claim_value_description = $3
	WHERE claim_value_id = $4 AND version = $5 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetClaimVal(), req.GetClaimValueDescription(), req.GetClaimValueId(), req.GetVersion())

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

// delete existing claim value
func (s *accountService) DeleteClaimValue(ctx context.Context, req *pb.DeleteClaimValueRequest) (*pb.DeleteClaimValueResponse, error) {
	resp := &pb.DeleteClaimValueResponse{}
	var err error

	sqlstring := `UPDATE tb_claimvalue SET deleted = now(), is_deleted = true, version = $1
	WHERE  claim_value_id = $2 AND version = $3 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetClaimValueId(), req.GetVersion())
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

// get claim value by id
func (s *accountService) GetClaimValueById(ctx context.Context, req *pb.GetClaimValueByIdRequest) (*pb.GetClaimValueByIdResponse, error) {
	resp := &pb.GetClaimValueByIdResponse{}
	var err error

	sqlstring := `SELECT claim_value_id, created, modified, version, claim_name_id, claim_val, claim_value_description
	FROM  tb_claimvalue WHERE claim_value_id = $1 AND is_deleted = false`

	// sqlstring := `SELECT cv.claim_value_id, cv.created, cn.modified, cv.version, cv.claim_name_id, cv.claim_val, cv.claim_value_description
	// FROM  tb_claimvalue AS cv
	// JOIN tb_claim AS cn
	// ON cv.claim_name_id = cn.claim_name_id
	// WHERE cv.claim_value_id = ? AND cv.is_deleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var claimVal pb.ClaimValue
	var created string
	var modified string

	err = stmt.QueryRow(req.GetClaimValueId()).Scan(&claimVal.ClaimValueId, &created, &modified, &claimVal.Version, &claimVal.ClaimNameId,
		&claimVal.ClaimVal, &claimVal.ClaimValueDescription)

	if err != nil {
		if err == sql.ErrNoRows {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		} else {
			level.Error(s.logger).Log("what", "QueryRow", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
		}
		return resp, nil
	}

	claimVal.Created = dml.DateTimeFromString(created)
	claimVal.Modified = dml.DateTimeFromString(modified)

	// now get the associated claim
	sqlstring1 := `SELECT claim_name_id, created, modified, version, claim_name, claim_description
	FROM tb_claim WHERE is_deleted = false AND claim_name_id = $1`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	var claim pb.Claim

	err = stmt1.QueryRow(claimVal.GetClaimNameId()).Scan(&claim.ClaimNameId, &created, &modified, &claim.Version, &claim.ClaimName, &claim.ClaimDescription)
	if err != nil {
		if err == sql.ErrNoRows {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		} else {
			level.Error(s.logger).Log("what", "QueryRow", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
		}
		return resp, nil
	}

	claim.Created = dml.DateTimeFromString(created)
	claim.Modified = dml.DateTimeFromString(modified)

	claimVal.Claim = &claim
	resp.ClaimValue = &claimVal

	return resp, err

}

// get all claim values for name id
func (s *accountService) GetClaimValuesByNameId(ctx context.Context, req *pb.GetClaimValuesByNameIdRequest) (*pb.GetClaimValuesByNameIdResponse, error) {
	resp := &pb.GetClaimValuesByNameIdResponse{}
	var err error

	sqlstring1 := `SELECT claim_name_id, created, modified, version, claim_name, claim_description
	FROM tb_claim WHERE is_deleted = false AND claim_name_id = $1`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()

	var claim pb.Claim

	var created string
	var modified string

	err = stmt1.QueryRow(req.GetClaimNameId()).Scan(&claim.ClaimNameId, &created, &modified, &claim.Version, &claim.ClaimName, &claim.ClaimDescription)
	if err != nil {
		if err == sql.ErrNoRows {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		} else {
			level.Error(s.logger).Log("what", "QueryRow", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
		}
		return resp, nil
	}

	claim.Created = dml.DateTimeFromString(created)
	claim.Modified = dml.DateTimeFromString(modified)

	sqlstring := `SELECT claim_value_id, created, modified, version, claim_name_id, claim_val, claim_value_description
	FROM  tb_claimvalue WHERE claim_name_id = $1 AND is_deleted = false`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		level.Error(s.logger).Log("what", "Prepare", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()
	rows, err := stmt.Query(req.GetClaimNameId())

	if err != nil {
		level.Error(s.logger).Log("what", "Query", "error", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	defer rows.Close()
	for rows.Next() {
		var claimVal pb.ClaimValue

		err = rows.Scan(&claimVal.ClaimValueId, &created, &modified, &claimVal.Version, &claimVal.ClaimNameId,
			&claimVal.ClaimVal, &claimVal.ClaimValueDescription)

		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}

		claimVal.Created = dml.DateTimeFromString(created)
		claimVal.Modified = dml.DateTimeFromString(modified)
		claimVal.Claim = &claim

		resp.ClaimValue = append(resp.ClaimValue, &claimVal)

	}

	return resp, err
}

// get all claim values for all claim names
func (s *accountService) GetClaimValues(ctx context.Context, req *pb.GetClaimValuesRequest) (*pb.GetClaimValuesResponse, error) {
	resp := &pb.GetClaimValuesResponse{}
	var err error

	sqlstring := `SELECT claim_value_id, created, modified, version, claim_name_id, claim_val, claim_value_description
	FROM  tb_claimvalue WHERE is_deleted = false`

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
		var claimVal pb.ClaimValue
		var created string
		var modified string

		err = rows.Scan(&claimVal.ClaimValueId, &created, &modified, &claimVal.Version, &claimVal.ClaimNameId,
			&claimVal.ClaimVal, &claimVal.ClaimValueDescription)

		if err != nil {
			level.Error(s.logger).Log("what", "Scan", "error", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}

		claimVal.Created = dml.DateTimeFromString(created)
		claimVal.Modified = dml.DateTimeFromString(modified)
		resp.ClaimValue = append(resp.ClaimValue, &claimVal)
	}

	return resp, err
}

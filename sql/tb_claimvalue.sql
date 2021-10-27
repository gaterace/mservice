
-- MService claim value entity
CREATE TABLE tb_claimvalue
(

    -- unique identifier for an MService claim value
    claim_value_id BIGSERIAL NOT NULL,
    -- creation date
    created TIMESTAMP NOT NULL,
    -- modification date
    modified TIMESTAMP NOT NULL,
    -- deletion date
    deleted TIMESTAMP NOT NULL,
    -- has record been deleted?
    is_deleted BOOL NOT NULL,
    -- version of this record
    version INT NOT NULL,
    -- unique identifier for an MService claim name
    claim_name_id BIGINT NOT NULL,
    -- claim value
    claim_val VARCHAR(20) NOT NULL,
    -- claim value description
    claim_value_description VARCHAR(100) NOT NULL
);

    
CREATE UNIQUE  INDEX pk_tb_claimvalue ON tb_claimvalue
(
	claim_value_id
); 


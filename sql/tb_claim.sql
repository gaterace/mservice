
-- MService claim name entity
CREATE TABLE tb_claim
(

    -- unique identifier for an MService claim name
    claim_name_id BIGSERIAL NOT NULL,
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
    -- claim name
    claim_name VARCHAR(10) NOT NULL,
    -- claim description
    claim_description VARCHAR(100) NOT NULL
);

    
CREATE UNIQUE  INDEX pk_tb_claim ON tb_claim
(
	claim_name_id
); 


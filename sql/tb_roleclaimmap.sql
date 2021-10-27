
CREATE TABLE tb_roleclaimmap
(

    -- unique identifier for an MService account role
    role_id BIGINT NOT NULL,
    -- unique identifier for an MService claim value
    claim_value_id BIGINT NOT NULL,
    -- creation date
    created TIMESTAMP NOT NULL,
    -- deletion date
    deleted TIMESTAMP NOT NULL,
    -- has record been deleted?
    is_deleted BOOL NOT NULL
);

    
CREATE UNIQUE  INDEX pk_tb_roleclaimmap ON tb_roleclaimmap
(
	role_id,claim_value_id
); 


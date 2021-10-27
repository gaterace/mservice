
-- MService account role entity
CREATE TABLE tb_accountrole
(

    -- unique identifier for an MService account role
    role_id BIGSERIAL NOT NULL,
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
    -- unique identifier for an MService account
    account_id BIGINT NOT NULL,
    -- descriptive name for role
    role_name VARCHAR(20) NOT NULL
);

    
CREATE UNIQUE  INDEX pk_tb_accountrole ON tb_accountrole
(
	role_id
); 
    
CREATE  UNIQUE INDEX ix_tb_accountrole_account_id_role_name ON tb_accountrole
(
	account_id,role_name
); 


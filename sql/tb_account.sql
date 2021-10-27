
-- MService account entity
CREATE TABLE tb_account
(

    -- unique identifier for an MService account
    account_id BIGSERIAL NOT NULL,
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
    -- name for account
    account_name VARCHAR(20) NOT NULL,
    -- long name for account
    account_long_name VARCHAR(100) NOT NULL,
    -- account_type
    account_type INT NOT NULL,
    -- account address line 1
    address1 VARCHAR(100) NOT NULL,
    -- account address line 2
    address2 VARCHAR(100) NOT NULL,
    -- account address city
    city VARCHAR(50) NOT NULL,
    -- account address state
    state VARCHAR(50) NOT NULL,
    -- account address postal or zip code
    postal_code VARCHAR(20) NOT NULL,
    -- account address country code
    country_code CHAR(2) NOT NULL,
    -- account phone number
    phone VARCHAR(20) NOT NULL,
    -- email address
    email VARCHAR(50) NOT NULL
);

    
CREATE UNIQUE  INDEX pk_tb_account ON tb_account
(
	account_id
); 
    
CREATE  UNIQUE INDEX ix_tb_account_account_name ON tb_account
(
	account_name
); 


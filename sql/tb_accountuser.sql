
-- MService account user entity
CREATE TABLE tb_accountuser
(

    -- unique identifier for an MService account user
    user_id BIGSERIAL NOT NULL,
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
    -- email address
    email VARCHAR(50) NOT NULL,
    -- account user full name
    user_full_name VARCHAR(100) NOT NULL,
    -- type of account user
    user_type INT NOT NULL,
    -- account user encrypted password hash
    password_enc VARCHAR(255) NOT NULL
);

    
CREATE UNIQUE  INDEX pk_tb_accountuser ON tb_accountuser
(
	user_id
); 
    
CREATE  UNIQUE INDEX ix_tb_accountuser_account_id_email ON tb_accountuser
(
	account_id,email
); 


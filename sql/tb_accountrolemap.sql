
-- MService account user to role map
CREATE TABLE tb_accountrolemap
(

    -- unique identifier for an MService account user
    user_id BIGINT NOT NULL,
    -- unique identifier for an MService account role
    role_id BIGINT NOT NULL,
    -- creation date
    created TIMESTAMP NOT NULL,
    -- deletion date
    deleted TIMESTAMP NOT NULL,
    -- has record been deleted?
    is_deleted BOOL NOT NULL
);

    
CREATE UNIQUE  INDEX pk_tb_accountrolemap ON tb_accountrolemap
(
	user_id,role_id
); 


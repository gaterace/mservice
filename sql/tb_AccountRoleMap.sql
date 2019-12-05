use mservice;

DROP TABLE IF EXISTS tb_AccountRoleMap;

-- MService account user to role map
CREATE TABLE tb_AccountRoleMap
(

    -- unique identifier for an MService account user
    inbUserId BIGINT NOT NULL,
    -- unique identifier for an MService account role
    inbRoleId BIGINT NOT NULL,
    -- creation date
    dtmCreated DATETIME NOT NULL,
    -- deletion date
    dtmDeleted DATETIME NOT NULL,
    -- has record been deleted?
    bitIsDeleted BOOL NOT NULL,


    PRIMARY KEY (inbUserId,inbRoleId)
) ENGINE=InnoDB;


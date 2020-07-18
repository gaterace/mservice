use mservice;

DROP TABLE IF EXISTS tb_AccountRole;

-- MService account role entity
CREATE TABLE tb_AccountRole
(

    -- unique identifier for an MService account role
    inbRoleId BIGINT AUTO_INCREMENT NOT NULL,
    -- creation date
    dtmCreated DATETIME NOT NULL,
    -- modification date
    dtmModified DATETIME NOT NULL,
    -- deletion date
    dtmDeleted DATETIME NOT NULL,
    -- has record been deleted?
    bitIsDeleted BOOL NOT NULL,
    -- version of this record
    intVersion INT NOT NULL,
    -- unique identifier for an MService account
    inbAccountId BIGINT NOT NULL,
    -- descriptive name for role
    chvRoleName VARCHAR(20) NOT NULL,
    -- data for entity ui extensions
    chvJsonData VARCHAR(8000) NOT NULL


    PRIMARY KEY (inbRoleId),
    UNIQUE (inbAccountId,chvRoleName)
) ENGINE=InnoDB;


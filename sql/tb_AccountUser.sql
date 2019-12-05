use mservice;

DROP TABLE IF EXISTS tb_AccountUser;

-- MService account user entity
CREATE TABLE tb_AccountUser
(

    -- unique identifier for an MService account user
    inbUserId BIGINT AUTO_INCREMENT NOT NULL,
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
    -- email address
    chvEmail VARCHAR(50) NOT NULL,
    -- account user full name
    chvUserFullName VARCHAR(100) NOT NULL,
    -- type of account user
    intUserType INT NOT NULL,
    -- account user encrypted password hash
    chvPasswordEnc VARCHAR(255) NOT NULL,


    PRIMARY KEY (inbUserId),
    UNIQUE (inbAccountId,chvEmail)
) ENGINE=InnoDB;


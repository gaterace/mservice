use mservice;

DROP TABLE IF EXISTS tb_Claim;

-- MService claim name entity
CREATE TABLE tb_Claim
(

    -- unique identifier for an MService claim name
    inbClaimNameId BIGINT AUTO_INCREMENT NOT NULL,
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
    -- claim name
    chvClaimName VARCHAR(10) NOT NULL,
    -- claim description
    chvClaimDescription VARCHAR(100) NOT NULL,


    PRIMARY KEY (inbClaimNameId)
) ENGINE=InnoDB;


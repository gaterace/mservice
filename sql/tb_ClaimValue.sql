use mservice;

DROP TABLE IF EXISTS tb_ClaimValue;

-- MService claim value entity
CREATE TABLE tb_ClaimValue
(

    -- unique identifier for an MService claim value
    inbClaimValueId BIGINT AUTO_INCREMENT NOT NULL,
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
    -- unique identifier for an MService claim name
    inbClaimNameId BIGINT NOT NULL,
    -- claim value
    chvClaimVal VARCHAR(20) NOT NULL,
    -- claim value description
    chvClaimValueDescription VARCHAR(100) NOT NULL,


    PRIMARY KEY (inbClaimValueId)
) ENGINE=InnoDB;


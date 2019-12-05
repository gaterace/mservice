use mservice;

DROP TABLE IF EXISTS tb_RoleClaimMap;

CREATE TABLE tb_RoleClaimMap
(

    -- unique identifier for an MService account role
    inbRoleId BIGINT NOT NULL,
    -- unique identifier for an MService claim value
    inbClaimValueId BIGINT NOT NULL,
    -- creation date
    dtmCreated DATETIME NOT NULL,
    -- deletion date
    dtmDeleted DATETIME NOT NULL,
    -- has record been deleted?
    bitIsDeleted BOOL NOT NULL,


    PRIMARY KEY (inbRoleId,inbClaimValueId)
) ENGINE=InnoDB;


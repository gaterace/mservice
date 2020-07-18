use mservice;

DROP TABLE IF EXISTS tb_EntitySchema;

-- MService account extension schema
CREATE TABLE tb_EntitySchema
(

    -- unique identifier for an MService account
    inbAccountId BIGINT NOT NULL,
    -- name of entity to be extended
    chvEntityName VARCHAR(32) NOT NULL,
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
    -- schema for json_data extensions
    chvJsonSchema VARCHAR(8000) NOT NULL,


    PRIMARY KEY (inbAccountId,chvEntityName)
) ENGINE=InnoDB;


use mservice;

DROP TABLE IF EXISTS tb_Account;

-- MService account entity
CREATE TABLE tb_Account
(

    -- unique identifier for an MService account
    inbAccountId BIGINT AUTO_INCREMENT NOT NULL,
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
    -- name for account
    chvAccountName VARCHAR(20) NOT NULL,
    -- long name for account
    chvAccountLongName VARCHAR(100) NOT NULL,
    -- account_type
    intAccountType INT NOT NULL,
    -- account address line 1
    chvAddress1 VARCHAR(100) NOT NULL,
    -- account address line 2
    chvAddress2 VARCHAR(100) NOT NULL,
    -- account address city
    chvCity VARCHAR(50) NOT NULL,
    -- account address state
    chvState VARCHAR(50) NOT NULL,
    -- account address postal or zip code
    chvPostalCode VARCHAR(20) NOT NULL,
    -- account address country code
    chvCountryCode CHAR(2) NOT NULL,
    -- account phone number
    chvPhone VARCHAR(20) NOT NULL,
    -- email address
    chvEmail VARCHAR(50) NOT NULL,


    PRIMARY KEY (inbAccountId),
    UNIQUE (chvAccountName)
) ENGINE=InnoDB;


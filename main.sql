CREATE DATABASE ping;

USE ping;

CREATE TABLE
    login (
        id int NOT NULL AUTO_INCREMENT,
        username VARCHAR(256) NOT NULL,
        passwordHash VARCHAR(512) NOT NULL,
        PRIMARY KEY (id)
    );

CREATE TABLE
    publicKeys (
        `from` VARCHAR(256) NOT NULL,
        `to` VARCHAR(256) NOT NULL,
        `pubKey` VARCHAR(4096) NOT NULL,
        PRIMARY KEY (`from`, `to`)
    );

CREATE TABLE
    IF NOT EXISTS `%s` (
        `from` VARCHAR(256) NOT NULL,
        `to` VARCHAR(256) NOT NULL,
        `time` VARCHAR(30) NOT NULL,
        `version` VARCHAR(5) NOT NULL,
        `system` int NOT NULL,
        `value` TEXT NOT NULL,
        `hash` VARCHAR(512) NOT NULL,
        `signature` BLOB NOT NULL
    );

-- CREATE TABLE ips(
--     userId INT NOT NULL,
--     ip VARCHAR(22) NOT NULL,
--     PRIMARY KEY(userId)
-- );
CREATE DATABASE ping;

USE ping;

CREATE TABLE login(
    id int NOT NULL AUTO_INCREMENT,
    username VARCHAR(256) NOT NULL,
    passwordHash VARCHAR(512) NOT NULL,
    PRIMARY KEY(id)
);

CREATE TABLE publicKeys(
	`from` VARCHAR(256) NOT NULL,
    `to` VARCHAR(256) NOT NULL,
    `pubKey` VARCHAR(4096) NOT NULL,
    PRIMARY KEY (`from`, `to`)
);

-- CREATE TABLE ips(
--     userId INT NOT NULL,
--     ip VARCHAR(22) NOT NULL,
--     PRIMARY KEY(userId)
-- );
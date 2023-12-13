CREATE DATABASE ping;

USE ping;

CREATE TABLE login(
    id int NOT NULL AUTO_INCREMENT,
    username VARCHAR(256) NOT NULL,
    passwordHash VARCHAR(512) NOT NULL,
    PRIMARY KEY(id)
);

-- CREATE TABLE ips(
--     userId INT NOT NULL,
--     ip VARCHAR(22) NOT NULL,
--     PRIMARY KEY(userId)
-- );
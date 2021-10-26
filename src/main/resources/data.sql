CREATE TABLE USERS (
    USERNAME VARCHAR2(50) PRIMARY KEY,
    PASSWORD_HASH VARCHAR2(4000) NOT NULL,
    SALT VARCHAR2(50),
    HASH_FUNCTION VARCHAR2(50) NOT NULL
);
CREATE TABLE WALLET_ITEMS (
    USERNAME VARCHAR2(50),
    WEB_ADDRESS VARCHAR2(50),
    WEB_ADDRESS_USERNAME VARCHAR2(50) NOT NULL,
    WEB_ADDRESS_PASSWORD VARCHAR2(4000) NOT NULL,
    PRIMARY KEY (USERNAME, WEB_ADDRESS)
);
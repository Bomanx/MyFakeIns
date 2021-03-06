
DROP DATABASE myfakeins;
CREATE DATABASE myfakeins;
USE myfakeins;



CREATE TABLE Users (
    uid int(4)  AUTO_INCREMENT,
    email varchar(255) UNIQUE,
    password varchar(255) NOT NULL,
    firstname VARCHAR(255),
    lastname VARCHAR(255),
    birthday DATE, 
    hometown VARCHAR(255), 
    gender CHAR,
  CONSTRAINT users_pk PRIMARY KEY (uid)
);


CREATE TABLE Albums(
    aid int(4) AUTO_INCREMENT,  
    Name VARCHAR(255) NOT NULL,
    
    Adate datetime DEFAULT NOW(), 
    uid INT(4) NOT NULL, 
    PRIMARY KEY(aid),
    FOREIGN KEY (uid) REFERENCES Users(uid) on delete CASCADE
    
    );

CREATE TABLE Photos
(
  pid int(4)  AUTO_INCREMENT,
  uid int(4) NOT NULL,
  imgdata longblob,
  caption VARCHAR(255),
  aid int(4),
  
  INDEX upid_idx (uid),
  
  CONSTRAINT photos_pk PRIMARY KEY (pid),
  FOREIGN KEY (uid) REFERENCES Users(uid) on delete cascade,
  FOREIGN KEY (aid) REFERENCES Albums(aid) on delete CASCADE
);




CREATE TABLE albumPhoto(     
    aid INT(4) NOT NULL,     
    pid INT(4),     
    PRIMARY KEY(aid, pid),     
    FOREIGN KEY(aid) REFERENCES Albums(aid) on delete cascade, 
    FOREIGN key (pid) REFERENCES photos(pid) on delete CASCADE
    );


CREATE TABLE userAlbum(
    uid INT(4) NOT NULL,      
    aid INT(4),      
    PRIMARY KEY(uid),     
    FOREIGN KEY(aid) REFERENCES Albums(aid),     
    FOREIGN KEY(uid) REFERENCES Users(uid) on delete cascade
    );


CREATE TABLE Comments(
    photouid INT(4) NOT NULL,
    uid INT(4),
    email VARCHAR(255),
    pid INT(4) NOT NULL,
    content VARCHAR(255),
    FOREIGN KEY (photouid) REFERENCES Users(uid),
    FOREIGN KEY (uid) REFERENCES Users(uid) on delete cascade,
    FOREIGN KEY (pid) REFERENCES photos(pid) on delete cascade
    );


CREATE TABLE photoTags(
    tid INT(4) AUTO_INCREMENT,
    uid INT(4),
    pid INT(4),
    word VARCHAR(255),
    PRIMARY KEY (tid, pid),
    FOREIGN KEY (uid) REFERENCES Users(uid) on delete CASCADE,
    FOREIGN KEY (pid) REFERENCES Photos(pid)  on delete cascade
    );



CREATE TABLE Friends(
    uid INT(4),
    fid INT(4),
    FOREIGN KEY (uid) REFERENCES Users(uid) on delete cascade,
    FOREIGN KEY (fid) REFERENCES Users(uid) on delete cascade,
    CONSTRAINT differentid CHECK (uid!=fid)
    );

CREATE TABLE Likes(
    uid INT(4),
    email VARCHAR(255),
    pid INT(4),
    PRIMARY KEY (pid,uid),
    FOREIGN KEY (uid) REFERENCES Users(uid),
    FOREIGN KEY (pid) REFERENCES Photos(pid) on delete CASCADE
    );

INSERT INTO Users (email, password) VALUES ('test@bu.edu', 'test');
INSERT INTO Users (email, password) VALUES ('test1@bu.edu', 'test');
INSERT INTO Users (email, password) VALUES ('test2@bu.edu', 'test');

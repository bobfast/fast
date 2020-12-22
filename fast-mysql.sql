create table attack_index (
no MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
pid int,
procname varchar(256),
hashcheck varchar(600),
time_stamp timestamp,
targetpath text,
bit varchar(10)
);

create table api_status (
no MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
idx int,
caller_pid varchar(10),
address varchar(32),
size int,
wapi varchar(256),
callstack text,
caller_path text
);

create table dump_path (
no MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
idx int,
dump text
);

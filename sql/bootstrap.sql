
INSERT INTO tb_account VALUES (1,now(),now(),now(),false,1,'master','example.com',1,'123 Main Street','','Anytown','CO','98765','US','800-123-4567','admin@example.com');

INSERT INTO tb_claim VALUES (1,now(),now(),now(),false,1,'acctmgt','account management');

INSERT INTO tb_claimvalue VALUES (1,now(),now(),now(),false,1,1,'admin','administrative access'),
(2,now(),now(),now(),false,1,1,'acctrw','read write account only'),
(3,now(),now(),now(),false,1,1,'acctro','read only account only'),
(4,now(),now(),now(),false,1,1,'userrw','read write user only'),
(5,now(),now(),now(),false,1,1,'userro','read only user only'),
(6,now(),now(),now(),false,1,1,'userpw','password change user only');

INSERT INTO tb_accountrole VALUES (1,now(),now(),now(),false,1,1,'admin_role');

INSERT INTO tb_roleclaimmap VALUES (1,1,now(),now(),false);

INSERT INTO tb_accountuser VALUES (1,now(),now(),now(),false,1,1,'admin@example.com','Adam Admin',2,'$2a$12$1YPMexBhQ33NxE3s9d7BQ.eK53OavAnI6zXczbd9eZ5Iu01b1f18a');

INSERT INTO tb_accountrolemap VALUES (1,1,now(),now(),false);



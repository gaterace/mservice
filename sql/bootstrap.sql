use mservice;

LOCK TABLES `tb_Account` WRITE;
INSERT INTO `tb_Account` VALUES (1,NOW(),NOW(),NOW(),0,1,'master','example.com',1,'123 Main Street','','Anytown','CO','98765','US','800-123-4567','admin@example.com');
UNLOCK TABLES;

LOCK TABLES `tb_Claim` WRITE;
INSERT INTO `tb_Claim` VALUES (1,NOW(),NOW(),NOW(),0,1,'acctmgt','account management');
UNLOCK TABLES;

LOCK TABLES `tb_ClaimValue` WRITE;
INSERT INTO `tb_ClaimValue` VALUES (1,NOW(),NOW(),NOW(),0,1,1,'admin','administrative access'),
(2,NOW(),NOW(),NOW(),0,1,1,'acctrw','read write account only'),
(3,NOW(),NOW(),NOW(),0,1,1,'acctro','read only account only'),
(4,NOW(),NOW(),NOW(),0,1,1,'userrw','read write user only'),
(5,NOW(),NOW(),NOW(),0,1,1,'userro','read only user only'),
(6,NOW(),NOW(),NOW(),0,1,1,'userpw','password change user only');
UNLOCK TABLES;

LOCK TABLES `tb_AccountRole` WRITE;
INSERT INTO `tb_AccountRole` VALUES (1,NOW(),NOW(),NOW(),0,1,1,'admin_role');
UNLOCK TABLES;

LOCK TABLES `tb_RoleClaimMap` WRITE;
INSERT INTO `tb_RoleClaimMap` VALUES (1,1,NOW(),NOW(),0);
UNLOCK TABLES;

LOCK TABLES `tb_AccountUser` WRITE;
INSERT INTO `tb_AccountUser` VALUES (1,NOW(),NOW(),NOW(),0,1,1,'admin@example.com','Adam Admin',2,'$2a$12$1YPMexBhQ33NxE3s9d7BQ.eK53OavAnI6zXczbd9eZ5Iu01b1f18a');
UNLOCK TABLES;

LOCK TABLES `tb_AccountRoleMap` WRITE;
INSERT INTO `tb_AccountRoleMap` VALUES (1,1,NOW(),NOW(),0);
UNLOCK TABLES;


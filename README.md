# MService

Copyright 2019 Demian Harvill

## Overview

MService is a microservice for authentication and authorization in support of this and other microservices.
It is written the Go, and uses [gRPC](https://grpc.io) to define and implement it's application programming interface (API).
A successful invocation of the **login** api returns a JSON Web Token (JWT) that can be used with this and other
microservices to gain access to methods in those microservices.

The JWT encodes the login user and account, as well as the claims associated with that login. The JWT is signed with with an
RSA private key (known only to the MService, but can be verified by the RSA public key (known to all clients). The JWT is passed
to microservices using the gRPC context. The lifetime of the JWT is configurable.

## Data Model

The persistent data is managed by a MySQL / MariaDB database associated with this microservice.

**Claims** and associated **Claim Values** are used to create key/value pairs in the JWT for authorization. For example, the
MService miscroservice uses the claim **acctmgt** for itself, an example claim value is **acctrw** for read/write access within 
an MService account.

An MService **Account** groups associated users and roles that are independent of other accounts.

An MService **User** represents a user or process that can login to the microservice and retrieve a JWT. It is identified by an 
email address and password (used for authentication).

An MService **Role** is defined within an account as a bundle of claims and associated claim values. Roles are then associated with 
an account user, and the claim bundles are encoded in the jWT returned from **login**.
 
## Certificates

### JWT Certificates
The generated JWT uses RSA asymetric encryption for the public and private keys. On Linux, use openssl to generate:

    /usr/bin/openssl genrsa -out jwt_private.pem 2048

    /usr/bin/openssl rsa -pubout -in jwt_private.pem -out jwt_public.pem


The jwt_private.pem should only be known to the MService server (acctserver), and the jwt_public.pem should be known
to both servers and clients. For the server and clients, this eses  locations are specified in
the configuration file **conf.yaml** .  

### SSL / TLS Certificates

In a production environment, the connection between the client and the MService server should be encrypted. This is
accomplished with the configuration setting:

    tls: true

If using either a public certificate for the server (ie, from LetsEncrypt) or a self-signed certificate,  the server need to know the public certificate as
well as the private key. 

The server configuration is:

    cert_file: <location of public or self-signed CA certificate

    key_file: <location of private key>

The client configuration needs to know the location of the CA cert_file if using self-signed certificates.

## Database

There are MySql scripts in the **sql/** directory that create the mservice database (mservice.sql) as well as all
the required tables (tb_*.sql).  These need to be run on the MySql server to create the database and associated tables.

The database also needs to be bootrapped with data to establish the initial account and claims, as well as the
initial admin user and roles.  This can be accomplished by running **bootstrap.sql**. This will create an initial account named 
**master** with a single administrative user, **admin@example.com**. The initial password is **changeme**. The account name
and administrative user can be changed using a text editor against bootstrap.sql.  Alternatively, the Go Client discussed later can be 
used to modify the initial settings. 

## Server

To build the server:

  cd cmd/acctserver
  
  go build

The acctserver executable can then be run.  It expects a YAML configuration file in the same directory named **conf.yaml** .  The location
of the configuration file can be changed with an environment variable,**ACCT_CONF** .

A commented sample configuration file is at **cmd/acctserver/conf.sample** . The locations of the various certificates and 
keys need to be provided, as well as the database user and password and the MySql connection string.

## Go Client

A command line client written in Go is available:

    cd cmd/acctclient

    go install 
    
It also expects a YAML configuration file in the user's home directory, **~/.mservice.config**. A commented sample for this
file is at **cmd/acctclient/conf.sample**

Running the excutable file with no parameters will write usage information to stdout.  In particular, most subcommands expect
the user to have logged in:

    acctclient -c login -email myname@example.com

which then prompts for a password. If the login is successful, the temporary JWT is written to
**~/.mservice.token**  The acctclient executable (and other clients in the suite) can then find the JWT to
authorize subsequent calls.

Note that the use of the Go acctclient is merely a convenience, and not a requirement. Since we are using gRPC, the thin client
can be written in any supported language.  It can be part of a web or mobile application for example.

## Claims and Roles ##

The MService microservice relies on the **acctmgt** claim, and the following claim values:

**admin**: administrative access, across all accounts

**acctrw**: read/write (administrative) access within a single account

**acctro**: read only access within a single account

**userrw**: user read-write access, can modify own user information

**userro**: user read-only access for own user information

**userpw**: user can modify own password

Note that within an account, a role must be created to map these claims to a logged-in user.


















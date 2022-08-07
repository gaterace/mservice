# MService

Copyright 2019-2022 Demian Harvill

## Overview

MService is a microservice for authentication and authorization in support of this and other microservices.
It is written the language Go, and uses [gRPC](https://grpc.io) to define and implement it's application programming interface (API).
A successful invocation of the **login** api returns a JSON Web Token (JWT) that can be used with this and other
microservices to gain access to methods in those microservices.

The JWT encodes the login user and account, as well as the claims associated with that login. The JWT is signed with with an
RSA private key (known only to the MService microservice), but can be verified by the RSA public key (known to all associated microservices). 
The JWT is passed to microservices using the gRPC context. The lifetime of the JWT is configurable.

As of version v0.9.2, the acctserver can optionally support HTTP Rest requests on a separate port. 

## Usage 

Example client usage using the Go command line client (note that any thin client in any language supported by gRPC
can be used instead):

**acctclient login -a master -e user@example.com**

Login for the user, creating a JWT if successful. The account (-a master ) can be omitted if it is specified 
in the client configuration file. The user is prompted for the password in this case.

**acctclient create_account -a master --account_long_name 'example.com'  --account_type 1  
          --address1 '123 Main Street' --city Anytown --state CO
          --postal_code 98765 --phone 800-123-4567 -e admin@example.com**

Creates an account to hold users and roles. Each account is independent of other accounts, so is likely 
to be associated with a company or division. Requires admin privileges to create an account.

**acctclient create_claim_name --claim_name acctmgt --claim_description 'account management'**

Creates a claim name (independent of account). Requires admin privileges to create a claim name.

**acctclient create_claim_value --claim_name_id 1 --claim_val acctro --claim_value_description 'read only account only'**

Creates a claim value associated with a claim name.  The claim name id was returned by the create_claim_name command.
Requires admin privileges to create a claim value.

**acctclient create_account_role --account_id 1 --role_name acct_ro**

Creates an account role to associate claims with an account. Requires the account_id which was returned by create_account,
and can be discovered with get_account_by_name. Requires admin or acctrw privileges to create an account role.

**acctclient add_claim_to_role --claim_value_id 3 --role_id 3**

Binds a claim value (and associated claim name) to a role.  The claim_value_id was returned by create_claim_value (and can be 
discovered with get_claim_values), and the role_id was returned by create_account_role (and can be discovered with 
get_account_roles). Requires admin or acctrw privileges to add a claim to an account role.

**acctclient create_account_user --account_id 1 -e joe@example.com --user_full_name 'Joe Jones' --user_type 2 --password changeme**

Creates a user within an account. Requires the account_id which was returned by create_account,
and can be discovered with get_account_by_name.

**acctclient add_user_to_role --user_id 7 --role_id 3**

Associates a role with a user. Requires the user_id returned by create_account_user (or can be discovered with get_account_users).
Also required is the role_id,  returned by create_account_role (and can be discovered with 
get_account_roles). Requires admin or acctrw privileges to add an account role to a user.

Other commands for update, delete and get operations can be discovered with 

**acctclient**

with no parameters. 

## Certificates

### JWT Certificates
The generated JWT uses RSA asymmetric encryption for the public and private keys. On Linux, use openssl to generate:

    /usr/bin/openssl genrsa -out jwt_private.pem 2048

    /usr/bin/openssl rsa -pubout -in jwt_private.pem -out jwt_public.pem


The jwt_private.pem should only be known to the MService server (acctserver), and the jwt_public.pem should be known
to both servers and clients. For the server and clients, these  locations are specified in
the configuration file conf.yaml.  

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
A MySql user with appropriate permissions needs to be created for the acctserver to use the mservice database.

The database also needs to be bootrapped with data to establish the initial account and claims, as well as the
initial admin user and roles.  This can be accomplished by running **bootstrap.sql**. This will create an initial account named 
**master** with a single administrative user, **admin@example.com**. The initial password is **changeme**. The account name
and administrative user can be changed using a text editor against bootstrap.sql.  Alternatively, the Go Client discussed later can be 
used to modify the initial settings. 

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


## Server

To build the server:

**cd cmd/acctserver**
  
**go build**

The acctserver executable can then be run.  It expects a YAML configuration file in the same directory named **conf.yaml** .  The location
of the configuration file can be changed with an environment variable,**ACCT_CONF** . All configuration can optionally be set
using command line flags or through environment variables (with ACCT_ prefix).

```
acctserver -h

Usage:
  acctserver [flags]

Flags:
      --cert_file string          Path to certificate file.
      --conf string               Path to inventory config file. (default "conf.yaml")
      --cors_origin string        Cross origin sites for REST.
      --db_pwd string             Database user password.
      --db_transport string       Database transport string.
      --db_user string            Database user name.
  -h, --help                      help for acctserver
      --jwt_private_file string   Path to JWT private key.
      --jwt_pub_file string       Path to JWT public certificate.
      --key_file string           Path to certificate key file.
      --lease_minutes int         JWT lease time. (default 30)
      --log_file string           Path to log file.
      --port int                  Port for RPC connections (default 50051)
      --rest_port int             Port for REST connections
      --tls                       Use tls for connection.
```

A commented sample configuration file is at **cmd/acctserver/conf.sample** . The locations of the various certificates and 
keys need to be provided, as well as the database user and password and the MySql connection string.

## Go Client

A command line client written in Go is available:

**cd cmd/acctclient**

**go install** 
    
It also expects a YAML configuration file in the user's home directory, **~/.mservice.config**. A commented sample for this
file is at **cmd/acctclient/conf.sample**

Running the excutable file with no parameters will write usage information to stdout.  In particular, most subcommands expect
the user to have logged in:

    acctclient login -e myname@example.com

which then prompts for a password. If the login is successful, the temporary JWT is written to
**~/.mservice.token**  The acctclient executable (and other clients in the suite) can then find the JWT to
authorize subsequent calls.

Note that the use of the Go acctclient is merely a convenience, and not a requirement. Since we are using gRPC, the thin client
can be written in any supported language.  It can be part of a web or mobile application for example.

A second command line client written in Go is available to demonstrate HTTP Rest calls: **acctclientrest**. The usage is the same
as acctclient, except the HTTP Rest transport is used instead of gRPC.


## Claims and Roles ##

The MService microservice relies on the **acctmgt** claim, and the following claim values:

**admin**: administrative access, across all accounts

**acctrw**: read/write (administrative) access within a single account

**acctro**: read only access within a single account

**userrw**: user read-write access, can modify own user information

**userro**: user read-only access for own user information

**userpw**: user can modify own password

Note that within an account, a role must be created to map these claims to a logged-in user.


















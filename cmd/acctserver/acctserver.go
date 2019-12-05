// Copyright 2019 Demian Harvill
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// GRPC server for acctservice.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/gaterace/mservice/pkg/acctauth"
	"github.com/gaterace/mservice/pkg/acctservice"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/kylelemons/go-gypsy/yaml"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	configPath := os.Getenv("ACCT_CONF")
	if configPath == "" {
		configPath = "conf.yaml"
	}

	config, err := yaml.ReadFile(configPath)
	if err != nil {
		log.Fatalf("configuration not found: " + configPath)
	}

	log_file, _ := config.Get("log_file")
	cert_file, _ := config.Get("cert_file")
	key_file, _ := config.Get("key_file")
	tls, _ := config.GetBool("tls")
	port, _ := config.GetInt("port")
	db_user, _ := config.Get("db_user")
	db_pwd, _ := config.Get("db_pwd")
	db_transport, _ := config.Get("db_transport")
	jwt_pub_file, _ := config.Get("jwt_pub_file")
	jwt_private_file, _ := config.Get("jwt_private_file")
	lease_minutes, _ := config.GetInt("lease_minutes")

	fmt.Printf("log_file: %s\n", log_file)
	fmt.Printf("cert_file: %s\n", cert_file)
	fmt.Printf("key_file: %s\n", key_file)
	fmt.Printf("tls: %t\n", tls)
	fmt.Printf("port: %d\n", port)
	fmt.Printf("db_user: %s\n", db_user)
	fmt.Printf("db_transport: %s\n", db_transport)
	fmt.Printf("jwt_pub_file: %s\n", jwt_pub_file)
	fmt.Printf("jwt_private_file: %s\n", jwt_private_file)
	fmt.Printf("lease_minutes: %d\n", lease_minutes)

	logfile, _ := os.Create(log_file)
	defer logfile.Close()

	logger := log.New(logfile, "api_account ", log.LstdFlags|log.Lshortfile)

	if port == 0 {
		port = 50051
	}

	listen_port := ":" + strconv.Itoa(int(port))
	// fmt.Println(listen_port)

	lis, err := net.Listen("tcp", listen_port)
	if err != nil {
		logger.Fatalf("failed to listen: %v", err)
	}

	var opts []grpc.ServerOption
	if tls {
		creds, err := credentials.NewServerTLSFromFile(cert_file, key_file)
		if err != nil {
			grpclog.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	s := grpc.NewServer(opts...)
	acctService := acctservice.NewAccountService()

	sqlDb, err := SetupDatabaseConnections(db_user, db_pwd, db_transport)
	if err != nil {
		logger.Fatalf("failed to get database connection: %v", err)
	}

	acctService.SetLogger(logger)
	acctService.SetDatabaseConnection(sqlDb)
	err = acctService.SetPrivateKey(jwt_private_file)
	if err != nil {
		logger.Printf("set private key error: %v\n", err)
	}

	if lease_minutes == 0 {
		lease_minutes = 30
	}

	acctService.SetLeaseMinutes(int(lease_minutes))

	// wire up the authorization middleware

	acctAuth := acctauth.NewAccountAuth(acctService)
	acctAuth.SetLogger(logger)

	acctAuth.SetPublicKey(jwt_pub_file)
	acctAuth.SetDatabaseConnection(sqlDb)
	err = acctAuth.NewApiServer(s)
	if err != nil {
		logger.Fatalf("failed to create api server: %v", err)
	}

	logger.Println("starting server ...")

	s.Serve(lis)

	logger.Println("shutting down server ...")

}

// helper to set up database connections for acctservice server.
func SetupDatabaseConnections(db_user string, db_pwd string, db_transport string) (*sql.DB, error) {
	var sqlDb *sql.DB
	endpoint := db_user + ":" + db_pwd + "@" + db_transport + "/mservice"
	fmt.Printf("mysql endpoint is %s\n", endpoint)
	var err error
	sqlDb, err = sql.Open("mysql", endpoint)
	if err == nil {
		err = sqlDb.Ping()
		if err != nil {
			sqlDb = nil
		}

	}

	if err == nil {
		fmt.Println("database connection established")
	} else {
		fmt.Printf("unable to establish database connection %v\n", err)
	}

	return sqlDb, err
}

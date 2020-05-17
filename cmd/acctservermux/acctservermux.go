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
	"context"
	"database/sql"
	"fmt"
	"github.com/gaterace/mservice/pkg/acctauth"
	"github.com/gaterace/mservice/pkg/acctservice"
	"github.com/gaterace/mservice/pkg/muxhandler"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/kylelemons/go-gypsy/yaml"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
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

	logFile, _ := config.Get("log_file")
	certFile, _ := config.Get("cert_file")
	keyFile, _ := config.Get("key_file")
	tls, _ := config.GetBool("tls")
	port, _ := config.GetInt("port")
	dbUser, _ := config.Get("db_user")
	dbPwd, _ := config.Get("db_pwd")
	dbTransport, _ := config.Get("db_transport")
	jwtPubFile, _ := config.Get("jwt_pub_file")
	jwtPrivateFile, _ := config.Get("jwt_private_file")
	leaseMinutes, _ := config.GetInt("lease_minutes")

	fmt.Printf("log_file: %s\n", logFile)
	fmt.Printf("cert_file: %s\n", certFile)
	fmt.Printf("key_file: %s\n", keyFile)
	fmt.Printf("tls: %t\n", tls)
	fmt.Printf("port: %d\n", port)
	fmt.Printf("db_user: %s\n", dbUser)
	fmt.Printf("db_transport: %s\n", dbTransport)
	fmt.Printf("jwt_pub_file: %s\n", jwtPubFile)
	fmt.Printf("jwt_private_file: %s\n", jwtPrivateFile)
	fmt.Printf("lease_minutes: %d\n", leaseMinutes)

	logfile, _ := os.Create(logFile)
	defer func() {
		_ = logfile.Close()
	}()

	logger := log.New(logfile, "api_account ", log.LstdFlags|log.Lshortfile)

	if port == 0 {
		port = 50051
	}

	acctService := acctservice.NewAccountService()

	sqlDb, err := SetupDatabaseConnections(dbUser, dbPwd, dbTransport)
	if err != nil {
		logger.Fatalf("failed to get database connection: %v", err)
	}

	acctService.SetLogger(logger)
	acctService.SetDatabaseConnection(sqlDb)

	err = acctService.SetPrivateKey(jwtPrivateFile)
	if err != nil {
			logger.Printf("set private key error: %v\n", err)
	}


	if leaseMinutes == 0 {
		leaseMinutes = 30
	}

	acctService.SetLeaseMinutes(int(leaseMinutes))

	// wire up the authorization middleware

	acctAuth := acctauth.NewAccountAuth(acctService)
	acctAuth.SetLogger(logger)

	err = acctAuth.SetPublicKey(jwtPubFile)
	if err != nil {
		logger.Fatalf("failed to set public key: %v", err)
	}
	acctAuth.SetDatabaseConnection(sqlDb)

	r := mux.NewRouter()
	mh := muxhandler.NewMuxHandler(acctAuth, r)
	mh.AddRoutes()

	addrString := fmt.Sprintf(":%d", port)

	srv := &http.Server{
		Addr:         addrString,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler: r, // Pass our instance of gorilla/mux in.
	}

	go func() {
		logger.Println("starting http server ...")
		if tls {
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil {
			logger.Printf("ListenAndServe err: %s", err.Error())
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	wait, _ :=  time.ParseDuration("15s")

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)

	logger.Println("shutting down http server ...")
	os.Exit(0)
}

// helper to set up database connections for acctservicemux server.
func SetupDatabaseConnections(dbUser string, dbPwd string, dbTransport string) (*sql.DB, error) {
	var sqlDb *sql.DB
	endpoint := dbUser + ":" + dbPwd + "@" + dbTransport + "/mservice"
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


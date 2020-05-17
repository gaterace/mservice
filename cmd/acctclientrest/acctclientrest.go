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

// Command line client for HTTP Rest acctservicemux.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"net/http"
	"bytes"
	"time"

	flag "github.com/juju/gnuflag"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
	"github.com/kylelemons/go-gypsy/yaml"
	"golang.org/x/crypto/ssh/terminal"
)

var cmd string
var account_name string
var email string
var password string
var account_long_name string
var account_type int
var address1 string
var address2 string
var city string
var state string
var postal_code string
var country_code string
var phone string
var version int
var account_id int64
var user_full_name string
var user_type int
var user_id int64
var password_old string
var claim_name string
var claim_description string
var claim_name_id int64
var claim_val string
var claim_value_description string
var claim_value_id int64
var role_name string
var role_id int64

func init() {
	// flag.StringVar(&cmd, "c", "", "acctclient command")
	flag.StringVar(&account_name, "a", "", "name for account")
	flag.StringVar(&account_name, "account_name", "", "name for account")
	flag.StringVar(&email, "e", "", "email address")
	flag.StringVar(&email, "email", "", "email address")
	flag.StringVar(&password, "password", "", "password for login")
	// flag.StringVar(p, "", "", "")
	flag.StringVar(&account_long_name, "account_long_name", "", "long name for account")
	flag.IntVar(&account_type, "account_type", 0, "account_type")
	flag.StringVar(&address1, "address1", "", "account address line 1")
	flag.StringVar(&address2, "address2", "", "account address line 2")
	flag.StringVar(&city, "city", "", "account address city")
	flag.StringVar(&state, "state", "", "account address state")
	flag.StringVar(&postal_code, "postal_code", "", "account address postal or zip code")
	flag.StringVar(&country_code, "country_code", "us", "account address country code")
	flag.StringVar(&phone, "phone", "", "account phone number")
	flag.Int64Var(&account_id, "account_id", 0, "unique identifier for an MService account")

	flag.IntVar(&version, "version", 0, "existing object version")

	flag.StringVar(&user_full_name, "user_full_name", "", "account user full name")
	flag.IntVar(&user_type, "user_type", 0, "type of account user")
	flag.Int64Var(&user_id, "user_id", 0, "unique identifier for an MService account user")
	flag.StringVar(&password_old, "password_old", "", "old password")

	flag.StringVar(&claim_name, "claim_name", "", "claim name")
	flag.StringVar(&claim_description, "claim_description", "", "claim description")
	flag.Int64Var(&claim_name_id, "claim_name_id", 0, "unique identifier for an MService claim names")
	flag.StringVar(&claim_val, "claim_val", "", "claim value")
	flag.StringVar(&claim_value_description, "claim_value_description", "", "claim value description")
	flag.Int64Var(&claim_value_id, "claim_value_id", 0, "unique identifier for an MService claim value")

	flag.StringVar(&role_name, "role_name", "", "descriptive name for role")
	flag.Int64Var(&role_id, "role_id", 0, "unique identifier for an MService account role")


}

func main() {
	flag.Parse(true)

	configFilename := "conf.yaml"
	usr, err := user.Current()
	if err == nil {
		homeDir := usr.HomeDir
		configFilename = homeDir + string(os.PathSeparator) + ".mservicemux.config"
	}

	config, err := yaml.ReadFile(configFilename)
	if err != nil {
		log.Fatalf("configuration not found: " + configFilename)
	}

	// log_file, _ := config.Get("log_file")
	ca_file, _ := config.Get("ca_file")
	useTls, _ := config.GetBool("tls")
	server_host_override, _ := config.Get("server_host_override")
	server, _ := config.Get("server")
	port, _ := config.GetInt("port")
	account, _ := config.Get("account")

	// fmt.Printf("log_file: %s\n", log_file)

	// fmt.Printf("ca_file: %s\n", ca_file)
	// fmt.Printf("useTls: %t\n", useTls)
	// fmt.Printf("server_host_override: %s\n", server_host_override)

	// fmt.Printf("server: %s\n", server)
	// fmt.Printf("port: %d\n", port)
	// fmt.Printf("account: %s\n", account)

	if port == 0 {
		port = 50051
	}

	if len(flag.Args()) > 0 {
		cmd = flag.Arg(0)
	}

	if cmd == "" {
		prog := os.Args[0]
		fmt.Printf("Command line client for mservice account grpc service\n")
		fmt.Printf("usage:\n")
		fmt.Printf("    %s login [-a <account>] -e <email> [--password <password>]\n", prog)
		fmt.Println(" ")
		fmt.Printf("    %s create_account [-a <account>] --account_long_name <name>  --account_type <type>  \n", prog)
		fmt.Println("          --address1 <address1> [--address2 <address2>] --city <city> --state <state>")
		fmt.Println("          --postal_code <postal_code> [--country_code <country_code>] --phone <phone> -e <email>")
		fmt.Printf("%s update_account --account_id <account_id> -- version <version> [-a <account>] --account_long_name <name>  --account_type <type> \n", prog)
		fmt.Println("          --address1 <address1> [--address2 <address2>] --city <city> --state <state>")
		fmt.Println("          --postal_code <postal_code> --country_code <country_code> --phone <phone> -e <email>")
		fmt.Printf("    %s delete_account --account_id <account_id> \n", prog)
		fmt.Printf("    %s get_account_by_id --account_id <account_id> \n", prog)
		fmt.Printf("    %s get_account_by_name -a <account_name> \n", prog)
		fmt.Printf("    %s get_account_names \n", prog)
		fmt.Println(" ")
		fmt.Printf("    %s create_account_user --account_id <account_id> -e <email> --user_full_name <user_full_name>\n", prog)
		fmt.Println("          --user_type <user_type> --password <password>")
		fmt.Printf("    %s update_account_user --user_id <user_id>  --version <version> -e <email> --user_full_name <user_full_name>\n", prog)
		fmt.Println("          --user_type <user_type>")
		fmt.Printf("    %s update_account_user_password --user_id <user_id> --version <version> --password_old <password_old> --password <password>\n", prog)
		fmt.Printf("    %s delete_account_user --user_id <user_id> --version <version>\n", prog)
		fmt.Printf("    %s get_account_user_by_id --user_id <user_id>\n", prog)
		fmt.Printf("    %s get_account_user_by_email [-a <account>] -e <email>\n", prog)
		fmt.Printf("    %s get_account_users [-a <account>]\n", prog)
		fmt.Println(" ")
		fmt.Printf("    %s create_claim_name --claim_name <claim_name> --claim_description <claim_description>\n", prog)
		fmt.Printf("    %s update_claim_name --claim_name_id <claim_name_id> [--claim_name <claim_name>] [--claim_description <claim_description>]\n", prog)
		fmt.Printf("    %s delete_claim_name --claim_name_id <claim_name_id>\n", prog)
		fmt.Printf("    %s get_claim_names \n", prog)
		fmt.Printf("    %s create_claim_value --claim_name_id <claim_name_id> --claim_val <claim_val> --claim_value_description <claim_value_description>\n", prog)
		fmt.Printf("    %s update_claim_value --claim_value_id <claim_value_id> --version <version> --claim_val <claim_val> --claim_value_description <claim_value_description>\n", prog)
		fmt.Printf("    %s delete_claim_value --claim_value_id <claim_value_id> --version <version>\n", prog)
		fmt.Printf("    %s get_claim_value_by_id --claim_value_id <claim_value_id> \n", prog)
		fmt.Printf("    %s get_claim_values_by_name_id --claim_name_id <claim_name_id> \n", prog)
		fmt.Printf("    %s get_claim_values \n", prog)
		fmt.Println(" ")
		fmt.Printf("    %s create_account_role --account_id <account_id> --role_name <role_name>\n", prog)
		fmt.Printf("    %s update_account_role --role_id <role_id> --version <version> --role_name <role_name>\n", prog)
		fmt.Printf("    %s delete_account_role --role_id <role_id> --version <version> \n", prog)
		fmt.Printf("    %s get_account_role_by_id --role_id <role_id>\n", prog)
		fmt.Printf("    %s get_account_roles --account_id <account_id>\n", prog)
		fmt.Printf("    %s add_user_to_role --user_id <user_id> --role_id <role_id>\n", prog)
		fmt.Printf("    %s remove_user_from_role --user_id <user_id> --role_id <role_id>\n", prog)
		fmt.Printf("    %s add_claim_to_role --claim_value_id <claim_value_id> --role_id <role_id>\n", prog)
		fmt.Printf("    %s remove_claim_from_role --claim_value_id <claim_value_id> --role_id <role_id>\n", prog)

		fmt.Printf("    %s get_server_version \n", prog)

		os.Exit(1)
	}

	if account_name != "" {
		account = account_name
	}

	validParams := true

	if account == "" {
		fmt.Println("account option missing or not in config")
		validParams = false
	}

	switch cmd {
	case "login":
		if email == "" {
			fmt.Println("email parameter missing")
			validParams = false
		}
		if password == "" {
			// prompt for password
			fmt.Print("Enter password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			if err == nil {
				// fmt.Println("\nPassword typed: " + string(bytePassword))
				password = string(bytePassword)
			}
			fmt.Println()
		}
		if password == "" {
			fmt.Println("password parameter missing")
			validParams = false
		}
	case "create_account":
		if account_long_name == "" {
			fmt.Println("account_long_name parameter missing")
			validParams = false
		}
		if account_type == 0 {
			fmt.Println("account_type parameter missing")
			validParams = false
		}
		if address1 == "" {
			fmt.Println("address1 parameter missing")
			validParams = false
		}
		if city == "" {
			fmt.Println("city parameter missing")
			validParams = false
		}
		if state == "" {
			fmt.Println("state parameter missing")
			validParams = false
		}
		if postal_code == "" {
			fmt.Println("postal_code parameter missing")
			validParams = false
		}
		if phone == "" {
			fmt.Println("phone parameter missing")
			validParams = false
		}
		if email == "" {
			fmt.Println("email parameter missing")
			validParams = false
		}
	case "update_account":
		if account_id == 0 {
			fmt.Println("account_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
		if account_long_name == "" {
			fmt.Println("account_long_name parameter missing")
			validParams = false
		}
		if account_type == 0 {
			fmt.Println("account_type parameter missing")
			validParams = false
		}
		if address1 == "" {
			fmt.Println("address1 parameter missing")
			validParams = false
		}
		if city == "" {
			fmt.Println("city parameter missing")
			validParams = false
		}
		if state == "" {
			fmt.Println("state parameter missing")
			validParams = false
		}
		if postal_code == "" {
			fmt.Println("postal_code parameter missing")
			validParams = false
		}
		if phone == "" {
			fmt.Println("phone parameter missing")
			validParams = false
		}
		if email == "" {
			fmt.Println("email parameter missing")
			validParams = false
		}
	case "delete_account":
		if account_id == 0 {
			fmt.Println("account_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
	case "get_account_by_id":
		if account_id == 0 {
			fmt.Println("account_id parameter missing")
			validParams = false
		}

	case "get_account_by_name":
		// just need account_name
	case "get_account_names":
		// no parameters
	case "create_account_user":
		if account_id == 0 {
			fmt.Println("account_id parameter missing")
			validParams = false
		}
		if email == "" {
			fmt.Println("email parameter missing")
			validParams = false
		}
		if user_full_name == "" {
			fmt.Println("user_full_name parameter missing")
			validParams = false
		}
		if user_type == 0 {
			fmt.Println("user_type parameter missing")
			validParams = false
		}
		if password == "" {
			fmt.Println("password parameter missing")
			validParams = false
		}

	case "update_account_user":
		if user_id == 0 {
			fmt.Println("user_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
		if email == "" {
			fmt.Println("email parameter missing")
			validParams = false
		}
		if user_full_name == "" {
			fmt.Println("user_full_name parameter missing")
			validParams = false
		}
		if user_type == 0 {
			fmt.Println("user_type parameter missing")
			validParams = false
		}
	case "update_account_user_password":
		if user_id == 0 {
			fmt.Println("user_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
		if password_old == "" {
			fmt.Println("password_old parameter missing")
			validParams = false
		}
		if password == "" {
			fmt.Println("password parameter missing")
			validParams = false
		}
	case "delete_account_user":
		if user_id == 0 {
			fmt.Println("user_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
	case "get_account_user_by_id":
		if user_id == 0 {
			fmt.Println("user_id parameter missing")
			validParams = false
		}
	case "get_account_user_by_email":
		if email == "" {
			fmt.Println("email parameter missing")
			validParams = false
		}
	case "get_account_users":
		// just need account name
	case "create_claim_name":
		if claim_name == "" {
			fmt.Println("claim_name parameter missing")
			validParams = false
		}
		if claim_description == "" {
			fmt.Println("claim_description parameter missing")
			validParams = false
		}
	case "update_claim_name":
		if claim_name_id == 0 {
			fmt.Println("claim_name_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
		if claim_description == "" {
			fmt.Println("claim_description parameter missing")
			validParams = false
		}
	case "delete_claim_name":
		if claim_name_id == 0 {
			fmt.Println("claim_name_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
	case "get_claim_names":
		// no parameters
	case "create_claim_value":
		if claim_name_id == 0 {
			fmt.Println("claim_name_id parameter missing")
			validParams = false
		}
		if claim_val == "" {
			fmt.Println("claim_val parameter missing")
			validParams = false
		}
		if claim_value_description == "" {
			fmt.Println("claim_value_description parameter missing")
			validParams = false
		}
	case "update_claim_value":
		if claim_value_id == 0 {
			fmt.Println("claim_value_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
		if claim_val == "" {
			fmt.Println("claim_val parameter missing")
			validParams = false
		}
		if claim_value_description == "" {
			fmt.Println("claim_value_description parameter missing")
			validParams = false
		}
	case "delete_claim_value":
		if claim_value_id == 0 {
			fmt.Println("claim_value_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
	case "get_claim_value_by_id":
		if claim_value_id == 0 {
			fmt.Println("claim_value_id parameter missing")
			validParams = false
		}
	case "get_claim_values_by_name_id":
		if claim_name_id == 0 {
			fmt.Println("claim_name_id parameter missing")
			validParams = false
		}
	case "get_claim_values":
		// no parameters
	case "create_account_role":
		if account_id == 0 {
			fmt.Println("account_id parameter missing")
			validParams = false
		}
		if role_name == "" {
			fmt.Println("role_name parameter missing")
			validParams = false
		}
	case "update_account_role":
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
		if role_name == "" {
			fmt.Println("role_name parameter missing")
			validParams = false
		}
	case "delete_account_role":
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
			validParams = false
		}
		if version <= 0 {
			fmt.Println("version parameter missing")
			validParams = false
		}
	case "get_account_role_by_id":
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
			validParams = false
		}
	case "get_account_roles":
		if account_id == 0 {
			fmt.Println("account_id parameter missing")
			validParams = false
		}
	case "add_user_to_role":
		if user_id == 0 {
			fmt.Println("user_id parameter missing")
			validParams = false
		}
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
			validParams = false
		}
	case "remove_user_from_role":
		if user_id == 0 {
			fmt.Println("user_id parameter missing")
			validParams = false
		}
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
			validParams = false
		}
	case "add_claim_to_role":
		if claim_value_id == 0 {
			fmt.Println("claim_value_id parameter missing")
			validParams = false
		}
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
			validParams = false
		}
	case "remove_claim_from_role":
		if claim_value_id == 0 {
			fmt.Println("claim_value_id parameter missing")
			validParams = false
		}
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
			validParams = false
		}
	case "get_server_version":
		validParams = true
	default:
		fmt.Printf("unknown command: %s\n", cmd)
		validParams = false
	}

	if !validParams {
		os.Exit(1)
	}

	tokenFilename := "token.txt"
	usr, err = user.Current()
	if err == nil {
		homeDir := usr.HomeDir
		tokenFilename = homeDir + string(os.PathSeparator) + ".mservice.token"
	}

	var serverAddr string

	if useTls {
		serverAddr = "https://" + server + ":" + strconv.Itoa(int(port))
	} else {
		serverAddr = "http://" + server + ":" + strconv.Itoa(int(port))
	}
	// fmt.Printf("address: %s\n", address)


	savedToken := ""

	data, err := ioutil.ReadFile(tokenFilename)

	if err == nil {
		savedToken = string(data)
	}



	bearer := "Bearer " + savedToken
	// fmt.Println(bearer)

	var client *http.Client

	if useTls {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		if ca_file != "" {
			// Read in the cert file
			certs, err := ioutil.ReadFile(ca_file)
			if err != nil {
				log.Fatalf("Failed to append %q to RootCAs: %v", ca_file, err)
			}

			// Append our cert to the system pool
			if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
				log.Println("No certs appended, using system certs only")
			}
		}

		config := &tls.Config{}
		config.RootCAs = rootCAs
		config.ServerName = server_host_override

		tr := &http.Transport{TLSClientConfig: config}
		client = &http.Client{
			Transport: tr,
			Timeout: time.Second * 10,
		}


	} else {
		client = &http.Client{
			Timeout: time.Second * 10,
		}
	}

	switch cmd {
	case "login":
		req := pb.LoginRequest{}
		req.AccountName = account
		req.Email = email
		req.Password = password
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := serverAddr + "/api/login"
		doMuxRequest(url, bearer, client, "POST", json)

	case "create_account":
		req := pb.CreateAccountRequest{}
		req.AccountName = account
		req.AccountLongName = account_long_name
		req.AccountType = int32(account_type)
		req.Address1 = address1
		req.Address2 = address2
		req.City = city
		req.State = state
		req.PostalCode = postal_code
		cc := country_code
		if cc == "" {
			cc = "us"
		}
		req.CountryCode = cc
		req.Phone = phone
		req.Email = email

		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}
		url := serverAddr + "/api/account"
		doMuxRequest(url, bearer, client, "POST", json)

	case "update_account":
		req := pb.UpdateAccountRequest{}
		req.AccountId = account_id
		req.Version = int32(version)
		req.AccountName = account
		req.AccountLongName = account_long_name
		req.AccountType = int32(account_type)
		req.Address1 = address1
		req.Address2 = address2
		req.City = city
		req.State = state
		req.PostalCode = postal_code
		cc := country_code
		if cc == "" {
			cc = "us"
		}
		req.CountryCode = cc
		req.Phone = phone
		req.Email = email

		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}
		url := serverAddr + "/api/account"
		doMuxRequest(url, bearer, client, "PUT", json)

	case "delete_account":
		url := fmt.Sprintf("%s/api/account/%d/%d", serverAddr, account_id, version)
		doMuxRequest(url, bearer, client, "DELETE", nil)

	case "get_account_by_id":
		url := fmt.Sprintf("%s/api/account/id/%d", serverAddr, account_id)
		doMuxRequest(url, bearer, client, "GET", nil)

	case "get_account_by_name":
		url := fmt.Sprintf("%s/api/account/name/%s", serverAddr, account)
		doMuxRequest(url, bearer, client, "GET", nil)

	case "get_account_names":
		url := fmt.Sprintf("%s/api/account/names", serverAddr)
		doMuxRequest(url, bearer, client, "GET", nil)

	case "create_account_user":
		req := pb.CreateAccountUserRequest{}
		req.AccountId = account_id
		req.Email = email
		req.UserFullName = user_full_name
		req.UserType = int32(user_type)
		req.PasswordEnc = password

		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}
		url := fmt.Sprintf("%s/api/user", serverAddr)
		doMuxRequest(url, bearer, client, "POST", json)
	case "update_account_user":
		req := pb.UpdateAccountUserRequest{}
		req.UserId = user_id
		req.Email = email
		req.UserFullName = user_full_name
		req.UserType = int32(user_type)
		req.Version = int32(version)

		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/user/%d", serverAddr, user_id)
		doMuxRequest(url, bearer, client, "PUT", json)

	case "update_account_user_password":
		req := pb.UpdateAccountUserPasswordRequest{}
		req.UserId = user_id
		req.Version = int32(version)
		req.PasswordOld = password_old
		req.PasswordEnc = password
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/user/pwd/%d", serverAddr, user_id)
		doMuxRequest(url, bearer, client, "PUT", json)

	case "delete_account_user":
		url := fmt.Sprintf("%s/api/user/%d/%d", serverAddr, user_id, version)
		doMuxRequest(url, bearer, client, "DELETE", nil)
	case "get_account_user_by_id":
		url := fmt.Sprintf("%s/api/user/id/%d", serverAddr, user_id)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "get_account_user_by_email":
		url := fmt.Sprintf("%s/api/user/email/%s/%s", serverAddr, account, email)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "get_account_users":
		url := fmt.Sprintf("%s/api/account/users/%s", serverAddr, account)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "create_claim_name":
		req := pb.CreateClaimNameRequest{}
		req.ClaimName = claim_name
		req.ClaimDescription = claim_description
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/claim", serverAddr)
		doMuxRequest(url, bearer, client, "POST", json)

	case "update_claim_name":
		req := pb.UpdateClaimNameRequest{}
		req.ClaimNameId = claim_name_id
		req.ClaimDescription = claim_description
		req.Version = int32(version)
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/claim/%d", serverAddr, claim_name_id)
		doMuxRequest(url, bearer, client, "PUT", json)

	case "delete_claim_name":
		url := fmt.Sprintf("%s/api/claim/%d/%d", serverAddr, claim_name_id, version)
		doMuxRequest(url, bearer, client, "DELETE", nil)

	case "get_claim_names":
		url := fmt.Sprintf("%s/api/claims", serverAddr)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "create_claim_value":
		req := pb.CreateClaimValueRequest{}
		req.ClaimNameId = claim_name_id
		req.ClaimVal = claim_val
		req.ClaimValueDescription = claim_value_description
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/claimvalue", serverAddr)
		doMuxRequest(url, bearer, client, "POST", json)
	case "update_claim_value":
		req := pb.UpdateClaimValueRequest{}
		req.ClaimValueId = claim_value_id
		req.ClaimVal = claim_val
		req.ClaimValueDescription = claim_value_description
		req.Version = int32(version)
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/claimvalue/%d", serverAddr, claim_value_id)
		doMuxRequest(url, bearer, client, "PUT", json)

	case "delete_claim_value":
		url := fmt.Sprintf("%s/api/claimvalue/%d/%d", serverAddr, claim_value_id, version)
		doMuxRequest(url, bearer, client, "DELETE", nil)

	case "get_claim_value_by_id":
		url := fmt.Sprintf("%s/api/claimvalue/id/%d", serverAddr, claim_value_id)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "get_claim_values_by_name_id":
		url := fmt.Sprintf("%s/api/claimvalue/claim/%d", serverAddr, claim_name_id)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "get_claim_values":
		url := fmt.Sprintf("%s/api/claimvalues", serverAddr)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "create_account_role":
		req := pb.CreateAccountRoleRequest{}
		req.AccountId = account_id
		req.RoleName = role_name
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/role", serverAddr)
		doMuxRequest(url, bearer, client, "POST", json)
	case "update_account_role":
		req := pb.UpdateAccountRoleRequest{}
		req.RoleId = role_id
		req.Version = int32(version)
		req.RoleName = role_name
		json, err := requestToJson(req)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			break
		}

		url := fmt.Sprintf("%s/api/role/%d", serverAddr, role_id)
		doMuxRequest(url, bearer, client, "PUT", json)

	case "delete_account_role":
		url := fmt.Sprintf("%s/api/role/%d/%d", serverAddr, role_id, version)
		doMuxRequest(url, bearer, client, "DELETE", nil)

	case "get_account_role_by_id":
		url := fmt.Sprintf("%s/api/role/id/%d", serverAddr, role_id)
		doMuxRequest(url, bearer, client, "GET", nil)
	case "get_account_roles":
		url := fmt.Sprintf("%s/api/roles/%d", serverAddr, account_id)
		doMuxRequest(url, bearer, client, "GET", nil)

	case "add_user_to_role":
		url := fmt.Sprintf("%s/api/role/user/%d/%d", serverAddr, role_id, user_id)
		doMuxRequest(url, bearer, client, "POST", nil)

	case "remove_user_from_role":
		url := fmt.Sprintf("%s/api/role/user/%d/%d", serverAddr, role_id, user_id)
		doMuxRequest(url, bearer, client, "DELETE", nil)

	case "add_claim_to_role":
		url := fmt.Sprintf("%s/api/role/claim/%d/%d", serverAddr, role_id, claim_value_id)
		doMuxRequest(url, bearer, client, "POST", nil)

	case "remove_claim_from_role":
		url := fmt.Sprintf("%s/api/role/claim/%d/%d", serverAddr, role_id, claim_value_id)
		doMuxRequest(url, bearer, client, "DELETE", nil)


	case "get_server_version":
		url := fmt.Sprintf("%s/api/server/version", serverAddr)
		doMuxRequest(url, bearer, client, "GET", nil)

	}
}

func doMuxRequest(url string, bearer string, client *http.Client, verb string, body io.Reader) {
	httpReq, err := http.NewRequest(verb, url, body)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	httpReq.Header.Set("Authorization", bearer)
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(httpReq)
	if err == nil {
		respBody, _ :=  ioutil.ReadAll(resp.Body)
		fmt.Println(string(respBody))
	} else {
		fmt.Printf("err: %s\n", err)
	}

}

func requestToJson(req interface{}) (*bytes.Buffer, error) {
	jtext, err := json.Marshal(req)
	// fmt.Printf("json: %s\n", string(jtext))
	buf := bytes.NewBuffer(jtext)
	return buf, err
}
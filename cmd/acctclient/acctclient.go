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

// Command line client for GRPC acctservice.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"

	flag "github.com/juju/gnuflag"

	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
	"github.com/kylelemons/go-gypsy/yaml"
	"golang.org/x/crypto/ssh/terminal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
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
		configFilename = homeDir + string(os.PathSeparator) + ".mservice.config"
	}

	config, err := yaml.ReadFile(configFilename)
	if err != nil {
		log.Fatalf("configuration not found: " + configFilename)
	}

	// log_file, _ := config.Get("log_file")
	caFile, _ := config.Get("ca_file")
	tls, _ := config.GetBool("tls")
	serverHostOverride, _ := config.Get("server_host_override")
	server, _ := config.Get("server")
	port, _ := config.GetInt("port")
	account, _ := config.Get("account")

	// fmt.Printf("log_file: %s\n", log_file)
	// fmt.Printf("ca_file: %s\n", ca_file)
	// fmt.Printf("tls: %t\n", tls)
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
		fmt.Printf("    %s update_account --account_id <account_id> [-a <account>] [--account_long_name <name>}  [--account_type <type>] \n", prog)
		fmt.Println("          [--address1 <address1>] [--address2 <address2>] [--city <city>] [--state <state>]")
		fmt.Println("          [--postal_code <postal_code>] [--country_code <country_code>] [--phone <phone>] [-e <email>]")
		fmt.Printf("    %s delete_account --account_id <account_id> \n", prog)
		fmt.Printf("    %s get_account_by_id --account_id <account_id> \n", prog)
		fmt.Printf("    %s get_account_by_name -a <account_name> \n", prog)
		fmt.Printf("    %s get_account_names \n", prog)
		fmt.Println(" ")
		fmt.Printf("    %s create_account_user --account_id <account_id> -e <email> --user_full_name <user_full_name>\n", prog)
		fmt.Println("          --user_type <user_type> --password <password>")
		fmt.Printf("    %s update_account_user --user_id <user_id> [-e <email>] [--user_full_name <user_full_name>]\n", prog)
		fmt.Println("          [--user_type <user_type>]")
		fmt.Printf("    %s update_account_user_password --user_id <user_id> --password_old <password_old> --password <password>\n", prog)
		fmt.Printf("    %s delete_account_user --user_id <user_id>\n", prog)
		fmt.Printf("    %s get_account_user_by_id --user_id <user_id>\n", prog)
		fmt.Printf("    %s get_account_user_by_email [-a <account>] -e <email>\n", prog)
		fmt.Printf("    %s get_account_users [-a <account>]\n", prog)
		fmt.Println(" ")
		fmt.Printf("    %s create_claim_name --claim_name <claim_name> --claim_description <claim_description>\n", prog)
		fmt.Printf("    %s update_claim_name --claim_name_id <claim_name_id> [--claim_name <claim_name>] [--claim_description <claim_description>]\n", prog)
		fmt.Printf("    %s delete_claim_name --claim_name_id <claim_name_id>\n", prog)
		fmt.Printf("    %s get_claim_names \n", prog)
		fmt.Printf("    %s create_claim_value --claim_name_id <claim_name_id> --claim_val <claim_val> --claim_value_description <claim_value_description>\n", prog)
		fmt.Printf("    %s update_claim_value --claim_value_id <claim_value_id> [--claim_val <claim_val>] [--claim_value_description <claim_value_description>]\n", prog)
		fmt.Printf("    %s delete_claim_value --claim_value_id <claim_value_id> \n", prog)
		fmt.Printf("    %s get_claim_value_by_id --claim_value_id <claim_value_id> \n", prog)
		fmt.Printf("    %s get_claim_values_by_name_id --claim_name_id <claim_name_id> \n", prog)
		fmt.Printf("    %s get_claim_values \n", prog)
		fmt.Println(" ")
		fmt.Printf("    %s create_account_role --account_id <account_id> --role_name <role_name>\n", prog)
		fmt.Printf("    %s update_account_role --role_id <role_id> --role_name <role_name>\n", prog)
		fmt.Printf("    %s delete_account_role --role_id <role_id>\n", prog)
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
	case "delete_account":
		if account_id == 0 {
			fmt.Println("account_id parameter missing")
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
	case "update_account_user_password":
		if user_id == 0 {
			fmt.Println("user_id parameter missing")
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
	case "delete_claim_name":
		if claim_name_id == 0 {
			fmt.Println("claim_name_id parameter missing")
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
	case "delete_claim_value":
		if claim_value_id == 0 {
			fmt.Println("claim_value_id parameter missing")
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
		if role_name == "" {
			fmt.Println("role_name parameter missing")
			validParams = false
		}
	case "delete_account_role":
		if role_id == 0 {
			fmt.Println("role_id parameter missing")
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

	address := server + ":" + strconv.Itoa(int(port))
	// fmt.Printf("address: %s\n", address)

	var opts []grpc.DialOption
	if tls {
		var sn string
		if serverHostOverride != "" {
			sn = serverHostOverride
		}
		var creds credentials.TransportCredentials
		if caFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(caFile, sn)
			if err != nil {
				grpclog.Fatalf("Failed to create TLS credentials %v", err)
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, sn)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	// set up connection to server
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	defer conn.Close()

	client := pb.NewMServiceAccountClient(conn)

	ctx := context.Background()

	savedToken := ""

	data, err := ioutil.ReadFile(tokenFilename)

	if err == nil {
		savedToken = string(data)
	}

	md := metadata.Pairs("token", savedToken)

	mctx := metadata.NewOutgoingContext(ctx, md)

	switch cmd {
	case "login":
		var token string
		req := pb.LoginRequest{}
		req.AccountName = account
		req.Email = email
		req.Password = password
		resp, err := client.Login(ctx, &req)
		if err == nil {
			if resp.ErrorCode == 0 {
				token = resp.GetJwt()
				err = ioutil.WriteFile(tokenFilename, []byte(token), 0664)
			} else {
				jtext, err := json.MarshalIndent(resp, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}

		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
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
		resp, err := client.CreateAccount(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}

	case "update_account":
		// first get the existing record
		req1 := pb.GetAccountByIdRequest{}
		req1.AccountId = account_id
		resp1, err := client.GetAccountById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.UpdateAccountRequest{}
				acct := resp1.GetAccount()
				req.AccountId = acct.GetAccountId()
				req.Version = acct.GetVersion()
				if account_name == "" {
					req.AccountName = acct.GetAccountName()
				} else {
					req.AccountName = account_name
				}
				if account_long_name == "" {
					req.AccountLongName = acct.GetAccountLongName()
				} else {
					req.AccountLongName = account_long_name
				}
				if account_type == 0 {
					req.AccountType = acct.GetAccountType()
				} else {
					req.AccountType = int32(account_type)
				}
				if address1 == "" {
					req.Address1 = acct.GetAddress1()
				} else {
					req.Address1 = address1
				}
				if address2 == "" {
					req.Address2 = acct.GetAddress2()
				} else {
					req.Address2 = address2
				}
				if city == "" {
					req.City = acct.GetCity()
				} else {
					req.City = city
				}
				if state == "" {
					req.State = acct.GetState()
				} else {
					req.State = state
				}
				if postal_code == "" {
					req.PostalCode = acct.GetPostalCode()
				} else {
					req.PostalCode = postal_code
				}
				if country_code == "" {
					req.CountryCode = acct.GetCountryCode()
				} else {
					req.CountryCode = country_code
				}
				if phone == "" {
					req.Phone = acct.GetPhone()
				} else {
					req.Phone = phone
				}
				if email == "" {
					req.Email = acct.GetEmail()
				} else {
					req.Email = email
				}
				resp, err := client.UpdateAccount(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}

			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "delete_account":
		req1 := pb.GetAccountByIdRequest{}
		req1.AccountId = account_id
		resp1, err := client.GetAccountById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.DeleteAccountRequest{}
				req.AccountId = account_id
				req.Version = resp1.GetAccount().GetVersion()
				resp, err := client.DeleteAccount(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}
			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}

	case "get_account_by_id":
		req := pb.GetAccountByIdRequest{}
		req.AccountId = account_id
		resp, err := client.GetAccountById(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_account_by_name":
		req := pb.GetAccountByNameRequest{}
		req.AccountName = account
		resp, err := client.GetAccountByName(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_account_names":
		req := pb.GetAccountNamesRequest{}
		req.DummyParam = 1
		resp, err := client.GetAccountNames(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "create_account_user":
		req := pb.CreateAccountUserRequest{}
		req.AccountId = account_id
		req.Email = email
		req.UserFullName = user_full_name
		req.UserType = int32(user_type)
		req.PasswordEnc = password
		resp, err := client.CreateAccountUser(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "update_account_user":
		req1 := pb.GetAccountUserByIdRequest{}
		req1.UserId = user_id
		resp1, err := client.GetAccountUserById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				pb_user := resp1.GetAccountUser()
				req := pb.UpdateAccountUserRequest{}
				req.UserId = pb_user.GetUserId()
				req.Version = pb_user.GetVersion()
				if email == "" {
					req.Email = pb_user.GetEmail()
				} else {
					req.Email = email
				}
				if user_full_name == "" {
					req.UserFullName = pb_user.GetUserFullName()
				} else {
					req.UserFullName = user_full_name
				}
				if user_type == 0 {
					req.UserType = pb_user.GetUserType()
				} else {
					req.UserType = int32(user_type)
				}
				resp, err := client.UpdateAccountUser(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}

			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}

		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "update_account_user_password":
		req1 := pb.GetAccountUserByIdRequest{}
		req1.UserId = user_id
		resp1, err := client.GetAccountUserById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.UpdateAccountUserPasswordRequest{}
				req.UserId = user_id
				req.Version = resp1.GetAccountUser().GetVersion()
				req.PasswordOld = password_old
				req.PasswordEnc = password
				resp, err := client.UpdateAccountUserPassword(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}
			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "delete_account_user":
		req1 := pb.GetAccountUserByIdRequest{}
		req1.UserId = user_id
		resp1, err := client.GetAccountUserById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.DeleteAccountUserRequest{}
				req.UserId = user_id
				req.Version = resp1.GetAccountUser().GetVersion()
				resp, err := client.DeleteAccountUser(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}
			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_account_user_by_id":
		req := pb.GetAccountUserByIdRequest{}
		req.UserId = user_id
		resp, err := client.GetAccountUserById(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_account_user_by_email":
		req := pb.GetAccountUserByEmailRequest{}
		req.AccountName = account
		req.Email = email
		resp, err := client.GetAccountUserByEmail(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_account_users":
		req := pb.GetAccountUsersRequest{}
		req.AccountName = account
		resp, err := client.GetAccountUsers(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "create_claim_name":
		req := pb.CreateClaimNameRequest{}
		req.ClaimName = claim_name
		req.ClaimDescription = claim_description
		resp, err := client.CreateClaimName(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "update_claim_name":
		var claim *pb.Claim
		req1 := pb.GetClaimNamesRequest{}
		req1.DummyParam = 1
		resp1, err := client.GetClaimNames(mctx, &req1)
		if (err == nil) && (resp1.GetErrorCode() == 0) {
			for _, claimName := range resp1.GetClaims() {
				if claimName.GetClaimNameId() == claim_name_id {
					claim = claimName
					break
				}
			}
		}
		req := pb.UpdateClaimNameRequest{}
		req.ClaimNameId = claim_name_id
		req.ClaimName = claim_name
		req.ClaimDescription = claim_description
		if claim != nil {
			req.Version = claim.GetVersion()
			if claim_name == "" {
				req.ClaimName = claim.GetClaimName()
			}
			if claim_description == "" {
				req.ClaimDescription = claim.GetClaimDescription()
			}
		}
		resp, err := client.UpdateClaimName(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "delete_claim_name":
		var version int32
		req1 := pb.GetClaimNamesRequest{}
		req1.DummyParam = 1
		resp1, err := client.GetClaimNames(mctx, &req1)
		if (err == nil) && (resp1.GetErrorCode() == 0) {
			for _, claimName := range resp1.GetClaims() {
				if claimName.GetClaimNameId() == claim_name_id {
					version = claimName.GetVersion()
					break
				}
			}
		}
		req := pb.DeleteClaimNameRequest{}
		req.ClaimNameId = claim_name_id
		req.Version = version
		resp, err := client.DeleteClaimName(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}

	case "get_claim_names":
		req := pb.GetClaimNamesRequest{}
		req.DummyParam = 1
		resp, err := client.GetClaimNames(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "create_claim_value":
		req := pb.CreateClaimValueRequest{}
		req.ClaimNameId = claim_name_id
		req.ClaimVal = claim_val
		req.ClaimValueDescription = claim_value_description
		resp, err := client.CreateClaimValue(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "update_claim_value":
		req1 := pb.GetClaimValueByIdRequest{}
		req1.ClaimValueId = claim_value_id
		resp1, err := client.GetClaimValueById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.UpdateClaimValueRequest{}
				req.ClaimValueId = claim_value_id
				req.Version = resp1.GetClaimValue().GetVersion()
				if claim_val == "" {
					req.ClaimVal = resp1.GetClaimValue().GetClaimVal()
				} else {
					req.ClaimVal = claim_val
				}
				if claim_value_description == "" {
					req.ClaimValueDescription = resp1.GetClaimValue().GetClaimValueDescription()
				} else {
					req.ClaimValueDescription = claim_value_description
				}
				resp, err := client.UpdateClaimValue(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}

			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "delete_claim_value":
		req1 := pb.GetClaimValueByIdRequest{}
		req1.ClaimValueId = claim_value_id
		resp1, err := client.GetClaimValueById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.DeleteClaimValueRequest{}
				req.ClaimValueId = claim_value_id
				req.Version = resp1.GetClaimValue().GetVersion()
				resp, err := client.DeleteClaimValue(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}
			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_claim_value_by_id":
		req := pb.GetClaimValueByIdRequest{}
		req.ClaimValueId = claim_value_id
		resp, err := client.GetClaimValueById(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_claim_values_by_name_id":
		req := pb.GetClaimValuesByNameIdRequest{}
		req.ClaimNameId = claim_name_id
		resp, err := client.GetClaimValuesByNameId(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_claim_values":
		req := pb.GetClaimValuesRequest{}
		req.DummyParam = 1
		resp, err := client.GetClaimValues(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "create_account_role":
		req := pb.CreateAccountRoleRequest{}
		req.AccountId = account_id
		req.RoleName = role_name
		resp, err := client.CreateAccountRole(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "update_account_role":
		req1 := pb.GetAccountRoleByIdRequest{}
		req1.RoleId = role_id
		resp1, err := client.GetAccountRoleById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.UpdateAccountRoleRequest{}
				req.RoleId = role_id
				req.RoleName = role_name
				req.Version = resp1.GetAccountRole().GetVersion()
				resp, err := client.UpdateAccountRole(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}

			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}

		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "delete_account_role":
		req1 := pb.GetAccountRoleByIdRequest{}
		req1.RoleId = role_id
		resp1, err := client.GetAccountRoleById(mctx, &req1)
		if err == nil {
			if resp1.GetErrorCode() == 0 {
				req := pb.DeleteAccountRoleRequest{}
				req.RoleId = role_id
				req.Version = resp1.GetAccountRole().GetVersion()
				resp, err := client.DeleteAccountRole(mctx, &req)
				if err == nil {
					jtext, err := json.MarshalIndent(resp, "", "  ")
					if err == nil {
						fmt.Println(string(jtext))
					}
				}
			} else {
				jtext, err := json.MarshalIndent(resp1, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_account_role_by_id":
		req := pb.GetAccountRoleByIdRequest{}
		req.RoleId = role_id
		resp, err := client.GetAccountRoleById(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_account_roles":
		req := pb.GetAccountRolesRequest{}
		req.AccountId = account_id
		resp, err := client.GetAccountRoles(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "add_user_to_role":
		req := pb.AddUserToRoleRequest{}
		req.UserId = user_id
		req.RoleId = role_id
		resp, err := client.AddUserToRole(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "remove_user_from_role":
		req := pb.RemoveUserFromRoleRequest{}
		req.UserId = user_id
		req.RoleId = role_id
		resp, err := client.RemoveUserFromRole(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "add_claim_to_role":
		req := pb.AddClaimToRoleRequest{}
		req.ClaimValueId = claim_value_id
		req.RoleId = role_id
		resp, err := client.AddClaimToRole(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "remove_claim_from_role":
		req := pb.RemoveClaimFromRoleRequest{}
		req.ClaimValueId = claim_value_id
		req.RoleId = role_id
		resp, err := client.RemoveClaimFromRole(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}

	case "get_server_version":
		req := pb.GetServerVersionRequest{}
		req.DummyParam = 1
		resp, err := client.GetServerVersion(mctx, &req)
		if err == nil {
			jtext, err := json.MarshalIndent(resp, "", "  ")
			if err == nil {
				fmt.Println(string(jtext))
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	}
}

package muxhandler

import (
	"context"
	"encoding/json"

	"github.com/gaterace/mservice/pkg/acctauth"
	pb "github.com/gaterace/mservice/pkg/mserviceaccount"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
)

type muxHandler struct {
	auth *acctauth.AccountAuth
	rtr *mux.Router
}

func NewMuxHandler(acctAuth *acctauth.AccountAuth, rtr *mux.Router) *muxHandler {
	mh := muxHandler{}
	mh.auth = acctAuth
	mh.rtr = rtr

	return &mh
}

func (mh *muxHandler) AddRoutes() {
	mh.rtr.HandleFunc("/api/login", mh.LoginHandler).Methods("POST")
}

func (mh *muxHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	req := pb.LoginRequest{}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(501)
		return
	}

	// fmt.Printf("request: %s\n", string(buf))

	err = json.Unmarshal(buf, &req)
	if err != nil {
		w.WriteHeader(502)
		return
	}

	// fmt.Printf("accountName: %s\n", req.GetAccountName())
	// fmt.Printf("email: %s\n", req.GetEmail())
	// fmt.Printf("password: %s\n", req.GetPassword())

	var ctx context.Context

	resp, err  := mh.auth.Login(ctx, &req)
	if err == nil {
		writeResponse(resp, err, int(resp.GetErrorCode()), w)
		return
	}

	w.WriteHeader(503)

	return
}

func writeResponse(resp interface{}, err error, errCode int, w http.ResponseWriter) {
	if err != nil {
		w.WriteHeader(503)
		return
	}

	if errCode == 0 {
		errCode = 200
	}

	jtext, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		w.WriteHeader(504)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(errCode)
	w.Write(jtext)
}
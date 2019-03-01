package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	. "github.com/elastos/Elastos.Service.DIDVote/cryptoballot"
)

// Handle a signature-request coming from a user
func signHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed. Only POST is allowed here.", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	signatureRequest, err := NewSignatureRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = signatureRequest.VerifySignature(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// @@TODO: Check the validity of the voter with the voter-list server. KYC voter
	isRs , err := isRetreivedSignature(signatureRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if isRs {
		http.Error(w, "already received fulfilled signature request", http.StatusBadRequest)
		return
	}
	// Sign the ballot
	ballotSig, err := conf.signingKey.BlindSign(signatureRequest.BlindBallot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a fulfilled signature request
	fulfilled := &FulfilledSignatureRequest{
		SignatureRequest: *signatureRequest,
		BallotSignature:  ballotSig,
	}

	err = saveSRToDb(fulfilled)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, fulfilled.String())
	return
}

func isRetreivedSignature(request *SignatureRequest) (bool,error) {
	r, err := db.Query("select * from sigreqs_"+request.ElectionID + " where request_id = ? and public_key = ?" , request.RequestID,request.PublicKey)
	if err != nil {
		return false, err
	}
	return r.Next(),nil
}

func saveSRToDb(request *FulfilledSignatureRequest)  error {

	_ , err := db.Exec("insert into sigreqs_"+request.ElectionID + " values(?,?,?,?,?)",request.RequestID,request.PublicKey,request.BlindBallot,request.Signature,request.BallotSignature)

	return err
}

package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	. "github.com/elastos/Elastos.Service.DIDVote/cryptoballot"
	"io/ioutil"
	"net/http"
	"strings"
)

func electionHandler(w http.ResponseWriter, r *http.Request) {
	// Parse URL and route
	urlparts := strings.Split(r.RequestURI, "/")

	// If the user is asking for `/election` or `/election/` then give them all the elections
	if r.RequestURI == "/election" || r.RequestURI == "/election/" {
		handleGETAllElections(w, r)
		return
	}

	// Check for the correct number of request parts
	if len(urlparts) != 3 {
		http.Error(w, "Invalid URL. 404 Not Found.", http.StatusNotFound)
		return
	}

	// Get the electionID
	electionID := urlparts[2]

	// Check for valid election ID
	if len(electionID) > MaxElectionIDSize || !ValidElectionID.MatchString(electionID) {
		http.Error(w, "Invalid Election ID. 404 Not Found.", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "GET":
		handleGETElection(w, r, electionID)
	case "PUT":
		handlePUTElection(w, r, electionID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePUTElection(w http.ResponseWriter, r *http.Request, electionID string) {
	err := verifySignatureHeaders(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	election, err := NewElection(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if election.ElectionID != electionID {
		http.Error(w, "Election ID mismatch between body and URL", http.StatusBadRequest)
		return
	}
	if hex.EncodeToString(election.PublicKey) != r.Header.Get("X-Public-Key") {
		http.Error(w, "Public Key mismatch between headers and body", http.StatusBadRequest)
		return
	}

	// Verify the signature on the election
	err = election.VerifySignature()
	if err != nil {
		http.Error(w, "Error verifying election signature. "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check to make sure this admin exists and has permission to administer elections
	//admin := conf.adminUsers.GetUser(election.PublicKey)
	admin := conf.didPublicKey == hex.EncodeToString(election.PublicKey)
	if !admin {
		http.Error(w, "Could not find admin with the provided public key of "+hex.EncodeToString(election.PublicKey), http.StatusForbidden)
		return
	}

	// All checks pass. Save the election
	err = saveElectionToDB(election)
	if err != nil {
		http.Error(w, "Error saving election: "+err.Error(), http.StatusInternalServerError)
	}
}

func saveElectionToDB(election *Election) error {
	buf := new(bytes.Buffer)
	for key, value := range election.TagSet.Map() {
		buf.WriteString(key)
		buf.WriteString("=")
		buf.WriteString(value)
		buf.WriteByte('\n')
	}
	tags := ""
	if buf.Len() > 0 {
		tags = string(buf.Bytes()[:(buf.Len()-1)])
	}
	_, err := db.Exec("INSERT INTO elections (election_id, election, startdate, enddate, tags) VALUES (?, ?, ?, ?, ?)", election.ElectionID, election.String(), election.Start, election.End, tags)
	if err != nil {
		return err
	}

	// Create the sigreqa table for storing signature requests
	_, err = db.Exec(strings.Replace(sigreqsQuery, "<election-id>", election.ElectionID, -1))
	if err != nil {
		return err
	}
	_, err = db.Exec(strings.Replace(sigreqsQueryIndex, "<election-id>", election.ElectionID, -1))
	if err != nil {
		return err
	}
	return nil
}

func handleGETElection(w http.ResponseWriter, r *http.Request, electionID string) {
	var rawElection []byte
	err := db.QueryRow("SELECT election FROM elections WHERE election_id = ?", electionID).Scan(&rawElection)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Could not find election with ID "+electionID, http.StatusNotFound)
		} else {
			http.Error(w, "Error reading election from database: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.Write(rawElection)
	return
}

func handleGETAllElections(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT election FROM elections")
	if err != nil {
		http.Error(w, "Error reading elections from database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for i := 0; rows.Next(); i++ {
		if i != 0 {
			w.Write([]byte("\n\n\n"))
		}
		var rawElection []byte
		err := rows.Scan(&rawElection) // Will this work? Can I scan into a io.Writer?
		if err != nil {
			http.Error(w, "Error reading elections from database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(rawElection)
	}
	return
}

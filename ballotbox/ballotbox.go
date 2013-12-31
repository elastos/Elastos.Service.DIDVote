package main

// NOTES
// See https://bitbucket.org/bumble/bumble-golang-common/src/master/key/publickey.go

import (
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	//"github.com/davecgh/go-spew/spew"
	"github.com/lib/pq"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	db             *sql.DB
	ballotClerkKey PublicKey // Used to verify signatures on ballots
	conf           Config
)

type parseError struct {
	Err  string
	Code int
}

func (err parseError) Error() string {
	return err.Err
}

func main() {
	// Bootstrap parses flags and config files, and set's up the database connection.
	bootstrap()

	// Bootstrap is complete, let's serve some REST
	//@@TODO BEAST AND CRIME protection
	//@@TODO SSL only

	http.HandleFunc("/vote/", voteHandler)

	//@@TODO /admin/ adminHandler

	log.Println("Listning on port 8002")

	err := http.ListenAndServe(":8002", nil)

	if err != nil {
		log.Fatal("Error starting http server: ", err)
	}
}

func bootstrap() {
	config_path_opt := flag.String("config", "./test.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	set_up_opt := flag.Bool("set-up-db", false, "Set up fresh database tables and schema. This should be run once before normal operations can occur.")
	flag.Parse()

	//@@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
	err := conf.loadFromFile(*config_path_opt)
	if err != nil {
		log.Fatal("Error parsing config file. ", err)
	}

	//@@TODO: Check to make sure the sslmode is set to "verify-full" (unless the user passed --insecure)
	//        See pq package documentation

	// Connect to the database and set-up
	db, err = sql.Open("postgres", conf.voteDBConnectionString())
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	// Set the maximum number of idle connections in the connection pool. `-1` means default (2 idle connections in the pool)
	if conf.voteDB.maxIdleConnections != -1 {
		db.SetMaxIdleConns(conf.voteDB.maxIdleConnections)
	}

	// If we are in 'set-up' mode, set-up the database and exit
	// @@TODO: schema.sql should be found in some path that is configurable by the user (voteflow-path environment variable?)
	if *set_up_opt {
		schema_sql, err := ioutil.ReadFile("./schema.sql")
		if err != nil {
			log.Fatal("Error loading database schema: ", err)
		}
		_, err = db.Exec(string(schema_sql))
		if err != nil {
			log.Fatal("Error loading database schema: ", err.(pq.PGError).Get('M'))
		}
		fmt.Println("Database set-up complete. Please run again without --set-up-db")
		os.Exit(0)
	}
}

func voteHandler(w http.ResponseWriter, r *http.Request) {
	electionID, ballotID, err := parseVoteRequest(r)
	if err != nil {
		http.Error(w, err.Error(), err.(parseError).Code)
		return
	}

	// If there is no ballotID and we are GETing, just return the full-list of votes for the electionID
	if ballotID == "" {
		if r.Method == "GET" {
			handleGETVoteBatch(w, r, electionID)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	// We are dealing with an individual vote
	if r.Method == "GET" {
		handleGETVote(w, r, electionID, ballotID)
	} else if r.Method == "PUT" {
		handlePUTVote(w, r, electionID, ballotID)
	} else if r.Method == "DELETE" {
		handleDELETEVote(w, r, electionID, ballotID)
	} else if r.Method == "HEAD" {
		handleHEADVote(w, r, electionID, ballotID)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleGETVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	w.Write([]byte("OK, let's GET a vote!"))
}

func handlePUTVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ballot, err := NewBallot(body)
	if err != nil {
		http.Error(w, "Error reading ballot. "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the signature
	err = verifyBallotSignature(ballot)
	if err != nil {
		http.Error(w, "Error verifying ballot signature. "+err.Error(), http.StatusInternalServerError)
		return
	}

	//@@TODO save to database

	w.Write([]byte(ballot.String()))
}

func handleDELETEVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	// If X-Voteflow-Public-Key was passed, it's already been verified, so we just need to check that it exists
	pk := r.Header.Get("X-Voteflow-Public-Key")
	if pk == "" {
		http.Error(w, "X-Voteflow-Public-Key header required for DELETE operations", http.StatusBadRequest)
		return
	}

	w.Write([]byte("OK, let's DELETE a vote!"))
}

func handleHEADVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	w.Write([]byte("OK, let's HEAD a vote!"))
}

func handleGETVoteBatch(w http.ResponseWriter, r *http.Request, electionID string) {
	w.Write([]byte("Full vote batch response to go here"))
}

// returns electionID, BallotID, publicKey (base64 encoded) and an error
func parseVoteRequest(r *http.Request) (electionID string, ballotID string, err error) {
	// Parse URL and route
	urlparts := strings.Split(r.RequestURI, "/")

	// Check for the correct number of request parts
	if len(urlparts) < 3 || len(urlparts) > 4 {
		err = parseError{"Invalid number of request parts", http.StatusNotFound}
		return
	}

	// Get the electionID
	electionID = urlparts[2]
	if len(electionID) > MaxElectionIDSize {
		err = parseError{"Invalid Election ID. 404 Not Found.", http.StatusNotFound}
		return
	}

	// If we are only length 3, that's it, we are asking for a full report / ballot roll for an election
	if len(urlparts) == 3 {
		return
	}

	// Get the ballotID (hex encoded SHA512 of base64 encoded public-key)
	ballotID = urlparts[3]
	if len(ballotID) > MaxBallotIDSize || !ValidBallotID.MatchString(ballotID) {
		err = parseError{"Invalid Ballot ID. 404 Not Found.", http.StatusNotFound}
	}

	// If the user has provided a signature of the request in the headers, verify it
	if r.Header.Get("X-Voteflow-Signature") != "" {
		// Verify the signature headers, do a cryptographic check to make sure the header and Method / URL request is signed
		if suberr := verifySignatureHeaders(r); suberr != nil {
			err = parseError{suberr.Error(), http.StatusBadRequest}
			return
		}
	}

	// All checks pass
	return
}

func verifySignatureHeaders(r *http.Request) error {
	pk, err := NewPublicKey([]byte(r.Header.Get("X-Voteflow-Public-Key")))
	if err != nil {
		return errors.New("Error parsing X-Voteflow-Public-Key header. " + err.Error())
	}

	sig, err := NewSignature([]byte(r.Header.Get("X-Voteflow-Signature")))
	if err != nil {
		return errors.New("Error parsing X-Voteflow-Signature header. " + err.Error())
	}

	// Verify the signature against the request string. For example PUT /vote/1234/939fhdsjkksdkl0903f...
	err = sig.VerifySignature(pk, []byte(r.Method+" "+r.RequestURI))
	if err != nil {
		return errors.New("Error verifying signature. " + err.Error())
	}

	return nil
}

func verifyBallotSignature(ballot *Ballot) error {
	// First we need to get the public key we will be using the verify the ballot.
	//@@TODO: One public key per election

	// First we need to load the public key from the ballotClerk server if this value has not already been set
	if ballotClerkKey.IsEmpty() {
		resp, err := http.Get(conf.ballotclerkURL + "/publickey")
		if err != nil {
			return errors.New("Error fetching public key from Ballot Clerk Server. " + err.Error())
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.New("Error fetching public key from Ballot Clerk Server. " + err.Error())
		}

		PEMBlock, _ := pem.Decode(body)
		if PEMBlock == nil || PEMBlock.Type != "RSA PUBLIC KEY" {
			return errors.New("Error fetching public key from Ballot Clerk Server. Could not find an RSA PUBLIC KEY block")
		}
		publicKey, err := NewPublicKey([]byte(base64.StdEncoding.EncodeToString(PEMBlock.Bytes)))
		if err != nil {
			return errors.New("Error fetching public key from Ballot Clerk Server. " + err.Error())
		}
		ballotClerkKey = publicKey
	}

	// Verify the ballot
	return ballot.VerifySignature(ballotClerkKey)
}

// Load a ballot from the backend postgres database - returns a pointer to a ballot.
func loadBallotFromDB(ElectionID string, ballotID string) (*Ballot, error) {
	return nil, errors.New("Not implemented")
}

func saveBallotToDB(ballot *Ballot) error {
	// The most complicated thing about this query is dealing with the tagSet, which needs to be inserted into an hstore column
	var tagKeyHolders, tagValHolders []string
	for i := 4; i < len(ballot.TagSet)+4; i++ {
		tagKeyHolders = append(tagKeyHolders, "$"+strconv.Itoa(i))
		tagValHolders = append(tagValHolders, "$"+strconv.Itoa(i+len(ballot.TagSet)))
	}
	query := "INSERT INTO ballots (ballot_id, ballot, tags) VALUES ($1, $2, $3, hstore(ARRAY[" + strings.Join(tagKeyHolders, ", ") + "], ARRAY[" + strings.Join(tagValHolders, ", ") + "]))"

	// golang's use of variadics is entirely too stringent, so you get crap like this
	values := append([]string{ballot.BallotID, ballot.String()}, append(ballot.TagSet.KeyStrings(), ballot.TagSet.ValueStrings()...)...)
	// Convert []string to []interface{}
	insertValues := make([]interface{}, len(values))
	for i, v := range values {
		insertValues[i] = interface{}(v)
	}

	_, err := db.Exec(query, insertValues...)
	return err
}

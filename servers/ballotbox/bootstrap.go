package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/cryptoballot/entropychecker"
	"github.com/dlintw/goconf"
	. "github.com/elastos/Elastos.Service.DIDVote/cryptoballot"
	_ "github.com/go-sql-driver/mysql"
)

// Bootstrap parses flags and config files, and set's up the database connection.
func bootstrap() {

	// If we are on linux, ensure we have sufficient entropy.
	if runtime.GOOS == "linux" {
		err := entropychecker.WaitForEntropy()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load config file
	configPathOpt := flag.String("config", "./test.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	//configEnvOpt := flag.Bool("envconfig", false, "Use environment variables (instead of an ini file) for configuration.")

	flag.Parse()

	//@@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
	c, err := NewConfigFromFile(*configPathOpt)
	if err != nil {
		log.Fatal("Error parsing config file. ", err)
	}
	conf = *c

	//@@TODO: Check to make sure the sslmode is set to "required" (unless the user passed --insecure)
	// Connect to the database and set-up
	db, err = sql.Open("mysql", conf.databaseConnectionString())
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	// Set the maximum number of idle connections in the connection pool. `-1` means default (2 idle connections in the pool)
	if conf.database.maxIdleConnections != -1 {
		db.SetMaxIdleConns(conf.database.maxIdleConnections)
	}
	// ConnMaxLifetime unit is second
	db.SetConnMaxLifetime(time.Duration(conf.database.connMaxLifetime * 1000 * 1000 * 1000))

	// Sync elections to database tables
	err = syncElectionToDB(conf.elections)
	if err != nil {
		log.Fatal("Error syncing elections to database: ", err)
	}
}

//@@TEST: loading known good config from file
func NewConfigFromFile(filepath string) (*config, error) {
	conf := config{
		configFilePath: filepath,
	}

	c, err := goconf.ReadConfigFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("Could not find config file. Try using the --config=\"<path-to-config-file>\" option to specify a config file.")
		} else {
			return nil, err
		}
	}

	// Change our working directory to that of the config file so that paths referenced in the config file are relative to that location
	err = os.Chdir(path.Dir(filepath))
	if err != nil {
		return nil, err
	}

	// Parse port
	conf.port, err = c.GetInt("", "port")
	if err != nil {
		return nil, err
	}

	// Parse database
	conf.database.driver, err = c.GetString("database", "driver")
	if err != nil {
		return nil, err
	}
	conf.database.sslmode, err = c.GetString("database", "sslmode")
	if err != nil {
		return nil, err
	}
	// For max_idle_connections missing should translates to -1
	if c.HasOption("database", "max_idle_connections") {
		conf.database.maxIdleConnections, err = c.GetInt("database", "max_idle_connections")
		if err != nil {
			return nil, err
		}
	} else {
		conf.database.maxIdleConnections = -1
	}

	// For conn_max_lifetime missing should translates to 4 hours
	if c.HasOption("database", "conn_max_lifetime") {
		conf.database.connMaxLifetime, err = c.GetInt("database", "conn_max_lifetime")
		if err != nil {
			return nil, err
		}
	} else {
		conf.database.connMaxLifetime = 14440
	}


	// Parse election-clerk URL
	conf.electionclerkURL, err = c.GetString("", "electionclerk-url")
	if err != nil {
		return nil, err
	}
	_, err = url.Parse(conf.electionclerkURL)
	if err != nil {
		return nil, err
	}

	// Ingest the readme
	conf.readmePath, err = c.GetString("", "readme")
	if err != nil {
		return nil, err
	}

	// Process local files
	err = configProcessFiles(&conf)
	if err != nil {
		return nil, err
	}

	// Update From BallotClerk
	err = UpdateConfigFromBallotClerk(&conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

// Process the readme
func configProcessFiles(conf *config) error {
	// Ingest the readme
	var err error
	conf.readme, err = ioutil.ReadFile(conf.readmePath)
	if err != nil {
		return err
	}

	return nil
}

func UpdateConfigFromBallotClerk(conf *config) error {
	// Get the ballot-clerk public key
	body, err := httpGetAll(conf.electionclerkURL + "/publickey")
	if err != nil {
		return err
	}
	PEMBlock, _ := pem.Decode(body)
	if PEMBlock.Type != "PUBLIC KEY" {
		return errors.New("Could not parse Election Clerk Public Key")
	}
	cryptoKey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
	if err != nil {
		return err
	}
	conf.clerkKey, err = NewPublicKeyFromCryptoKey(cryptoKey.(*rsa.PublicKey))
	if err != nil {
		return err
	}

	// Get the admin users
	body, err = httpGetAll(conf.electionclerkURL + "/admins")
	if err != nil {
		return err
	}
	conf.adminUsers, err = NewUserSet(body)
	if err != nil {
		return err
	}

	// Get the list of elections
	body, err = httpGetAll(conf.electionclerkURL + "/election")
	if err != nil {
		return err
	}
	if len(body) != 0 {
		rawElections := bytes.Split(body, []byte("\n\n\n"))
		conf.elections = make(map[string]Election, len(rawElections))

		for _, rawElection := range rawElections {
			election, err := NewElection(rawElection)
			if err != nil {
				return err
			}
			conf.elections[election.ElectionID] = *election
		}
	}

	return nil
}

// Given a URL, do the request and get the body as a byte slice
func httpGetAll(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("Received " + resp.Status + " from " + url)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (conf *config) databaseConnectionString() (connection string) {

	return conf.database.driver
}

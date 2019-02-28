package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/cryptoballot/entropychecker"
	"github.com/dlintw/goconf"
	. "github.com/elastos/Elastos.Service.DIDVote/cryptoballot"
	_ "github.com/go-sql-driver/mysql"
	"github.com/phayes/decryptpem"
)

func bootstrap() {

	// If we are on linux, ensure we have sufficient entropy.
	if runtime.GOOS == "linux" {
		err := entropychecker.WaitForEntropy()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Get configuration from file or environment
	configPathOpt := flag.String("config", "./electionclerk.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	setUpOpt := flag.Bool("set-up-db", false, "Set up fresh database tables and schema. This should be run once before normal operations can occur.")
	flag.Parse()


	config, err := NewConfigFromFile(*configPathOpt)
	if err != nil {
		log.Fatal("Error parsing config file. ", err)
	}
	conf = *config

	// Connect to the database and set-up
	db, err = sql.Open("mysql", conf.databaseConnectionString())
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	// Set the maximum number of idle connections in the connection pool. `-1` means default of 2 idle connections in the pool
	if conf.database.maxIdleConnections != -1 {
		db.SetMaxIdleConns(conf.database.maxIdleConnections)
	}
	// ConnMaxLifetime unit is second
	db.SetConnMaxLifetime(time.Duration(conf.database.connMaxLifetime * 1000 * 1000 * 1000))


	// If we are in 'set-up' mode, set-up the database and exit
	if *setUpOpt {
		_, err = db.Exec(schemaQuery)
		if err != nil {
			log.Fatal("Error loading database schema: ", err.Error())
		}
		_, err = db.Exec(schemaQueryIndex)
		if err != nil {
			log.Fatal("Error loading database schema: ", err.Error())
		}
		fmt.Println("Database set-up complete. Please run again without --set-up-db")
		os.Exit(0)
	}
}

func NewConfigFromFile(filepath string) (*Config, error) {
	config := Config{
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
	config.port, err = c.GetInt("", "port")
	if err != nil {
		return nil, err
	}

	// Parse did public key
	config.didPublicKey, err = c.GetString("", "didPublicKey")
	if err != nil {
		return nil, err
	}

	// Parse database config options
	config.database.driver, err = c.GetString("database", "driver")
	if err != nil {
		return nil, err
	}
	config.database.sslmode, err = c.GetString("database", "sslmode")
	if err != nil {
		return nil, err
	}
	// For max_idle_connections missing should translates to -1
	if c.HasOption("database", "max_idle_connections") {
		config.database.maxIdleConnections, err = c.GetInt("database", "max_idle_connections")
		if err != nil {
			return nil, err
		}
	} else {
		config.database.maxIdleConnections = -1
	}

	// For conn_max_lifetime missing should translates to 4 hours
	if c.HasOption("database", "conn_max_lifetime") {
		config.database.connMaxLifetime, err = c.GetInt("database", "conn_max_lifetime")
		if err != nil {
			return nil, err
		}
	} else {
		config.database.connMaxLifetime = 14440
	}

	// Ingest the private key into the global config object
	config.signingKeyPath, err = c.GetString("", "signing-key")
	if err != nil {
		return nil, err
	}

	// Ingest administrators
	config.adminKeysPath, err = c.GetString("", "admins")
	if err != nil {
		return nil, err
	}

	// Ingest the readme
	config.readmePath, err = c.GetString("", "readme")
	if err != nil {
		return nil, err
	}

	// Processs files
	err = configProcessFiles(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// Process the signing key, admin keys, and the readme
func configProcessFiles(config *Config) error {
	// Ingest the private key into the global config object
	signingKeyPEM, err := decryptpem.DecryptFileWithPrompt(config.signingKeyPath)
	if err != nil {
		return err
	}
	config.signingKey, err = NewPrivateKeyFromBlock(signingKeyPEM)
	if err != nil {
		return err
	}

	// Ingest administrators
	adminPEMBytes, err := ioutil.ReadFile(config.adminKeysPath)
	if err != nil {
		return err
	}
	config.adminUsers, err = NewUserSet(adminPEMBytes)
	if err != nil {
		return err
	}

	// Ingest the readme
	config.readme, err = ioutil.ReadFile(config.readmePath)
	if err != nil {
		return err
	}

	return nil
}

func (config *Config) databaseConnectionString() (connection string) {
	return config.database.driver
}

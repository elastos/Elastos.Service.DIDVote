package main

import (
	"encoding/hex"
	"fmt"
	"github.com/cryptoballot/entropychecker"
	"github.com/elastos/Elastos.Service.DIDVote/clients/util"
	"github.com/elastos/Elastos.Service.DIDVote/cryptoballot"
	"github.com/phayes/decryptpem"
	"github.com/urfave/cli"
	"log"
	"os"
	"runtime"
)

// Version specifies the version of this binary
var Version = "0.1"

// BallotClerkClient is used to connect to ballotclerk server
var BallotClerkClient *util.BallotclerkClient

// BallotBoxClient is used to connect to ballotbox server
var BallotBoxClient *util.BallotBoxClient

// PrivateKey for all operations that require a private key
var PrivateKey cryptoballot.PrivateKey

// PublicKey derived from PrivateKey
var PublicKey cryptoballot.PublicKey

// DID PrivateKey
var DidPrivateKey cryptoballot.DIDPrivateKey

// DID PublicKey derived from DiDPrivateKey
var DidPublicKey cryptoballot.DIDPublicKey

func main() {
	app := cli.NewApp()
	app.Name = "cryptoballot"

	// Global options
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "ballotclerk",
			Value: "http://localhost:8000",
		},
		cli.StringFlag{
			Name:  "ballotbox",
			Value: "http://localhost:8001",
		},
		cli.StringFlag{
			Name:  "key",
			Value: "",
		},
		cli.StringFlag{
			Name:  "didKey",
			Value: "",
		},
	}

	// Commands
	app.Commands = []cli.Command{
		{
			Name:  "admin",
			Usage: "perform election administrative operations",
			Subcommands: []cli.Command{
				{
					Name:      "create",
					Usage:     "create a new election",
					Action:    actionAdminCreate,
					ArgsUsage: "[electionfile]",
				},
				{
					Name:      "tally",
					Usage:     "Verify and tally election results",
					ArgsUsage: "[election-id]",
					Action:    actionAdminTally,
				},
			},
		},
		{
			Name:  "voter",
			Usage: "vote in an election",
			Subcommands: []cli.Command{
				{
					Name:      "vote",
					Usage:     "vote in an election",
					Action:    actionVoterVote,
					ArgsUsage: "[votefile]",
				},
				{
					Name:      "verify",
					Usage:     "Verify that the voters vote has been counted",
					ArgsUsage: "[votefile]",
					Action: func(c *cli.Context) error {
						fmt.Println("verify: ", c.Args().First())
						return nil
					},
				},
			},
		},
		{
			Name:  "version",
			Usage: "print version",
			Action: func(c *cli.Context) error {
				fmt.Println(Version)
				return nil
			},
		},
	}

	// Set up connections to services
	app.Before = func(c *cli.Context) error {

		// If we are on linux, ensure we have sufficient entropy.
		if runtime.GOOS == "linux" {
			err := entropychecker.WaitForEntropy()
			if err != nil {
				log.Fatal(err)
			}
		}

		// ballotclerk
		BallotClerkClient = util.NewBallotclerkClient(c.String("ballotclerk"))

		// Connect to A4D Extract
		BallotBoxClient = util.NewBallotBoxClient(c.String("ballotbox"))

		// Privat Key
		if c.String("key") != "" {

			// Decrypt it as needed
			pem, err := decryptpem.DecryptFileWithPrompt(c.String("key"))
			if err != nil {
				log.Fatal(err)
			}

			PrivateKey, err = cryptoballot.NewPrivateKeyFromBlock(pem)
			if err != nil {
				log.Fatal(err)
			}

			PublicKey, err = PrivateKey.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
		}
		// DID private key
		var err error
		DidPrivateKey,err = hex.DecodeString(c.String("didKey"))
		if err != nil {
			log.Fatal("Invalid didKey :" + err.Error())
		}
		if len(DidPrivateKey) == 32 {
			var err error
			DidPublicKey , err = DidPrivateKey.GetPublicKeyFromPrivateKey()
			if err != nil {
				log.Fatal(err)
			}
		}
		return nil
	}

	app.Version = Version
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

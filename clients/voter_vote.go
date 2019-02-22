package main

import (
	"github.com/elastos/Elastos.ELA.Utility/common"
	"io/ioutil"
	"log"

	"github.com/elastos/Elastos.Service.DIDVote/cryptoballot"
	"github.com/urfave/cli"
)

func actionVoterVote(c *cli.Context) error {
	filename := c.Args().First()

	if filename == "" {
		log.Fatal("Please specify an balliot file to PUT to the ballotbox server")
	}

	if PrivateKey == nil {
		log.Fatal("Please specify a private key pem file with --key (eg: `--key=path/to/mykey.pem`)")
	}

	if len(DidPrivateKey) != 32 {
		log.Fatal("Please specify a did private key with --didKey (eg: `--didKey=CC6FA0F0E191AD47A430FE04411C079F07D5C1EE47C3AA55F0E0204C8FE36D17`)")
	}


	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	ballot, err := cryptoballot.NewBallot(content)
	if err != nil {
		log.Fatal(err)
	}

	// Get public key from ballotclerk server
	clerkPublicKey, err := BallotClerkClient.GetPublicKey()
	if err != nil {
		log.Fatal(err)
	}

	// Blind the ballot
	blindBallot, unblinder, err := ballot.Blind(clerkPublicKey)
	if err != nil {
		log.Fatal(err)
	}


	// Create a signature request
	reqId := common.Sha256D(DidPublicKey.Bytes())
	signatureRequest := &cryptoballot.SignatureRequest{
		ElectionID:  ballot.ElectionID,
		RequestID:   reqId[:],
		PublicKey:   DidPublicKey.Bytes(),
		BlindBallot: blindBallot,
	}
	// replace it with DID privatekey
	signatureRequest.Signature, err = DidPrivateKey.SignString(signatureRequest.String())
	if err != nil {
		log.Fatal(err)
	}
	// Do the signature request
	fulfilled, err := BallotClerkClient.PostSignatureRequest(signatureRequest, DidPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Unblind the ballot using the FulfilledSignatureRequest
	err = ballot.Unblind(clerkPublicKey, fulfilled.BallotSignature, unblinder)
	if err != nil {
		log.Fatal(err)
	}

	// PUT the ballot
	err = BallotBoxClient.PutBallot(ballot)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

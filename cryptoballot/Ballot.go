package cryptoballot

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"

	"github.com/cryptoballot/fdh"
	"github.com/cryptoballot/rsablind"
	"github.com/phayes/errors"
)

const (
	MaxBallotIDSize = 128
)

var (
	// maxBallotSize: election-id (max 128 bytes) + BallotID + Vote + (64 tags) + signature + line-seperators
	MaxBallotSize = MaxElectionIDSize + MaxBallotIDSize + (maxVoteSize) + (64 * (MaxTagKeySize + MaxTagValueSize + 1)) + base64.StdEncoding.EncodedLen(1024) + (4*2 + 64 + 64)
	ValidBallotID = regexp.MustCompile(`^[0-9a-zA-Z\-\.\[\]_~:/?#@!$&'()*+,;=]+$`) // Regex for valid characters. More or less the same as RFC 3986, sec 2.

	ErrBallotTooBig        = errors.Newf("This ballot is too big. Maximum ballot size is %d bytes", MaxBallotSize)
	ErrBallotIDTooBig      = errors.Newf("Ballot ID is too big. Maximum ballot-id size is %d characters", MaxBallotIDSize)
	ErrBallotInvalid       = errors.New("Invalid ballot format")
	ErrBallotIDInvalid     = errors.New("Ballot ID contains illigal characters. Valid characters are as per RFC 3986, sec 2: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=")
	ErrBallotInvalidVote   = errors.New("Cannot parse Cote in ballot")
	ErrBallotInvalidTagSet = errors.New("Cannot parse TagSet in ballot")
	ErrBallotInvalidSig    = errors.New("Cannot parse ballot Signature")
	ErrBallotBadSig        = errors.New("Ballot signature does not sign this ballot")
	ErrBallotSigNotFound   = errors.New("Could not verify ballot signature: Signature does not exist")
	ErrBallotCannotBlind   = errors.New("Could not blind ballot")
	ErrBallotCannotUnblind = errors.New("Could not unblind ballot")
	ErrBallotHasSignature  = errors.New("The ballot already has a signature")
)

type Ballot struct {
	ElectionID string
	BallotID   string // Random user-selected string. Valid characters are as per RFC 3986, sec 2: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=
	Vote              // Ordered list of choice
	TagSet            // Arbitrary key-value store
	Signature         // Crypto signature for the ballot (signed by ballot-clerk server)
}

// Given a raw ballot-string (as a []byte) (see documentation for format), return a new Ballot.
// Generally the ballot-string is coming from a client in a PUT body.
// This will also verify the signature on the ballot and return an error if the ballot does not pass crypto verification
func NewBallot(rawBallot []byte) (*Ballot, error) {
	var (
		tagsSec    int
		signSec    int
		err        error
		electionID string
		ballotID   string
		vote       Vote
		tagSet     TagSet
		signature  Signature
	)

	// Check it's size
	if len(rawBallot) > MaxBallotSize {
		return nil, ErrBallotTooBig
	}

	// Split the ballot into parts seperated by a double linebreak
	parts := bytes.Split(rawBallot, []byte("\n\n"))

	// Determine what components exist
	numParts := len(parts)
	switch numParts {
	case 3:
		tagsSec = 0
		signSec = 0
	case 4:
		// We need to determine if the last element in the ballot is a tag or a signature
		if bytes.Contains(parts[3], []byte{'\n'}) {
			// If it contains a linebreak, it's a tagset
			tagsSec = 3
			signSec = 0
		} else {
			// We need to test by looking at length. The maximum tagset size is smaller than the smallest signature
			if len(parts[3]) > (MaxTagKeySize + MaxTagValueSize + 1) {
				tagsSec = 0
				signSec = 3
			} else {
				tagsSec = 3
				signSec = 0
			}
		}
	case 5:
		tagsSec = 3
		signSec = 4
	default:
		return &Ballot{}, ErrBallotInvalid
	}

	electionID = string(parts[0])
	if len(electionID) > MaxElectionIDSize {
		return &Ballot{}, ErrElectionIDTooBig
	}
	if !ValidElectionID.MatchString(electionID) {
		return &Ballot{}, ErrElectionIDInvalid
	}

	ballotID = string(parts[1])
	if len(ballotID) > MaxBallotIDSize {
		return &Ballot{}, ErrBallotIDTooBig
	}
	if !ValidBallotID.MatchString(ballotID) {
		return &Ballot{}, ErrBallotIDInvalid
	}

	vote, err = NewVote(parts[2])
	if err != nil {
		return &Ballot{}, errors.Wrap(err, ErrBallotInvalidVote)
	}

	if tagsSec != 0 {
		tagSet, err = NewTagSet(parts[tagsSec])
		if err != nil {
			return &Ballot{}, errors.Wrap(err, ErrBallotInvalidTagSet)
		}
	} else {
		tagSet = nil
	}

	if signSec != 0 {
		signature, err = NewSignature(parts[signSec])
		if err != nil {
			return &Ballot{}, errors.Wrap(err, ErrBallotInvalidSig)
		}
	} else {
		signature = nil
	}

	// All checks pass, create and return the ballot
	ballot := Ballot{
		electionID,
		ballotID,
		vote,
		tagSet,
		signature,
	}
	return &ballot, nil
}

// VerifySignature verifies that the ballot has been property cryptographically signed
func (ballot *Ballot) VerifySignature(pk PublicKey) error {
	if !ballot.HasSignature() {
		return errors.Wrap(ErrBallotSigNotFound, ErrBallotBadSig)
	}
	s := ballot.StringWithoutSignature()
	h := sha256.New()
	h.Write([]byte(s))
	return ballot.Signature.VerifyRawSignature(pk, h.Sum(nil))
}

// VerifyBlindSignature verifies that the ballot has been property cryptographically signed with a blind signature
func (ballot *Ballot) VerifyBlindSignature(pk PublicKey) error {
	if !ballot.HasSignature() {
		return errors.Wrap(ErrBallotSigNotFound, ErrBallotBadSig)
	}

	// Verify that the blind signature is corrrect
	return ballot.Signature.VerifyBlindSignature(pk, []byte(ballot.StringWithoutSignature()))
}

// GetSHA256 gets the (hex-encoded) SHA256 of the String value of the ballot.
func (ballot *Ballot) GetSHA256() []byte {
	h := sha256.New()
	h.Write([]byte(ballot.String()))
	sha256hex := make([]byte, hex.EncodedLen(sha256.Size))
	hex.Encode(sha256hex, h.Sum(nil))
	return sha256hex
}

// TagSets are optional, check to see if this ballot has them
func (ballot *Ballot) HasTagSet() bool {
	return ballot.TagSet != nil
}

// Signatures are generally required, but are sometimes optional (for example, for working with the ballot before it is signed)
// This function checks to see if the ballot has a signature
func (ballot *Ballot) HasSignature() bool {
	return ballot.Signature != nil
}

// Implements Stringer. Returns the String that would be expected in a PUT request to create the ballot
// The returned string is the same format as expected by NewBallot
func (ballot Ballot) String() string {
	s := ballot.StringWithoutSignature()

	if ballot.HasSignature() {
		s += "\n\n" + ballot.Signature.String()
	}

	return s
}

// StringWithoutSignature returns a string of the ballot without the signature, OK for signing.
func (ballot *Ballot) StringWithoutSignature() string {
	s := ballot.ElectionID + "\n\n" + ballot.BallotID + "\n\n" + ballot.Vote.String()
	if ballot.HasTagSet() {
		s += "\n\n" + ballot.TagSet.String()
	}

	return s
}

// Blind blinds the ballot, making it ready for signing by a signing authority
// It will blind the ballot using a full-domain-hash that is half the size of the signing' authority's key.
// The result is returned as a hex encoding of the blinded ballot, and a raw unblinder.
func (ballot *Ballot) Blind(signingKey PublicKey) (blinded BlindBallot, ublinder []byte, err error) {
	if ballot.HasSignature() {
		return nil, nil, errors.Wrap(ErrBallotHasSignature, ErrBallotCannotBlind)
	}

	// Full-domain-hash that is half the key size
	keylen, err := signingKey.KeyLength()
	if err != nil {
		return nil, nil, errors.Wrap(err, ErrBallotCannotBlind)
	}
	hashed := fdh.Sum(crypto.SHA256, keylen/2, []byte(ballot.StringWithoutSignature()))

	// The the cryptokey from the public key
	pubcrypt, err := signingKey.GetCryptoKey()
	if err != nil {
		return nil, nil, errors.Wrap(ErrBallotCannotBlind, err)
	}

	// Blind the message
	blindedBytes, unblinder, err := rsablind.Blind(pubcrypt, hashed)
	if err != nil {
		return nil, nil, errors.Wrap(ErrBallotCannotBlind, err)
	}

	return BlindBallot(blindedBytes), unblinder, nil
}

// Unblind unblinds the ballot, adding the unblinded signature to the ballot
func (ballot *Ballot) Unblind(signingKey PublicKey, sig Signature, unblinder []byte) error {
	if ballot.HasSignature() {
		return errors.Wrap(ErrBallotHasSignature, ErrBallotCannotUnblind)
	}

	// Unblind the signature
	unblindedSig, err := sig.Unblind(signingKey, unblinder)
	if err != nil {
		return errors.Wrap(err, ErrBallotCannotUnblind)
	}

	// Confirm that the signature signs the ballot
	s := ballot.StringWithoutSignature()
	err = unblindedSig.VerifyBlindSignature(signingKey, []byte(s))
	if err != nil {
		return errors.Wrap(err, ErrBallotCannotUnblind)
	}

	// Add the signature to the ballot
	ballot.Signature = unblindedSig

	return nil
}

package cryptoballot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/elastos/Elastos.ELA.Utility/crypto"
	"math/big"
)

type DIDPrivateKey []byte

type DIDPublicKey struct {
	crypto.PublicKey
}

//SignString signing string using did private key
func (didPrivateKey DIDPrivateKey) SignString(str string) ([]byte,error){
	signature , err := crypto.Sign(didPrivateKey,[]byte(str))
	if err != nil {
		return []byte{},err
	}
	return signature,nil
}

//VerifyString verify String using did public key
func (didPublicKey DIDPublicKey) VerifySignature(signature []byte,data []byte) error{
	return crypto.Verify(didPublicKey.PublicKey,data,signature)
}

//Bytes get public key in bytes
func (didPublicKey DIDPublicKey) Bytes() []byte {
	pub , err := didPublicKey.EncodePoint(true)
	if err != nil {
		return []byte{}
	}
	return pub
}

//GetPublicKeyFromPrivateKey get did public key from did private key
func (didPrivateKey DIDPrivateKey) GetPublicKeyFromPrivateKey() (DIDPublicKey,error){
	priv := new(ecdsa.PrivateKey)
	c := elliptic.P256()
	priv.PublicKey.Curve = c
	k := new(big.Int)
	k.SetBytes(didPrivateKey)
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	publicKey := new(crypto.PublicKey)
	publicKey.X = new(big.Int).Set(priv.PublicKey.X)
	publicKey.Y = new(big.Int).Set(priv.PublicKey.Y)
	return DIDPublicKey{*publicKey} , nil
}
package cryptoballot

import (
	"crypto"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/cryptoballot/fdh"
	"github.com/cryptoballot/rsablind"
)

var (
	goodPrivateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCjFca3HtjM6T6HQEApX7bDuatpiXiEMKr1uiTbAgOvzQpBa7cy
Y0Xr/cEw4ovwjjVHXfr5uRqY/J+w1p6RVVtxy96hdR25ySj0636Tl+swTxT/+BKi
OOkzEHUL3vxrfkqYZHXg/tYUET3yQsjrtAWU1Cw6ZU0JI8jUKIeQQy7jrQIDAQAB
AoGAKlQSmaDmAHlhg1VH0fVHyJE+Tkwh/Z1sIg9IVZe2QUDksoo0qF1f3pqkM/34
+FzQs09PPtWuc5rOD+YEjhArhXi2nH5QFyS4nYe6hrVHmCDhsZK3sXe6x9az0AgY
GNqFYxD2bdrMp5YeKC1pDtjT958/1WPKJATceQ5FTqsXrwECQQDpSaJ+t1HlWm6q
yBjEbX44ZaGK4lQByK2bUaaEpi9EMk5705SUFvZD4FnHtP5ZKrmpI5vusR5wmbxt
zUkR/vWhAkEAsvZw/00CeJB0XkUlnbpbH2qsh5juHWr+vO6POSovTgR1hK3+vZqh
JY/yyX/sAIr2z8dh/4pufhSLuS/lAAdajQJACS/6M01a71Jpa1ZoC0xYnTX7b7HM
JynVFHnZuf2lfOUSTDQf9NkWp8OtJX1OSwqwtyWM3ZCiJ0MWtahRCWFmIQJBAIOn
4yceK0Qw2TsE2ZB4qVKqcnRq4DnKHc82HS1ryFM32pCaRD6ORCDTDkSIlEEt+jaP
MpwA5hpg2Q2Km4hy4H0CQQDGQEUid5GgYYpE5XNe0ocONeOZHcAyFaWK0OBzvx+U
kA0JPmGuqyj2KciYii0dI4UIUGYNeusaGnZKxoZfGuFo
-----END RSA PRIVATE KEY-----
`)
	badPrivateKey  = []byte("IAMNOTAKEY")
	badPrivateKey2 = []byte("-----BEGIN PRIVATE KEY-----MIIEpAIBAAKCAQE-----END PRIVATE KEY-----")
	badPrivateKey3 = []byte("-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQE-----END RSA PRIVATE KEY-----")
)

func TestGoodPrivateKey(t *testing.T) {

	//priv, err := GeneratePrivateKey(1024)
	//if err != nil {
	//	t.Error(err)
	//	return
	//}
	//println(priv.String())

	priv, err := NewPrivateKey(goodPrivateKey)
	if err != nil {
		t.Error(err)
		return
	}

	pub, err := priv.PublicKey()
	println("pub:"+pub.String())
	if err != nil {
		t.Error(err)
		return
	}

	if priv.IsEmpty() {
		t.Errorf("Valid private key should not be empty")
	}

	if strings.TrimSpace(priv.String()) != strings.TrimSpace(string(goodPrivateKey)) {
		t.Errorf("Private Key does not survive round trip from string and back")
	}

	message := "hello,world"
	sig, err := priv.SignString(message)
	if err != nil {
		t.Error(err)
		return
	}
	println(base64.StdEncoding.EncodeToString(sig))
	//sig , _:= NewSignature([]byte(`l0Zpl7w2uNrFr0Tx9QBr04+h4PJ3nZisVxGnenqo2N4oOftEAGfEiiBUoCSbW/A5sdPOFUl61cINqzRbWYK5ppjyrjjDW7dVWsypbe/LDiIbP7y/yZyDXqKaOC5zGuIfBC0Sq/nJqoAESWIbivRdS5UqA3SCcGM8GakUzG1LZwU=`))

	err = sig.VerifySignature(pub, []byte(message))
	if err != nil {
		t.Error(err)
		return
	}
}
func TestBadPrivateKey(t *testing.T) {
	pk, err := NewPrivateKey(badPrivateKey)
	if err == nil {
		t.Errorf("Invalid private key did not return error")
	}

	if !pk.IsEmpty() {
		t.Errorf("Invalid private key should be empty")
	}

	_, err = NewPrivateKey(badPrivateKey2)
	if err == nil {
		t.Errorf("Invalid private key did not return error")
	}

	_, err = NewPrivateKey(badPrivateKey3)
	if err == nil {
		t.Errorf("Invalid private key did not return error")
	}

	// Try to generate a zero length private key
	_, err = GeneratePrivateKey(0)
	if err == nil {
		t.Errorf("Zero sized private key should generate error")
	}
}

func TestBlindSignature(t *testing.T) {

	// Get the private key
	priv, err := NewPrivateKey(goodPrivateKey)
	if err != nil {
		t.Error(err)
		return
	}

	// Get the public key
	pub, err := priv.PublicKey()
	if err != nil {
		t.Error(err)
		return
	}

	// Get the public cryptoKey
	pubcrypt, err := pub.GetCryptoKey()
	if err != nil {
		t.Error(err)
		return
	}

	// Generate the message
	message := []byte("ATTACK AT DAWN")

	// Full-domain-hash that is half the key size
	hashed := fdh.Sum(crypto.SHA256, 1024, message)

	// Blind the message
	blinded, unblinder, err := rsablind.Blind(pubcrypt, hashed)
	if err != nil {
		t.Error(err)
		return
	}

	// Blind sign the blinded message
	sig, err := priv.BlindSign(blinded)
	if err != nil {
		t.Error(err)
		return
	}

	// Test doing a naive PKCS1v15 signature (which adds left padding to the result)
	_, err = priv.SignRawBytes(hashed)
	if err != nil {
		t.Error(err)
		return
	}

	// Unblind the signature
	unblindedSig, err := sig.Unblind(pub, unblinder)
	if err != nil {
		t.Error(err)
		return
	}

	// Verify the blind signature
	err = unblindedSig.VerifyBlindSignature(pub, message)
	if err != nil {
		t.Error(err)
		return
	}

}

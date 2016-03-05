package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	b64, err := hexToBase64([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	if err != nil {
		t.Fatal(err)
	}
	if b64 != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("Unexpected b64 output %s", b64)
	}
}

func TestFixedXOR(t *testing.T) {
	a := []byte("a")
	b := []byte("ab")
	_, err := fixedXOR(a, b)
	if err == nil {
		t.Fatal("Expected error with differing input lengths")
	}

	input, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		t.Fatal(err)
	}

	key, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}
	xored, err := fixedXOR(input, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(xored) != "the kid don't play" {
		t.Errorf("Unexpected xored string: %s", xored)
	}
}

func TestOneByteXOR(t *testing.T) {
	letterFrequencies, err := letterFrequencies("files/corpus.txt")
	if err != nil {
		t.Fatal(err)
	}

	input, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Fatal(err)
	}
	plainText, _, _, err := decryptXORCipher(input, letterFrequencies)
	if err != nil {
		t.Fatal(err)
	}
	if string(plainText) != "Cooking MC's like a pound of bacon" {
		t.Errorf("Unexpected plaintext: %s", string(plainText))
	}
}

func TestDetectOneByteXOR(t *testing.T) {
	letterFrequencies, err := letterFrequencies("files/corpus.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphers := loadHexCiphers(t, "files/4.txt")
	pt, err := decryptSingleByteXOR(ciphers, letterFrequencies)
	if err != nil {
		t.Error(err)
	}
	if string(pt)[:len(pt)-1] != string("Now that the party is jumping") {
		t.Errorf("Unexpected plaintext : %s", (string(pt)))
	}

}

func TestEncryptRepeatingKeyXOR(t *testing.T) {
	cipher := encryptRepeatingKeyXOR([]byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`), []byte("ICE"))
	if cipher != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		t.Error("Unexpected cipher")
	}
}

func TestDecryptRepeatingKeyXOR(t *testing.T) {
	d, err := hammingDistanceBits([]byte("this is a test"), []byte("wokka wokka!!!"))
	if err != nil {
		t.Fatal(err)
	}
	if d != 37 {
		t.Error("d should be 37")
	}

	cipherBase64, err := ioutil.ReadFile("files/6.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(string(cipherBase64))
	if err != nil {
		t.Fatal(err)
	}

	letterFrequencies, err := letterFrequencies("files/corpus.txt")
	if err != nil {
		t.Fatal(err)
	}

	b, _, err := decryptRepeatingKeyXOR(data, letterFrequencies)
	if err != nil && string(b)[:34] != "I'm back and I'm ringin' the bell" {
		t.Error(err)
	}
}

func TestDecryptAESECB(t *testing.T) {
	cipherBase64, err := ioutil.ReadFile("files/7.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(string(cipherBase64))
	if err != nil {
		t.Fatal(err)
	}

	plainText, err := decryptAESECB(data, []byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plainText)[:32] != "I'm back and I'm ringin' the bel" {
		t.Error("unexpected data: %s", string(data))
	}

	cipher, err := encryptAESECB(plainText, []byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != string(cipher) {
		t.Errorf("aes ecb roundtrip failed")
	}
}

func TestAESECBRoundtripOneblock(t *testing.T) {
	testAESECBRoundtrip(t, []byte("this is a test.."))
}

func TestAESECBRoundtripMulti(t *testing.T) {
	testAESECBRoundtrip(t, bytes.Repeat([]byte("this is a test.."), 4))
}

func TestAESECBRoundtripWithPadding(t *testing.T) {
	testAESECBRoundtrip(t, []byte("i need padding"))
}

func TestAESECBRoundtripMultiWithPadding(t *testing.T) {
	testAESECBRoundtrip(t, bytes.Repeat([]byte("i need padding"), 5))
}

func testAESECBRoundtrip(t *testing.T, input []byte) {
	key := []byte("YELLOW SUBMARINE")
	cipher, err := encryptAESECB(input, key)
	if err != nil {
		t.Fatal(err)
	}

	plainText, err := decryptAESECB(cipher, key)
	if err != nil {
		t.Fatal(err)
	}

	if string(plainText) != string(input) {
		t.Fatalf("aes ecb round trip failed: %s", input)
	}
}

func TestDetectAESECB(t *testing.T) {
	ciphers := loadHexCiphers(t, "files/8.txt")
	_, count := detectECBMode(ciphers)
	if count < 4 {
		t.Error("no repeating block found")
	}
}

func loadHexCiphers(t *testing.T, file string) [][]byte {
	ciphersAsHex, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	ciphers := make([][]byte, 0)
	for _, hexCipher := range bytes.Split([]byte(ciphersAsHex), []byte("\n")) {
		cipher := make([]byte, len(hexCipher)/2)
		_, err := hex.Decode(cipher, hexCipher)
		if err != nil {
			t.Fatal(err)
		}
		ciphers = append(ciphers, cipher)
	}
	return ciphers

}

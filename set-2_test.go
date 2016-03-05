package main

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"
)

func TestPKCS7Padding(t *testing.T) {
	padded := PKCS7Pad([]byte("YELLOW SUBMARINE"), 20)
	if string(padded) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Errorf("expected padding")
	}

	padded = PKCS7Pad([]byte("YELLOW SUBMARINE"), 16)
	if string(padded) != "YELLOW SUBMARINE" {
		t.Errorf("unexpected padding")
	}

}

func TestAESCBCDecrypt(t *testing.T) {
	cipher, err := ioutil.ReadFile("files/10.txt")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err = base64.StdEncoding.DecodeString(string(cipher))
	if err != nil {
		t.Fatal(err)
	}
	plainText, err := decryptAESCBC(cipher, []byte("YELLOW SUBMARINE"), bytes.Repeat([]byte{0}, 16))
	if string(plainText)[:32] != string("I'm back and I'm ringin' the bel") {
		t.Errorf("AES decrypt failed")
	}

}

func TestAESCBCRoundtripOneblock(t *testing.T) {
	testAESCBCRoundtrip(t, []byte("this is a test.."))
}

func TestAESCBCRoundtripMulti(t *testing.T) {
	testAESCBCRoundtrip(t, bytes.Repeat([]byte("this is a test.."), 4))
}

func TestAESCBCRoundtripWithPadding(t *testing.T) {
	testAESCBCRoundtrip(t, []byte("i need padding"))
}

func TestAESCBCRoundtripMultiWithPadding(t *testing.T) {
	testAESCBCRoundtrip(t, bytes.Repeat([]byte("i need padding"), 5))
}

func testAESCBCRoundtrip(t *testing.T, input []byte) {
	iv := bytes.Repeat([]byte{0}, 16)
	key := []byte("YELLOW SUBMARINE")

	cipher, err := encryptAESCBC(input, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	plainText, err := decryptAESCBC(cipher[16:], key, cipher[:16])
	if string(plainText) != string(input) {
		t.Fatalf("aes cbc round trip failed: %s", plainText)
	}
}

func TestEncryptionOracle(t *testing.T) {
	plainText := bytes.Repeat([]byte{'a'}, 16*4)

	encryptionOracle(plainText)
}

func TestDecryptUnknown(t *testing.T) {
	plainText, err := decryptUnknown()
	if err != nil {
		t.Fatal(err)
	}
	if len(plainText) != 139 {
		t.Errorf("short decryption got %d != 139", len(plainText))
	}
	if string(plainText)[:16] != "Rollin' in my 5." {
		t.Errorf("Unexpected plaintext : %s", plainText)
	}
}

func TestForgeAdminProfile(t *testing.T) {
	// make an email of sufficient size to get an encryption
	// of a block that is 'admin' with PKCS7Padding
	// "admin\x11\x11\x11..."
	block1 := strings.Repeat("A", 16-len("email="))
	block2 := PKCS7Pad([]byte("admin"), 16)
	cipher, err := encryptedProfile(block1 + string(block2))
	if err != nil {
		t.Fatal(err)
	}
	roleForgery := cipher[16:32]

	// create a 3 block encryption with a valid middle block:
	// "email=AAAAAAAAAAA", "AAA&uid=10&role="
	email := strings.Repeat("A", 16-len("email=")+3)
	cipher, err = encryptedProfile(email)
	if err != nil {
		t.Fatal(err)
	}
	forgery := append(cipher[:32], roleForgery...)

	d, err := decryptAESECB(forgery, key1)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kvParse(string(d))
	if err != nil {
		t.Fatal(err)
	}
	if admin["role"] != "admin" {
		t.Errorf("failed to create admin role: %s", admin["role"])
	}
}

func TestDecryptUnknownWithPrefixNone(t *testing.T) {
	testDecryptUnknownWithPrefix(t, []byte{})
}

func TestDecryptUnknownWithPrefixOne(t *testing.T) {
	testDecryptUnknownWithPrefix(t, bytes.Repeat([]byte("?"), 1))
}

func TestDecryptUnknownWithPrefix7(t *testing.T) {
	testDecryptUnknownWithPrefix(t, bytes.Repeat([]byte("?"), 7))
}

func TestDecryptUnknownWithPrefixOneBlock(t *testing.T) {
	testDecryptUnknownWithPrefix(t, bytes.Repeat([]byte("?"), 16))
}

func TestDecryptUnknownWithPrefixBiggy(t *testing.T) {
	testDecryptUnknownWithPrefix(t, bytes.Repeat([]byte("?"), 153))
}

func testDecryptUnknownWithPrefix(t *testing.T, prefix []byte) {
	plainText, err := decryptUnknownWithPrefix(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(plainText) != 139 {
		t.Fatalf("short decryption got %d != 139", len(plainText))
	}

	if string(plainText)[:16] != "Rollin' in my 5." {
		t.Errorf("Unexpected plaintext : %s", plainText)
	}
}

func TestPKCS7PadValidate(t *testing.T) {
	if !validatePKCS7Pad([]byte("ICE ICE BABY\x04\x04\x04\x04")) {
		t.Error("pad validation failed")
	}
	if validatePKCS7Pad([]byte("ICE ICE BABY\x05\x05\x05\x05")) {
		t.Errorf("bad pad validated")
	}
	if validatePKCS7Pad([]byte("ICE ICE BABY\x01\x02\x03\x04")) {
		t.Errorf("bad pad validated")
	}
}

func TestCBCBitFlip(t *testing.T) {
	input := []byte("yellow submarine")
	key := keyGen()
	cipher, err := encryptCommentsWithUserData(input, key)
	if err != nil {
		t.Fatal(err)
	}

	// Bit flip block n to influence block n+1
	fakeBlock, _ := fixedXOR(cipher[32:48], input)
	fakeBlock, _ = fixedXOR(fakeBlock, []byte("a=bcd;jdmin=true"))

	forgery := make([]byte, 0)
	forgery = append(forgery, cipher[:32]...) // IV + block 1
	forgery = append(forgery, fakeBlock...)   // fake block
	forgery = append(forgery, cipher[48:]...) // rest

	isAdmin := isAdmin(forgery, key)
	if !isAdmin {
		t.Errorf("decrpytion should be admin")
	}

}

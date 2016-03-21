package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}
func PKCS7Pad(data []byte, blockLen int) []byte {
	required := blockLen - len(data)
	padding := bytes.Repeat([]byte{byte(required)}, required)
	return append(data, padding...)
}

func decryptAESCBC(input, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	bs := aes.BlockSize
	prev := iv
	out := make([]byte, 0, len(input))

	for len(input) > 0 {
		temp := make([]byte, bs)
		block.Decrypt(temp, input[:bs])
		decrypted, err := fixedXOR(temp, prev)
		if err != nil {
			return []byte{}, err
		}
		out = append(out, decrypted...)
		prev = input[:bs]
		input = input[bs:]
	}

	padLen := int(out[len(out)-1])
	if padLen > bs {
		return []byte{}, nil
	}

	out = out[:len(out)-padLen]

	return out, nil
}

func encryptAESCBC(input, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	bs := aes.BlockSize
	prev := iv
	out := iv // place iv at start of output

	if len(input)%16 == 0 {
		input = append(input, PKCS7Pad(make([]byte, 0, bs), bs)...)
	}
	for len(input) > 0 {
		if len(input) < bs {
			input = PKCS7Pad(input, bs)
		}

		xored, err := fixedXOR(prev, input[:bs])
		if err != nil {
			return []byte{}, err
		}
		temp := make([]byte, bs)
		block.Encrypt(temp, xored)
		out = append(out, temp...)
		prev = temp
		input = input[bs:]
	}

	return out, nil
}

func keyGen() []byte {
	key := make([]byte, 16)
	r, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	if r != 16 {
		panic(fmt.Sprintf("keygen short read: %d", r))
	}

	return key
}

func encryptionOracle(input []byte) ([]byte, int, error) {
	pad := make([]byte, 5+rand.Int()%5)
	_, err := rand.Read(pad)
	if err != nil {
		return []byte{}, 0, err
	}
	input = append(pad, input...)
	input = append(input, pad...)
	key := keyGen()
	var cipher []byte
	if rand.Int()%2 == 0 {
		iv := keyGen()
		cipher, err = encryptAESCBC(input, key, iv)
		if err != nil {
			return []byte{}, 0, err
		}
		cipher = cipher[16:]
	} else {
		cipher, err = encryptAESECB(input, key)
	}
	_, repeats := detectECBMode([][]byte{cipher})
	if repeats > 1 {
		return cipher, ECB, nil
	}
	return cipher, CBC, nil
}

const (
	ECB = 1 << iota
	CBC
)

func ECBEncryptWithUnknown(key, input []byte) ([]byte, error) {
	unknown, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		return []byte{}, err
	}
	toEncrypt := append(input, unknown...)
	return encryptAESECB(toEncrypt, key)
}

func decryptUnknown(key []byte) ([]byte, error) {
	cipher, err := ECBEncryptWithUnknown(key, []byte{})
	if err != nil {
		return []byte{}, err
	}
	cipherLen := len(cipher)
	var blockSize int

	// Addition of dummy padding block in ECB mode gives away block size
	for i := 1; i < 32; i++ {
		in := bytes.Repeat([]byte{'A'}, i)
		cipher, err := ECBEncryptWithUnknown(key, in)
		if err != nil {
			return []byte{}, err
		}

		if len(cipher) != cipherLen {
			blockSize = len(cipher) - cipherLen
			break
		}
	}
	if blockSize != 16 {
		panic(fmt.Sprintf("expected blocksize=16, got=%d", blockSize))
	}

	repeating := 3
	in := bytes.Repeat([]byte{0}, repeating*blockSize)
	cipher, err = ECBEncryptWithUnknown(key, in)
	if err != nil {
		return []byte{}, err
	}

	_, repeats := detectECBMode([][]byte{cipher})
	if repeats != repeating {
		return []byte{}, fmt.Errorf("cannot decrypt non-ECB cipher")
	}

	plainText := []byte{}
	for blockNum := 0; blockNum < cipherLen/blockSize; blockNum++ {
		for i := 1; i < blockSize+1; i++ {
			shortBlock := bytes.Repeat([]byte{'A'}, blockSize-i)
			cipher, err = ECBEncryptWithUnknown(key, shortBlock)
			if err != nil {
				return []byte{}, err
			}

			for b := 0; b < 128; b++ {
				testInput := append(shortBlock, plainText...)
				testInput = append(testInput, byte(b))
				testEncrypted, err := ECBEncryptWithUnknown(key, testInput)
				if err != nil {
					return []byte{}, err
				}

				cmpFrom := blockSize * blockNum
				cmpTo := cmpFrom + blockSize
				if string(testEncrypted)[cmpFrom:cmpTo] == string(cipher)[cmpFrom:cmpTo] {
					plainText = append(plainText, testInput[cmpTo-1])
					break
				}
			}
		}
	}
	return plainText, nil
}

func kvParse(in string) (map[string]string, error) {
	obj := make(map[string]string)
	tokens := strings.Split(in, "&")
	for _, t := range tokens {
		kv := strings.Split(t, "=")
		if len(kv) != 2 {
			return obj, fmt.Errorf("error parsing", kv)
		}
		obj[kv[0]] = kv[1]
	}
	return obj, nil
}

func profileFor(email string) map[string]interface{} {
	email = strings.Replace(email, "&", "*", -1)
	email = strings.Replace(email, "=", "*", -1)
	return map[string]interface{}{
		"email": email,
		"uid":   10,
		"role":  "user",
	}
}

func encodeProfile(p map[string]interface{}) []byte {
	email := []byte("email=" + p["email"].(string))
	rem := []byte(fmt.Sprintf("&uid=%d&role=%s", p["uid"], p["role"]))
	return append(email, rem...)
}

func encryptedProfile(key []byte, email string) ([]byte, error) {
	encoded := encodeProfile(profileFor(email))
	cipher, err := encryptAESECB(encoded, key)
	if err != nil {
		return []byte{}, err
	}
	return cipher, nil
}

// todo: pass keys in
func ECBEncryptWithUnknownAndPrefix(key, prefix, input []byte) ([]byte, error) {
	unknown, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		return []byte{}, err
	}

	input = append(prefix, input...)
	toEncrypt := append(input, unknown...)
	return encryptAESECB(toEncrypt, key)
}

func decryptUnknownWithPrefix(key, prefix []byte) ([]byte, error) {
	blockSize := 16
	testBlock := bytes.Repeat([]byte{'A'}, blockSize)
	testBlockEnc, err := encryptAESECB(testBlock, key)
	if err != nil {
		return []byte{}, err
	}

	var pos int
	var input []byte
	var cipherLen int
	for i := 0; i < 16; i++ {
		input = append(testBlock, bytes.Repeat([]byte{'A'}, i)...)

		// Keep adding to the dummy block until its encryption is found in
		// the cipher.  This gives away the length
		cipher, err := ECBEncryptWithUnknownAndPrefix(key, prefix, input)
		if err != nil {
			return []byte{}, err
		}
		pos = 0
		for len(cipher) > 0 {
			if string(cipher[:blockSize]) == string(testBlockEnc[:blockSize]) {
				cipherLen = len(cipher)
				goto done
			}
			pos += blockSize
			cipher = cipher[blockSize:]
		}
	}

	return []byte{}, fmt.Errorf("unable to establish prefix text length")

done:
	plainText := []byte{}
	for blockNum := 0; blockNum < (cipherLen/blockSize)-1; blockNum++ {
		for i := 1; i < blockSize+1; i++ {
			shortBlock := input[:len(input)-i]
			cipher, err := ECBEncryptWithUnknownAndPrefix(key, prefix, shortBlock)
			if err != nil {
				return []byte{}, err
			}

			for b := 0; b < 128; b++ {
				testInput := append(shortBlock, plainText...)
				testInput = append(testInput, byte(b))
				testEncrypted, err := ECBEncryptWithUnknownAndPrefix(key, prefix, testInput)
				if err != nil {
					return []byte{}, err
				}
				cmpFrom := pos + (blockSize * blockNum)
				cmpTo := cmpFrom + blockSize
				if string(testEncrypted)[cmpFrom:cmpTo] == string(cipher)[cmpFrom:cmpTo] {
					plainText = append(plainText, testInput[len(testInput)-1])
					break
				}
			}
		}
	}

	return plainText, nil
}

func validatePKCS7Pad(input []byte) bool {
	if len(input) == 0 {
		return false
	}
	padLen := input[len(input)-1]
	if int(padLen) > len(input) {
		return false
	}
	return string(bytes.Repeat([]byte{padLen}, int(padLen))) ==
		string(input[len(input)-int(padLen):])
}

func encryptCommentsWithUserData(input, key []byte) ([]byte, error) {
	iv := keyGen()
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	postfix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	toEncrypt := append(append(prefix, []byte(url.QueryEscape(string(input)))...), postfix...)
	//	printBlocks("to encrypt", toEncrypt)
	cipher, err := encryptAESCBC(toEncrypt, key, iv)
	if err != nil {
		return []byte{}, err
	}
	return cipher, err
}

func isAdmin(input, key []byte) bool {
	plainText, err := decryptAESCBC(input[16:], key, input[:16])
	if err != nil {
		return false
	}

	//	printBlocks("decrypted", plainText)
	return strings.Contains(string(plainText), "admin=true")
}

func printBlocks(comment string, input []byte) {
	fmt.Print(comment, " ")
	for len(input) > 16 {
		fmt.Print("[", fmt.Sprintf("%q", input[:16]), "]  ")
		input = input[16:]
	}
	pad := strings.Repeat(" ", 16-len(input))
	fmt.Print("[", fmt.Sprintf("%q", input), pad, "]")
	fmt.Println("")
}

func CBCBitFlip(key, input []byte) ([]byte, error) {
	cipher, err := encryptCommentsWithUserData(input, key)
	if err != nil {
		return []byte{}, err
	}

	// fakeBlock has the xor of the cipher block which will be xored
	// with it during the CBC decryption.  This essentially zeroes it..
	fakeBlock, err := fixedXOR(cipher[32:48], input)
	if err != nil {
		return []byte{}, err
	}
	// ... meaning whatever is xored in will appear in the decrypted plaintext
	fakeBlock, err = fixedXOR(fakeBlock, []byte("a=bcd;admin=true"))
	if err != nil {
		return []byte{}, err
	}

	forgery := make([]byte, 0)
	forgery = append(forgery, cipher[:32]...) // IV + block 1
	forgery = append(forgery, fakeBlock...)   // fake block
	forgery = append(forgery, cipher[48:]...) // rest
	return forgery, nil
}

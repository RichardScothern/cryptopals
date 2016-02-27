package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func main() {
	// 1. Hex to Base64
	b64, err := hexToBase64([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	if err != nil {
		panic(err)
	}
	if b64 != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		panic(b64)
	}

	// 2. Fixed XOR
	input, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		panic(err)
	}

	key, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		panic(err)
	}
	xored, err := fixedXOR(input, key)
	if err != nil {
		panic(err)
	}
	if string(xored) != "the kid don't play" {
		panic(string(xored))
	}

	// 3. Decrypt single char XOR
	letterFrequencies, err := letterFrequencies("files/corpus.txt")
	if err != nil {
		panic(err)
	}

	input, err = hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		panic(err)
	}
	plainText, _, _, err := decryptXORCipher(input, letterFrequencies)
	if err != nil {
		panic(err)
	}
	if string(plainText) != "Cooking MC's like a pound of bacon" {
		panic(string(plainText))
	}

	// 4. Decrypt single byte XOR
	ciphersAsHex, err := ioutil.ReadFile("files/4.txt")
	if err != nil {
		panic(err)
	}

	ciphers := make([][]byte, 0)
	for _, hexCipher := range bytes.Split([]byte(ciphersAsHex), []byte("\n")) {
		cipher := make([]byte, len(hexCipher)/2)
		_, err := hex.Decode(cipher, hexCipher)
		if err != nil {
			panic(err)
		}
		ciphers = append(ciphers, cipher)
	}

	pt, err := decryptSingleByteXOR(ciphers, letterFrequencies)
	if err != nil {
		panic(err)
	}
	if string(pt)[:len(pt)-1] != string("Now that the party is jumping") {
		panic(string(pt))
	}

	// 5. repeating key XOR
	cipher := encryptRepeatingKeyXOR([]byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`), []byte("ICE"))
	if cipher != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		panic(cipher)
	}

	// 6. Decrypt repeating XOR
	d, err := hammingDistanceBits([]byte("this is a test"), []byte("wokka wokka!!!"))
	if err != nil {
		panic(err)
	}
	if d != 37 {
		panic("d should be 37")
	}

	cipherBase64, err := ioutil.ReadFile("files/6.txt")
	if err != nil {
		panic(err)
	}
	data, err := base64.StdEncoding.DecodeString(string(cipherBase64))
	if err != nil {
		panic(err)
	}

	b, _, err := decryptRepeatingKeyXOR(data, letterFrequencies)
	if err != nil && string(b)[:34] != "I'm back and I'm ringin' the bell" {
		panic(err)
	}

	// 7. Decrypt AES-ECB mode with key
	cipherBase64, err = ioutil.ReadFile("files/7.txt")
	if err != nil {
		panic(err)
	}
	data, err = base64.StdEncoding.DecodeString(string(cipherBase64))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	err = decryptAES128ECB(data, []byte("YELLOW SUBMARINE"))
	if err != nil {
		panic(err)
	}

	// 8. Detect AES-ECB mode
	ciphersAsHex, err = ioutil.ReadFile("files/8.txt")
	if err != nil {
		panic(err)
	}

	ciphers = make([][]byte, 0)
	for _, hexCipher := range bytes.Split([]byte(ciphersAsHex), []byte("\n")) {
		cipher := make([]byte, len(hexCipher)/2)
		_, err := hex.Decode(cipher, hexCipher)
		if err != nil {
			panic(err)
		}
		ciphers = append(ciphers, cipher)
	}

	_, count := detectECBMode(ciphers)
	if count < 4 {
		panic("no repeating block found")
	}

}

func detectECBMode(input [][]byte) ([]byte, int) {
	var ecbCipher []byte
	highestBlockCount := 0
	blockSize := 16
	for _, cipher := range input {
		seen := make(map[string]int, 0)
		for len(cipher) > blockSize {
			seen[string(cipher[:blockSize])]++
			cipher = cipher[blockSize:]
		}
		repeatingBlockCount := 0
		for _, v := range seen {
			if v > repeatingBlockCount {
				repeatingBlockCount = v
			}
		}
		if repeatingBlockCount > highestBlockCount {
			highestBlockCount = repeatingBlockCount
			ecbCipher = cipher
		}
	}
	return ecbCipher, highestBlockCount

}

func decryptAES128ECB(input, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	for len(input) > block.BlockSize() {
		block.Decrypt(input[:aes.BlockSize], input[:aes.BlockSize])
		input = input[aes.BlockSize:]
	}

	return nil
}

func decryptRepeatingKeyXOR(input []byte, letterFrequencies map[byte]int) ([]byte, []byte, error) {
	var hammingScoreNormalized float32 = float32(len(input) * 8)
	var ks int
	scores := []string{}

	for keySize := 2; keySize < 40; keySize++ {
		first := input[0:keySize]
		second := input[keySize : keySize*2]

		if len(first) != keySize || len(second) != keySize {
			panic(fmt.Sprintf("Bad block len size.  Expected %d, got %d, %d", keySize, len(first), len(second)))
		}

		d, err := hammingDistanceBits(first, second)
		if err != nil {
			return []byte{}, []byte{}, err
		}

		normalized1 := float32(d) / float32(keySize)

		scores = append(scores, fmt.Sprintf("%f ks=%d averaged", normalized1, keySize))

		if normalized1 < hammingScoreNormalized {
			hammingScoreNormalized = normalized1
			ks = keySize
		}
	}
	// sort.Strings(scores)
	// for _, s := range scores {
	// 	fmt.Println(s)
	// }

	bestKey := make([]byte, 0)
	bestPlainText := make([]byte, 0)
	bestScore := 0
	for ks = 2; ks < 40; ks++ {
		keyBlock := make([]byte, 0)
		for start := 0; start < ks; start++ {
			block := make([]byte, 0)
			for j := start; j+ks < len(input); j += ks {
				block = append(block, input[j])
			}

			_, _, key, err := decryptXORCipher(block, letterFrequencies)
			if err != nil {
				return []byte{}, []byte{}, err

			}
			keyBlock = append(keyBlock, key)
		}

		key := bytes.Repeat(keyBlock, 1+len(input)/ks)
		xored, err := fixedXOR(input, key[:len(input)])
		if err != nil {
			return []byte{}, []byte{}, err
		}
		thisScore := score(letterFrequencies, xored)
		if thisScore > bestScore {
			bestScore = thisScore
			bestPlainText = xored
			bestKey = keyBlock
		}
	}
	return bestPlainText, bestKey, nil
}

func decryptSingleByteXOR(ciphers [][]byte, letterFrequencies map[byte]int) ([]byte, error) {
	bestScore := 0
	var plainText []byte

	for _, candidate := range ciphers {
		decrypted, score, _, err := decryptXORCipher(candidate, letterFrequencies)
		if err != nil {
			return []byte{}, err
		}

		if score > bestScore {
			plainText = decrypted
			bestScore = score
		}
	}

	return plainText, nil
}

func encryptRepeatingKeyXOR(input, key []byte) string {
	out := make([]byte, 0)
	var ki int
	for _, c := range input {
		if ki == len(key) {
			ki = 0
		}
		out = append(out, c^key[ki])
		ki++
	}
	return hex.EncodeToString(out)
}

func hexToBase64(input []byte) (string, error) {
	decodedHex := make([]byte, len(input)/2)
	_, err := hex.Decode(decodedHex, input)
	if err != nil {
		return "", err
	}

	expectedLen := base64.StdEncoding.EncodedLen(len(decodedHex))
	return base64.StdEncoding.EncodeToString(decodedHex)[:expectedLen], nil
}

func fixedXOR(input, key []byte) ([]byte, error) {
	if len(input) != len(key) {
		return []byte{}, fmt.Errorf("fixedxor: mismatched input lengths")
	}

	out := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		out[i] = input[i] ^ key[i]
	}

	return out, nil
}

type nothing struct{}
type set map[string]nothing

func (s set) add(w string) {
	s[strings.ToLower(w)] = nothing{}
}

func (s set) has(w string) bool {
	_, ok := s[strings.ToLower(w)]
	return ok
}

func dictionary(dictionaryFile string) (set, error) {
	all, err := ioutil.ReadFile(dictionaryFile)
	if err != nil {
		return set{}, err
	}
	s := set{}
	for _, w := range strings.Split(string(all), "\n") {
		s.add(w)
	}
	return s, nil
}

func letterFrequencies(corpusFile string) (map[byte]int, error) {
	file, err := os.Open(corpusFile)
	if err != nil {
		return map[byte]int{}, err
	}
	defer file.Close()

	frequencies := make(map[byte]int)
	buf := make([]byte, 32*1024)

	for {
		_, err = file.Read(buf)
		if err == nil {
			for _, b := range buf {
				frequencies[b]++
			}
		} else if err == io.EOF {
			break
		} else {
			return frequencies, err
		}
	}

	leastFrequent := 1 << 32
	for _, v := range frequencies {
		if v < leastFrequent {
			leastFrequent = v
		}
	}

	for k, v := range frequencies {
		frequencies[k] = v / leastFrequent
	}

	return frequencies, nil
}

func decryptXORCipher(cipher []byte, letterFrequencies map[byte]int) ([]byte, int, byte, error) {
	bestScore := 0
	plainText := []byte{}
	var key byte
	for b := ' '; b < 'z'; b++ {
		candidateKey := bytes.Repeat([]byte{byte(b)}, len(cipher))
		candidate, err := fixedXOR(cipher, candidateKey)
		if err != nil {
			return []byte{}, 0, '0', err
		}

		s := score(letterFrequencies, candidate)
		if s > bestScore {
			bestScore = s
			plainText = candidate
			key = byte(b)
		}

	}
	normalized := bestScore / len(cipher)
	return plainText, normalized, key, nil
}

func score(corpus map[byte]int, candidate []byte) int {
	score := 0
	for _, char := range candidate {
		if char < 32 || char > 126 {

		} else {
			score += corpus[char]
		}
	}

	return score
}

func score2(candidate []byte) int {
	els := "etaonrishd .,\nlfcmugypwbvkjxqz" //-_!?'\"/1234567890*"
	score := 0
	for _, c := range candidate {
		pos := strings.Index(els, strings.ToLower(string(c)))
		if pos == -1 {
			// Not ascii
			score += 256
		} else if strings.ToUpper(string(c)) == string(c) {
			// Uppercase less common
			score += 1 + (pos * 2)

		} else {
			score += pos
		}
	}
	return score / len(candidate)
}

func hammingDistanceBits(s1, s2 []byte) (int, error) {
	if len(s1) != len(s2) {
		return 0, fmt.Errorf("mismatching input lengths: %d != %d", len(s1), len(s2))
	}
	toBin := func(s []byte) string {
		var asBin string
		for _, c := range s {
			next := strconv.FormatInt(int64(c), 2)
			for len(next) < 8 {
				next = "0" + next
			}
			asBin += next
		}
		return asBin
	}
	distance := 0
	s1bin := toBin(s1)
	s2bin := toBin(s2)
	for i := 0; i < len(s1bin); i++ {
		if s1bin[i] != s2bin[i] {
			distance++
		}
	}
	return distance, nil
}

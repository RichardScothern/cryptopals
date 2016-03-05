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

func encryptAESECB(input, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	bs := block.BlockSize()

	if len(input)%bs == 0 {
		input = append(input, PKCS7Pad([]byte{}, bs)...)
	}
	out := make([]byte, 0, len(input))
	for len(input) > 0 {
		if len(input) < bs {
			input = PKCS7Pad(input, bs)
		}
		temp := make([]byte, bs)
		block.Encrypt(temp, input[:bs])
		input = input[bs:]
		out = append(out, temp...)
	}

	return out, nil

}

func decryptAESECB(input, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	bs := block.BlockSize()
	out := make([]byte, 0)
	for len(input) > 0 {
		temp := make([]byte, bs)
		block.Decrypt(temp, input[:bs])
		input = input[bs:]
		out = append(out, temp...)
	}

	padLen := int(out[len(out)-1])
	out = out[:len(out)-padLen]
	return out, nil
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

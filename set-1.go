package main

import "fmt"

func main() {
	fmt.Println(itoa(1234, 16)) // 4D2
	fmt.Println(itoa(123, 16))  // 7B
	fmt.Println(itoa(8, 16))    // 0B
	fmt.Println(itoa(738291, 16)) // B43F3
	
	fmt.Println(atoi("123", 10))
}


var alphas = map[int]string {
	16 : "0123456789ABCDEF",
	64 : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
}

// 123, 10
func atoi(s string, base int) int {
	res := 0
	m := 10
	for i := 0; i<len(s); i++ {
		c := int(s[i] - '0')
		res = (res * m ) +c
	}
	return res
}

func itoa(num, base int) string {
	var out []byte
	doitoa(num, base, &out)
	return string(out)
}

func doitoa(num, base int, out *[]byte) {	
	d := num / base
	r := num % base
	if d > base {
		doitoa(d, base, out)			
	} else { 
		*out = append(*out, alphas[base][d])
	}
	*out = append(*out, alphas[base][r])
}

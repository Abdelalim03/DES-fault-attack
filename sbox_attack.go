package main

import (
	"fmt"
	"log"
	"strconv"
)

func GetR16L16(cipher []byte) (string, string) {
	if len(cipher) != 8 {
		log.Fatal("GetR16L16 requires 8 bytes input")
	}
	bin := zfill(bytesToBin(cipher), 64)
	fmt.Printf("Cipher in binary: %s\n", bin)
	ipInv := InitialPermutation(bin)
	return ipInv[:32], ipInv[32:]
}

// Calculate output of an S-box given 6-bit input
func calculateS(sbox [][]int, input string) string {
	row, _ := strconv.ParseInt(string(input[0])+string(input[5]), 2, 64)
	col, _ := strconv.ParseInt(input[1:5], 2, 64)
	val := sbox[row][col]
	return fmt.Sprintf("%04b", val)
}

// Perform exhaustive search for a given S-box with expected differential output
func ExhaustiveAttackSBox(sbox [][]int, R15, R15Fault, expected string) []string {
	results := []string{}
	for key := 0; key < 64; key++ {
		keyBits := fmt.Sprintf("%06b", key)
		out1 := calculateS(sbox, Xor(R15, keyBits))
		out2 := calculateS(sbox, Xor(R15Fault, keyBits))
		if Xor(out1, out2) == expected {
			results = append(results, keyBits)
		}
	}
	return results
}

// Intersect multiple slices of strings
func Intersect(lists [][]string) []string {
	if len(lists) == 0 {
		return []string{}
	}
	resultMap := make(map[string]int)
	for _, item := range lists[0] {
		resultMap[item] = 1
	}

	for i := 1; i < len(lists); i++ {
		tempMap := make(map[string]int)
		for _, item := range lists[i] {
			if _, exists := resultMap[item]; exists {
				tempMap[item] = 1
			}
		}
		resultMap = tempMap
	}

	result := []string{}
	for k := range resultMap {
		result = append(result, k)
	}
	return result
}

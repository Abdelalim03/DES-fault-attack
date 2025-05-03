package main

import (
	"encoding/hex"
	"log"
)

func decodeHexStr(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("Erreur lors du décodage hexadécimal : %v", err)
	}
	return b
}

var Plaintext = decodeHexStr("546E2CF42ACEAB94")

var CipherCorrect = decodeHexStr("1E755AA550C14FFF")

var CipherFaulty = [][]byte{
	decodeHexStr("1F254AE5428147FF"),
	decodeHexStr("0E751A8554E14EBF"),
	decodeHexStr("1E6458E1D1C04BEB"),
	decodeHexStr("1F055EA350C14EBF"),
	decodeHexStr("1C7052A110D44FEB"),
	decodeHexStr("5E554AA550C14FF7"),
	decodeHexStr("8A755AA551C18BEB"),
	decodeHexStr("1E704AA150C84F7A"),
	decodeHexStr("1F345AA5D1C149EB"),
	decodeHexStr("5E754AAD509D4FFE"),
	decodeHexStr("1A759AB570C11FBF"),
	decodeHexStr("1E7D5A3411D10FEB"),
	decodeHexStr("8A6558E151C00BFF"),
	decodeHexStr("1E7D5EA400C54FFD"),
	decodeHexStr("6A754AA554817FFE"),
	decodeHexStr("0A351AB540C30FDF"),
	decodeHexStr("1A751AA570C1DFAB"),
	decodeHexStr("1F655AA340C34FFF"),
	decodeHexStr("5E757AA51C955EFF"),
	decodeHexStr("0A775AC154C14EBF"),
	decodeHexStr("7E75CAB554811FFE"),
	decodeHexStr("1E725AE550C04F7B"),
	decodeHexStr("16354AA5009147FF"),
	decodeHexStr("5E744AA554415FE7"),
	decodeHexStr("4A755AA518956FFF"),
	decodeHexStr("1E705A3551410FEB"),
	decodeHexStr("1F2552E502D54FFF"),
	decodeHexStr("5EF54ABD51D50BFF"),
	decodeHexStr("16357AA504D15EFF"),
	decodeHexStr("0AF51AA551C10FDF"),
	decodeHexStr("1D305AA150C04DEB"),
	decodeHexStr("1A751FA500F54FFD"),
}

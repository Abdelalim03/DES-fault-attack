package main

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
)

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Reset  = "\033[0m"
)

func Recover_K16(cipherCorrect []byte, cipherFaults [][]byte, Sboxes map[string][][]int) string {
	possibleKeysPart := map[string][][]string{
		"S1": {}, "S2": {}, "S3": {}, "S4": {},
		"S5": {}, "S6": {}, "S7": {}, "S8": {},
	}
	R16, L16 := GetR16L16(cipherCorrect)
	R15 := L16

	fmt.Printf(Cyan+"➤ Analyse du chiffré correct : %X\n"+Reset, cipherCorrect)
	fmt.Printf("⤷ R16 : %s\n⤷ L16 : %s\n", R16, L16)

	R15Expanded := Expand(R15)

	for k, faulted := range cipherFaults {
		fmt.Printf("\n%s=== Faille %d détectée sur un chiffré fauté ===%s\n", Yellow, k+1, Reset)

		R16Err, L16Err := GetR16L16(faulted)
		R15Err := L16Err
		R15ErrExpanded := Expand(R15Err)

		deltaR16 := Xor(R16, R16Err)
		revPResult := RevPerm(deltaR16)

		equations := []string{}
		for i := 0; i < 32; i += 4 {
			equations = append(equations, revPResult[i:i+4])
		}

		fmt.Println("Équations différentielles extraites :")
		for i, eq := range equations {
			fmt.Printf("⤷ S%d : %s\n", i+1, eq)
		}

		for i := 0; i < 8; i++ {
			if equations[i] == "0000" {
				continue
			}
			sboxName := fmt.Sprintf("S%d", i+1)
			input := R15Expanded[i*6 : (i+1)*6]
			inputFault := R15ErrExpanded[i*6 : (i+1)*6]
			result := ExhaustiveAttackSBox(Sboxes[sboxName], input, inputFault, equations[i])
			if len(result) > 0 {
				possibleKeysPart[sboxName] = append(possibleKeysPart[sboxName], result)
			}
		}
		fmt.Println("────────────────────────────────────────────────────────────────────────────")
	}

	finalParts := []string{}
	fmt.Printf("\n%sParties valides par S-box (après intersection) :%s\n", Cyan, Reset)
	for i := 1; i <= 8; i++ {
		name := fmt.Sprintf("S%d", i)
		intersected := Intersect(possibleKeysPart[name])
		possibleKeysPart[name] = [][]string{intersected}
		fmt.Printf("⤷ %s : %v\n", name, intersected)
		if len(intersected) == 0 {
			log.Fatalf(Red+"Impossible de déduire la sous-clé pour %s"+Reset, name)
		}
		finalParts = append(finalParts, intersected[0])
	}

	K16 := strings.Join(finalParts, "")
	kInt, _ := strconv.ParseUint(K16, 2, 64)
	fmt.Printf(Green+"\n✅ Sous-clé K16 récupérée :\n⤷ Binaire : %s\n⤷ Hexa : %X\n"+Reset, K16, kInt)
	return K16
}

func RecoverMainKey(K16 string) {
	if len(K16) != 48 {
		log.Fatal(Red + "Erreur : K16 doit contenir 48 bits" + Reset)
	}

	missingIndices := getMissingIndices(PC2, 56)
	total := 1 << len(missingIndices)

	fmt.Printf(Yellow + "\n⏳ Tentative de reconstitution de la clé complète...\n" + Reset)
	for i := 0; i < total; i++ {
		baseStr := ReversePC2(K16, missingIndices)
		base := []byte(baseStr)

		binary := fmt.Sprintf("%0*b", len(missingIndices), i)
		for j, idx := range missingIndices {
			base[idx] = binary[j]
		}

		K56 := ReversePC1(string(base))
		K64 := addParityBits(K56)

		keyBytes := []byte{}
		for j := 0; j < len(K64); j += 8 {
			b, err := strconv.ParseUint(K64[j:j+8], 2, 8)
			if err != nil {
				continue
			}
			keyBytes = append(keyBytes, byte(b))
		}

		cipher, err := des.NewCipher(keyBytes)
		if err != nil {
			continue
		}
		out := make([]byte, 8)
		cipher.Encrypt(out, Plaintext)

		if hex.EncodeToString(out) == hex.EncodeToString(CipherCorrect) {
			fmt.Printf(Green+"\n✅ Clé DES complète retrouvée : %X\n"+Reset, keyBytes)
			return
		}
	}
	fmt.Println(Red + "❌ Aucune clé valide trouvée." + Reset)
}

func main() {
	fmt.Println(Cyan + "\n═══════════════════════════════════════════════")
	fmt.Println("    ⇨ Attaque par faute sur le DES ⇦")
	fmt.Println("═══════════════════════════════════════════════" + Reset)

	K16 := Recover_K16(CipherCorrect, CipherFaulty, Sboxes)
	RecoverMainKey(K16)
}

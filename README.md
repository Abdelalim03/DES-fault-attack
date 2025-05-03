# 🔐 Attack-par-fautes-sur-DES

Implémentation d'une attaque par fautes sur le chiffrement **DES** (Differential Fault Analysis, ou DFA) en langage Go.

Ce projet permet de retrouver la **clé secrète complète du DES** à partir d’un chiffré correct et d’une série de chiffrés fautés. L’attaque repose sur l’analyse des différentiels au niveau des S-boxes du 16ᵉ tour, puis sur la reconstruction de la clé complète en inversant les permutations du DES.

---

## 🚀 Exécution

Assurez-vous d’avoir [Go installé](https://golang.org/dl/).  
Dans le dossier du projet, lancez :

```bash
make run
```

ou bien :

```bash
make build
./des_dfa_attack
```

# Makefile pour Attack-par-fautes-sur-DES

APP_NAME = des_dfa_attack

# Lancer l’attaque
run:
	@echo "Lancement de l'attaque par faute sur DES..."
	go run *.go

# Compiler l'application en binaire local
build:
	@echo "Compilation de l'application..."
	go build -o $(APP_NAME) *.go
	@echo "Binaire généré : ./$(APP_NAME)"

# Supprimer le binaire généré
clean:
	@echo "Nettoyage..."
	rm -f $(APP_NAME)

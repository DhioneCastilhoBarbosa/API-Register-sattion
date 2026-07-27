// Comando auxiliar: gera o hash bcrypt de uma senha (cadastro manual via SQL).
// Preferencialmente use POST /auth/register e depois libere o acesso:
//
//	UPDATE panel_users SET enabled = true WHERE email = 'voce@empresa.com';
//
// Uso:
//
//	go run ./cmd/hashpassword "minhaSenhaForte123"
//
// Depois insira no banco:
//
//	INSERT INTO panel_users (email, password_hash, enabled) VALUES ('voce@empresa.com', '<hash gerado>', true);
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "uso: go run ./cmd/hashpassword <senha>")
		os.Exit(1)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro ao gerar hash:", err)
		os.Exit(1)
	}

	fmt.Println(string(hash))
}

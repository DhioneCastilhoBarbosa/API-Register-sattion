package auth

import "errors"

var (
	// ErrUserDisabled indica credenciais corretas, mas acesso ainda não liberado.
	ErrUserDisabled = errors.New("usuário aguardando liberação de acesso")
	// ErrEmailTaken indica que o e-mail já existe em panel_users.
	ErrEmailTaken = errors.New("e-mail já cadastrado")
)

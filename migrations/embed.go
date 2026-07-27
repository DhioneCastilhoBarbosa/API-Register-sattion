package migrations

import "embed"

// FS contém os arquivos .sql versionados (aplicados na subida da API).
//
//go:embed *.sql
var FS embed.FS

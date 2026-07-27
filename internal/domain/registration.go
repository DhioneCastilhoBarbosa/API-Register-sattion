package domain

import "time"

// RegistrationForm é o payload que vem do formulário React — mapeado 1:1
// com os campos das imagens que você mostrou. Latitude/Longitude chegam já
// resolvidas pelo front (ViaCEP + geocoder), o backend só persiste e repassa.
type RegistrationForm struct {
	FirstName         string   `json:"first_name"`
	LastName          string   `json:"last_name"`
	AreaCode          string   `json:"area_code"`
	Phone             string   `json:"phone"`
	Email             string   `json:"email"`
	Address           string   `json:"address"`      // só o nome da rua
	HouseNumber       string   `json:"house_number"` // número do estabelecimento
	AddressComplement string   `json:"address_complement"`
	City              string   `json:"city"`
	State             string   `json:"state"`
	ZipCode           string   `json:"zip_code"`
	Latitude          float64  `json:"latitude"`
	Longitude         float64  `json:"longitude"`
	ChargerModel      string   `json:"charger_model"`
	ChargerNickname   string   `json:"charger_nickname"`
	SerialNumber      string   `json:"serial_number"`
	Visibility        string   `json:"visibility"` // "private" | "public"
	AuthorizedEmails  []string `json:"authorized_emails"`
	// AuthorizedUsers: para visibility=private, informe user_pk (obtido via
	// GET /users/by-cpf/{cpf}). O primeiro com owner=true (ou o primeiro da
	// lista) vira owner no bindUsers da CVE.
	AuthorizedUsers []AuthorizedUser `json:"authorized_users"`
	WantsRFIDTag    bool             `json:"wants_rfid_tag"`
	RFIDCodes       []string         `json:"rfid_codes"`
	Available24h    bool             `json:"available_24h"`
	AvailableFrom   string           `json:"available_from"` // "HH:MM"
	AvailableTo     string           `json:"available_to"`
	// LicenseCode é o código da licença CVE (ex: P3D-..., 12M-...), não a
	// chave de acesso CVE-.... Se vazio, a API tenta achar uma licença
	// disponível pelo e-mail do solicitante.
	LicenseCode    string `json:"license_code"`
	AdditionalInfo string `json:"additional_info"`
}

// AuthorizedUser é quem terá acesso ao chargepoint PRIVATE.
type AuthorizedUser struct {
	UserPk     int    `json:"user_pk"`
	Owner      bool   `json:"owner"`
	BindExists *bool  `json:"bind_exists,omitempty"`
	BindStatus string `json:"bind_status"`
	CPF        string `json:"cpf,omitempty"`
	Email      string `json:"email,omitempty"`
}

type RegistrationStatus string

const (
	StatusPending RegistrationStatus = "pending"
	StatusSuccess RegistrationStatus = "success"
	StatusError   RegistrationStatus = "error"
)

// Registration é o que fica salvo no Postgres — o form original mais o
// resultado da orquestração (chargeBoxPk criado, licença usada, erro se deu
// ruim). É o que permite busca futura e atuação manual.
type Registration struct {
	ID             int
	Form           RegistrationForm
	CVEChargeBoxPk *int
	LicenseCode    *string
	Status         RegistrationStatus
	ErrorMessage   *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

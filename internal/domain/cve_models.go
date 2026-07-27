package domain

// Address espelha o objeto "address" do ChargePointRestForm da API CVE-PRO.
type Address struct {
	Street      string  `json:"street"`
	HouseNumber *string `json:"houseNumber"` // número do estabelecimento (null se vazio)
	Complement  string  `json:"complement,omitempty"`
	City        string  `json:"city"`
	State       string  `json:"state"`
	ZipCode     string  `json:"zipCode"`
	Country     string  `json:"country"`
}

// BindUser é o item de bindUsers no POST /chargepoints (PRIVATE).
type BindUser struct {
	UserPk     int    `json:"user_pk"`
	Owner      bool   `json:"owner"`
	BindExists bool   `json:"bind_exists"`
	BindStatus string `json:"bind_status"`
}

// ChargePointRestForm é o body do POST /api/v1/chargepoints.
// Importante: campos de dinheiro devem ser números (não "0.0" string),
// senão a CVE responde 202 sem persistir o chargepoint.
type ChargePointRestForm struct {
	Active                    bool       `json:"active"`
	ChargeBoxID               string     `json:"chargeBoxId"`
	EndpointAddress           string     `json:"endpointAddress"`
	Description               string     `json:"description"`
	Address                   Address    `json:"address"`
	LocationLatitude          float64    `json:"locationLatitude"`
	LocationLongitude         float64    `json:"locationLongitude"`
	ShowLocation              bool       `json:"showLocation"`
	TypeOf                    string     `json:"typeOf"` // "PRIVATE" | "PUBLIC"
	IsOpen24Hours             bool       `json:"isOpen_24Hours"`
	OpenTime                  *string    `json:"openTime"`
	CloseTime                 *string    `json:"closeTime"`
	// schedule_type e auto_stop_on_close usam snake_case no form da CVE
	// (scheduleType no response é só leitura). Sem schedule_type="CUSTOM",
	// a CVE mantém "24H" mesmo com isOpen_24Hours=false.
	ScheduleType              string     `json:"schedule_type,omitempty"`
	AutoStopOnClose           bool       `json:"auto_stop_on_close"`
	MoneyPerKilowattCost      float64    `json:"moneyPerKilowattCost"`
	MoneyPerDurationCost      float64    `json:"moneyPerDurationCost"`
	MoneyPerTransactionCost   float64    `json:"moneyPerTransactionCost"`
	MoneyPerKilowattIncome    float64    `json:"moneyPerKilowattIncome"`
	MoneyPerDurationIncome    float64    `json:"moneyPerDurationIncome"`
	MoneyPerTransactionIncome float64    `json:"moneyPerTransactionIncome"`
	IsHubjectCompatible       bool       `json:"isHubjectCompatible"`
	HasSocPercentage          bool       `json:"hasSocPercentage"`
	LicenseCode               string     `json:"licenseCode"`
	PaymentChargeTypeCost     string     `json:"paymentChargeTypeCost"`
	PaymentChargeTypeIncome   string     `json:"paymentChargeTypeIncome"`
	PaymentChargeByIncome     string     `json:"paymentChargeByIncome"`
	TaxIncome                 float64    `json:"taxIncome"`
	Reservation               bool       `json:"reservation"`
	Photos                    []string   `json:"photos"`
	IsTenantDeviceReader      bool       `json:"isTenantDeviceReader"`
	TenantPk                  int        `json:"tenant_pk"`
	BindUsers                 []BindUser `json:"bindUsers,omitempty"`
}

// ChargePointListItem é um item de "chargePointList" na resposta de
// GET /api/v1/chargepoints — só os campos que usamos.
type ChargePointListItem struct {
	ChargeBoxID string `json:"chargeBoxId"`
	ChargeBoxPk int    `json:"chargeBoxPk"`
}

type ChargePointListRestResponse struct {
	ChargePointList []ChargePointListItem `json:"chargePointList"`
	Count           int                   `json:"count"`
	Error           string                `json:"error,omitempty"`
}

// OcppTagForm é o body do POST /api/v1/ocpptags para cadastrar uma TagRFID.
type OcppTagForm struct {
	IDTag       string `json:"id_tag"`
	Type        string `json:"type"` // ex: "CARD"
	TenantPk    int    `json:"tenant_pk"`
	OwnerUserPk int    `json:"owner_user_pk,omitempty"`
	Note        string `json:"note,omitempty"`
	Inactive    bool   `json:"inactive,omitempty"`
}

// CVELoginRequest/CVELoginResponse: POST /api/v1/login.
type CVELoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CVELoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
	Error     string `json:"error,omitempty"`
}

// UserVerify: body do POST /api/v1/users/exist_email.
type UserVerify struct {
	Email string `json:"email"`
}

type ExistResponse struct {
	Value bool   `json:"value"`
	Error string `json:"error,omitempty"`
}

// UserOverview é um item de "userList" na resposta de GET /api/v1/users_data.
type UserOverview struct {
	UserPk    int    `json:"userPk"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	Phone     string `json:"phone,omitempty"`
	DocType   string `json:"docType,omitempty"`
	DocNumber string `json:"docNumber,omitempty"`
	Tenant    string `json:"tenant,omitempty"`
	OcppIdTag string `json:"ocppIdTag,omitempty"`
	Error     string `json:"error,omitempty"`
}

type UserListRestResponse struct {
	UserList []UserOverview `json:"userList"`
	Error    string         `json:"error,omitempty"`
}

// UserPrivateStation espelha userPrivateStation de
// GET /api/v1/users_data/tenant_parent/cpf/{cpf}.
type UserPrivateStation struct {
	Email         string  `json:"email"`
	Phone         string  `json:"phone"`
	Owner         *bool   `json:"owner"`
	UserPk        int     `json:"user_pk"`
	UserName      string  `json:"user_name"`
	DocType       string  `json:"doc_type"`
	DocNumber     string  `json:"doc_number"`
	OcppIDTag     string  `json:"ocpp_id_tag"`
	BindStatus    *string `json:"bind_status"`
	BindExists    bool    `json:"bind_exists"`
	TenantName    string  `json:"tenant_name"`
	TenantRelated bool    `json:"tenant_related"`
}

type UserPrivateStationResponse struct {
	Error              *string             `json:"error"`
	UserPrivateStation *UserPrivateStation `json:"userPrivateStation"`
}

type ErrorRestResponse struct {
	Error string `json:"error,omitempty"`
}

package service

import (
	"context"
	"fmt"
	"strings"

	"cve-registration-api/internal/domain"
)

type CVEClient interface {
	CreateChargepoint(ctx context.Context, form domain.ChargePointRestForm) error
	FindChargeBoxPkByFilter(ctx context.Context, chargeBoxID string) (int, error)
	UserExists(ctx context.Context, email string) (bool, error)
	FindUserPkByEmail(ctx context.Context, email string) (int, error)
	FindUserByCPF(ctx context.Context, cpf string) (*domain.UserPrivateStation, error)
	CreateOcppTag(ctx context.Context, form domain.OcppTagForm) error
}

type LicenseClient interface {
	BuscarLicencaDisponivelPorEmail(ctx context.Context, email string) (*domain.License, error)
	BuscarLicencaPorCodigo(ctx context.Context, codigo string) (*domain.License, error)
}

type RegistrationRepository interface {
	Create(ctx context.Context, reg *domain.Registration) error
	UpdateResult(ctx context.Context, id int, status domain.RegistrationStatus, chargeBoxPk *int, licenseCode *string, errMsg *string) error
}

type RegistrationService struct {
	cve      CVEClient
	license  LicenseClient
	repo     RegistrationRepository
	tenantPk int
}

func NewRegistrationService(cve CVEClient, license LicenseClient, repo RegistrationRepository, tenantPk int) *RegistrationService {
	return &RegistrationService{cve: cve, license: license, repo: repo, tenantPk: tenantPk}
}

// FindUserByCPF resolve quem pode ter acesso a estação privada a partir do CPF.
func (s *RegistrationService) FindUserByCPF(ctx context.Context, cpf string) (*domain.UserPrivateStation, error) {
	return s.cve.FindUserByCPF(ctx, cpf)
}

// Register roda o fluxo completo. Cada etapa que falha grava o erro no
// registro (pra atuação manual depois) e retorna — sem deixar o carregador
// pela metade cadastrado sem rastro.
func (s *RegistrationService) Register(ctx context.Context, form domain.RegistrationForm) (*domain.Registration, error) {
	reg := &domain.Registration{Form: form, Status: domain.StatusPending}
	if err := s.repo.Create(ctx, reg); err != nil {
		return nil, fmt.Errorf("salvar solicitação: %w", err)
	}

	// 1) Resolver licenseCode (P3D-/12M-/..., nunca chave CVE-...).
	licenca, err := s.resolveLicense(ctx, form)
	if err != nil {
		return reg, s.fail(ctx, reg, err)
	}

	// 2) Se privado, montar bindUsers a partir de authorized_users (user_pk)
	//    e/ou CPF / e-mails autorizados.
	var bindUsers []domain.BindUser
	if form.Visibility == "private" {
		bindUsers, err = s.resolveBindUsers(ctx, form)
		if err != nil {
			return reg, s.fail(ctx, reg, err)
		}
		if len(bindUsers) == 0 {
			return reg, s.fail(ctx, reg, fmt.Errorf(
				"visibility=private exige authorized_users com user_pk (use GET /users/by-cpf/{cpf})",
			))
		}
	}

	// 3) Montar e enviar o cadastro do chargepoint.
	var openTime, closeTime *string
	scheduleType := "24H"
	autoStopOnClose := false
	if !form.Available24h {
		from, err := normalizeClockTime(form.AvailableFrom)
		if err != nil {
			return reg, s.fail(ctx, reg, fmt.Errorf("available_from inválido: %w", err))
		}
		to, err := normalizeClockTime(form.AvailableTo)
		if err != nil {
			return reg, s.fail(ctx, reg, fmt.Errorf("available_to inválido: %w", err))
		}
		openTime, closeTime = &from, &to
		// CUSTOM + open/close: a CVE deixa de marcar a estação como 24H.
		scheduleType = "CUSTOM"
		autoStopOnClose = true
	}

	cpForm := domain.ChargePointRestForm{
		Active:          true,
		ChargeBoxID:     form.SerialNumber,
		EndpointAddress: "",
		Description:     form.ChargerNickname,
		Address: domain.Address{
			Street:      form.Address,
			HouseNumber: houseNumberPtr(form.HouseNumber),
			Complement:  form.AddressComplement,
			City:        form.City,
			State:       form.State,
			ZipCode:     form.ZipCode,
			Country:     "BR",
		},
		LocationLatitude:          form.Latitude,
		LocationLongitude:         form.Longitude,
		ShowLocation:              form.Latitude != 0 || form.Longitude != 0,
		TypeOf:                    visibilityToTypeOf(form.Visibility),
		IsOpen24Hours:             form.Available24h,
		OpenTime:                  openTime,
		CloseTime:                 closeTime,
		ScheduleType:              scheduleType,
		AutoStopOnClose:           autoStopOnClose,
		MoneyPerKilowattCost:      0,
		MoneyPerDurationCost:      0,
		MoneyPerTransactionCost:   0,
		MoneyPerKilowattIncome:    0,
		MoneyPerDurationIncome:    0,
		MoneyPerTransactionIncome: 0,
		IsHubjectCompatible:       false,
		HasSocPercentage:          true,
		LicenseCode:               licenca.Codigo,
		PaymentChargeTypeCost:     "KWH",
		PaymentChargeTypeIncome:   "KWH",
		PaymentChargeByIncome:     "CHARGE_BOX",
		TaxIncome:                 0,
		Reservation:               false,
		Photos:                    []string{},
		IsTenantDeviceReader:      false,
		TenantPk:                  s.tenantPk,
		BindUsers:                 bindUsers,
	}

	if err := s.cve.CreateChargepoint(ctx, cpForm); err != nil {
		return reg, s.fail(ctx, reg, err)
	}

	// chargeBoxPk é opcional e não deve atrasar a resposta: a CVE aceita o
	// create (202) antes de indexar na listagem — PRIVATE quase nunca aparece
	// na conta de API. Uma busca rápida, sem retry nem varredura ampla.
	var chargeBoxPkPtr *int
	if pk, err := s.cve.FindChargeBoxPkByFilter(ctx, form.SerialNumber); err == nil {
		chargeBoxPkPtr = &pk
		reg.CVEChargeBoxPk = chargeBoxPkPtr
	}

	// 4) Cadastrar tags RFID, se solicitado.
	if form.WantsRFIDTag {
		for _, code := range form.RFIDCodes {
			tagForm := domain.OcppTagForm{
				IDTag:    code,
				Type:     "CARD",
				TenantPk: s.tenantPk,
			}
			if err := s.cve.CreateOcppTag(ctx, tagForm); err != nil {
				return reg, s.fail(ctx, reg, fmt.Errorf("cadastrar tag RFID %s: %w", code, err))
			}
		}
	}

	licenseCode := licenca.Codigo
	reg.LicenseCode = &licenseCode
	reg.Status = domain.StatusSuccess

	if err := s.repo.UpdateResult(ctx, reg.ID, domain.StatusSuccess, chargeBoxPkPtr, &licenseCode, nil); err != nil {
		return reg, fmt.Errorf("salvar resultado do cadastro: %w", err)
	}

	return reg, nil
}

func (s *RegistrationService) resolveBindUsers(ctx context.Context, form domain.RegistrationForm) ([]domain.BindUser, error) {
	var bindUsers []domain.BindUser
	hasOwner := false

	for _, u := range form.AuthorizedUsers {
		userPk := u.UserPk
		if userPk == 0 && strings.TrimSpace(u.CPF) != "" {
			found, err := s.cve.FindUserByCPF(ctx, u.CPF)
			if err != nil {
				return nil, fmt.Errorf("resolver CPF %s: %w", u.CPF, err)
			}
			userPk = found.UserPk
		}
		if userPk == 0 {
			return nil, fmt.Errorf("authorized_users exige user_pk ou cpf")
		}

		bindExists := true
		if u.BindExists != nil {
			bindExists = *u.BindExists
		}
		bindStatus := u.BindStatus
		if bindStatus == "" {
			bindStatus = "ACCEPTED"
		}

		bindUsers = append(bindUsers, domain.BindUser{
			UserPk:     userPk,
			Owner:      u.Owner,
			BindExists: bindExists,
			BindStatus: bindStatus,
		})
		if u.Owner {
			hasOwner = true
		}
	}

	// Compat: e-mails autorizados sem user_pk explícito.
	for _, email := range form.AuthorizedEmails {
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}
		exists, err := s.cve.UserExists(ctx, email)
		if err != nil {
			return nil, fmt.Errorf("checar usuário %s: %w", email, err)
		}
		if !exists {
			return nil, fmt.Errorf(
				"e-mail %s não tem conta no app CVE — peça para criar a conta antes de conceder acesso", email,
			)
		}
		userPk, err := s.cve.FindUserPkByEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		already := false
		for _, b := range bindUsers {
			if b.UserPk == userPk {
				already = true
				break
			}
		}
		if already {
			continue
		}
		bindUsers = append(bindUsers, domain.BindUser{
			UserPk:     userPk,
			Owner:      false,
			BindExists: true,
			BindStatus: "ACCEPTED",
		})
	}

	if len(bindUsers) > 0 && !hasOwner {
		bindUsers[0].Owner = true
	}
	return bindUsers, nil
}

func (s *RegistrationService) resolveLicense(ctx context.Context, form domain.RegistrationForm) (*domain.License, error) {
	codigo := strings.TrimSpace(form.LicenseCode)
	if codigo != "" {
		if strings.HasPrefix(strings.ToUpper(codigo), "CVE-") {
			return nil, fmt.Errorf("license_code inválido (%s): use o código da licença (ex: P3D-..., 12M-...), não a chave de acesso CVE-...", codigo)
		}
		licenca, err := s.license.BuscarLicencaPorCodigo(ctx, codigo)
		if err != nil {
			return nil, fmt.Errorf("checagem de licença: %w", err)
		}
		if licenca == nil {
			return nil, fmt.Errorf("licença %s não encontrada", codigo)
		}
		return licenca, nil
	}

	licenca, err := s.license.BuscarLicencaDisponivelPorEmail(ctx, form.Email)
	if err != nil {
		return nil, fmt.Errorf("checagem de licença: %w", err)
	}
	if licenca == nil {
		return nil, fmt.Errorf("nenhuma licença disponível encontrada para %s", form.Email)
	}
	return licenca, nil
}

func (s *RegistrationService) fail(ctx context.Context, reg *domain.Registration, cause error) error {
	msg := cause.Error()
	reg.Status = domain.StatusError
	reg.ErrorMessage = &msg
	_ = s.repo.UpdateResult(ctx, reg.ID, domain.StatusError, nil, nil, &msg)
	return cause
}

func visibilityToTypeOf(visibility string) string {
	if visibility == "public" {
		return "PUBLIC"
	}
	return "PRIVATE"
}

func houseNumberPtr(n string) *string {
	n = strings.TrimSpace(n)
	if n == "" {
		return nil
	}
	return &n
}

// normalizeClockTime converte "HH:MM" ou "HH:MM:SS" para "HH:MM:SS"
// (formato exigido pela CVE-PRO; "HH:MM" sozinho causa 500).
func normalizeClockTime(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("horário obrigatório quando available_24h=false (use HH:MM ou HH:MM:SS)")
	}
	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 2:
		if len(parts[0]) != 2 || len(parts[1]) != 2 {
			return "", fmt.Errorf("use o formato HH:MM (ex: 08:00)")
		}
		return parts[0] + ":" + parts[1] + ":00", nil
	case 3:
		if len(parts[0]) != 2 || len(parts[1]) != 2 || len(parts[2]) != 2 {
			return "", fmt.Errorf("use o formato HH:MM:SS (ex: 08:00:00)")
		}
		return raw, nil
	default:
		return "", fmt.Errorf("use o formato HH:MM ou HH:MM:SS")
	}
}

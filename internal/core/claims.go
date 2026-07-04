package core

// Claims is an OIDC-style claim set derived from a certificate's parsed subject —
// ready to drop into an ID token or an authorization decision, instead of a raw
// DN. Standard OIDC claims (sub, name, given_name, family_name, email) sit
// alongside RK-specific ones (iin, bin, organization, roles, owner_type, gender).
//
// It is built from already-extracted fields (see certparse.go), so it inherits the
// same best-effort semantics: absent values are simply omitted. sub is the stable
// subject identifier — IIN when present (individuals and employees), else BIN
// (infosystem certificates without an IIN).
type Claims struct {
	Sub          string   `json:"sub,omitempty"`
	Name         string   `json:"name,omitempty"`
	GivenName    string   `json:"given_name,omitempty"`
	FamilyName   string   `json:"family_name,omitempty"`
	Email        string   `json:"email,omitempty"`
	IIN          string   `json:"iin,omitempty"`
	BIN          string   `json:"bin,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	OwnerType    string   `json:"owner_type,omitempty"`
	Gender       string   `json:"gender,omitempty"` // OIDC-style: "male" | "female"
}

// ClaimsFromCertificate maps a parsed certificate's subject into an OIDC claim set.
func ClaimsFromCertificate(cert Certificate) Claims {
	s := cert.Subject
	c := Claims{
		Sub:          subjectID(s),
		Name:         displayName(s),
		GivenName:    s.GivenName,
		FamilyName:   s.LastName,
		Email:        s.Email,
		IIN:          s.IIN,
		BIN:          s.BIN,
		Organization: s.Organization,
		Roles:        cert.Roles,
		OwnerType:    cert.OwnerType,
		Gender:       oidcGender(s.Gender),
	}
	return c
}

// subjectID is the stable OIDC sub: IIN if present, else BIN.
func subjectID(s Subject) string {
	if s.IIN != "" {
		return s.IIN
	}
	return s.BIN
}

// displayName is the OIDC name claim: the certificate common name, or a
// family+given composite when the common name is absent.
func displayName(s Subject) string {
	if s.CommonName != "" {
		return s.CommonName
	}
	switch {
	case s.LastName != "" && s.GivenName != "":
		return s.LastName + " " + s.GivenName
	case s.LastName != "":
		return s.LastName
	default:
		return s.GivenName
	}
}

// oidcGender maps the derived MALE|FEMALE|NONE to the OIDC-conventional lowercase
// value, omitting the non-gendered / unknown case.
func oidcGender(g string) string {
	switch g {
	case "MALE":
		return "male"
	case "FEMALE":
		return "female"
	default:
		return ""
	}
}

package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Profile object types.
const (
	ProofTyp       = "agent-trust-proof+jwt"
	DelegationTyp  = "agent-trust-delegation+jwt"
	AttestationTyp = "agent-trust-attestation+jwt"
)

// B64URL encodes without padding.
func B64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// B64URLDecode decodes padded or unpadded input.
func B64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// BodyHash is b64url(sha256(body)) — the proof's `rh` claim.
func BodyHash(body []byte) string { h := sha256.Sum256(body); return B64URL(h[:]) }

// JWK is the subset of RFC 7517 the profile uses (EC P-256 and OKP Ed25519).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// AlgForJWK: ES256 for P-256, EdDSA for Ed25519, "" otherwise.
func AlgForJWK(k JWK) string {
	if k.Kty == "EC" && k.Crv == "P-256" {
		return "ES256"
	}
	if k.Kty == "OKP" && k.Crv == "Ed25519" {
		return "EdDSA"
	}
	return ""
}

// Signer holds a private key for ES256 or EdDSA.
type Signer struct {
	Alg string
	EC  *ecdsa.PrivateKey
	Ed  ed25519.PrivateKey
}

// GenerateKey creates an agent/org key pair and its public JWK.
func GenerateKey(alg string) (*Signer, JWK, error) {
	switch alg {
	case "ES256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, JWK{}, err
		}
		return &Signer{Alg: alg, EC: k}, JWK{Kty: "EC", Crv: "P-256", X: B64URL(pad32(k.X)), Y: B64URL(pad32(k.Y))}, nil
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, JWK{}, err
		}
		return &Signer{Alg: alg, Ed: priv}, JWK{Kty: "OKP", Crv: "Ed25519", X: B64URL(pub)}, nil
	}
	return nil, JWK{}, errors.New("alg")
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (s *Signer) sign(input []byte) ([]byte, error) {
	switch s.Alg {
	case "ES256":
		h := sha256.Sum256(input)
		r, sv, err := ecdsa.Sign(rand.Reader, s.EC, h[:])
		if err != nil {
			return nil, err
		}
		return append(pad32(r), pad32(sv)...), nil
	case "EdDSA":
		return ed25519.Sign(s.Ed, input), nil
	}
	return nil, errors.New("alg")
}

func verifySig(k JWK, alg string, input, sig []byte) bool {
	switch alg {
	case "ES256":
		if k.Kty != "EC" || k.Crv != "P-256" || len(sig) != 64 {
			return false
		}
		x, ex := B64URLDecode(k.X)
		y, ey := B64URLDecode(k.Y)
		if ex != nil || ey != nil {
			return false
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		h := sha256.Sum256(input)
		return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case "EdDSA":
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			return false
		}
		x, err := B64URLDecode(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(x), input, sig)
	}
	return false
}

var _ = crypto.SHA256

// JWTHeader of a profile object.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// SignJWT produces a compact JWS.
func SignJWT(s *Signer, kid, typ string, payload any) (string, error) {
	hb, _ := json.Marshal(JWTHeader{Alg: s.Alg, Typ: typ, Kid: kid})
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := B64URL(hb) + "." + B64URL(pb)
	sig, err := s.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + B64URL(sig), nil
}

// DecodeJWT reads header and payload without verifying.
func DecodeJWT(token string, payload any) (JWTHeader, bool) {
	parts := strings.Split(token, ".")
	var h JWTHeader
	if len(parts) != 3 {
		return h, false
	}
	hb, e1 := B64URLDecode(parts[0])
	pb, e2 := B64URLDecode(parts[1])
	if e1 != nil || e2 != nil || json.Unmarshal(hb, &h) != nil {
		return h, false
	}
	if payload != nil && json.Unmarshal(pb, payload) != nil {
		return h, false
	}
	return h, true
}

// KeyResolver returns the public JWK for (kid, iss), or nil.
type KeyResolver func(kid, iss string) *JWK

type timeClaims struct {
	Iss string `json:"iss"`
	Exp *int64 `json:"exp"`
	Nbf *int64 `json:"nbf"`
	Iat *int64 `json:"iat"`
}

// VerifyJWT checks signature, typ and time claims; payload is decoded into out. Returns a reason on failure.
func VerifyJWT(token, typ string, resolve KeyResolver, now time.Time, out any) string {
	var tc timeClaims
	h, ok := DecodeJWT(token, &tc)
	if !ok {
		return "malformed"
	}
	if h.Typ != typ {
		return "typ"
	}
	if h.Alg != "ES256" && h.Alg != "EdDSA" {
		return "alg"
	}
	if h.Kid == "" || tc.Iss == "" {
		return "claims"
	}
	k := resolve(h.Kid, tc.Iss)
	if k == nil {
		return "unknown_key"
	}
	if AlgForJWK(*k) != h.Alg {
		return "alg_mismatch"
	}
	parts := strings.Split(token, ".")
	sig, err := B64URLDecode(parts[2])
	if err != nil || !verifySig(*k, h.Alg, []byte(parts[0]+"."+parts[1]), sig) {
		return "signature"
	}
	t := now.Unix()
	if tc.Exp != nil && *tc.Exp <= t {
		return "expired"
	}
	if tc.Nbf != nil && *tc.Nbf > t+300 {
		return "not_yet_valid"
	}
	if tc.Iat != nil && *tc.Iat > t+300 {
		return "iat_future"
	}
	if out != nil {
		pb, _ := B64URLDecode(parts[1])
		if json.Unmarshal(pb, out) != nil {
			return "claims"
		}
	}
	return ""
}

// ---------- request proof (Agent-Proof) ----------

// ProofClaims of a request proof.
type ProofClaims struct {
	Iss string `json:"iss"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
	Rh  string `json:"rh"`
}

// NormalizeHtu: lower-case scheme+host, path only.
func NormalizeHtu(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" {
		return u
	}
	return strings.ToLower(p.Scheme) + "://" + strings.ToLower(p.Host) + p.Path
}

// SignRequestProof produces the Agent-Proof header value.
func SignRequestProof(s *Signer, kid, iss, htm, htu string, body []byte, now time.Time, ttl int64) (string, error) {
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	c := ProofClaims{Iss: iss, Htm: strings.ToUpper(htm), Htu: NormalizeHtu(htu), Iat: now.Unix(), Exp: now.Unix() + ttl, Jti: B64URL(jti), Rh: BodyHash(body)}
	return SignJWT(s, kid, ProofTyp, c)
}

// ProofInput for VerifyRequestProof.
type ProofInput struct {
	Proof      string
	ResolveKey func(kid string) *JWK
	Htm, Htu   string
	BodyHash   string
	Now        time.Time
	SeenJti    func(jti string, exp int64) bool
}

// ProofResult of VerifyRequestProof.
type ProofResult struct {
	OK     bool
	Reason string
	Kid    string
	Alg    string
	Claims ProofClaims
}

// VerifyRequestProof mirrors the TypeScript reference.
func VerifyRequestProof(i ProofInput) ProofResult {
	var c ProofClaims
	h, ok := DecodeJWT(i.Proof, &c)
	if !ok {
		return ProofResult{Reason: "malformed"}
	}
	res := ProofResult{Kid: h.Kid, Alg: h.Alg}
	if h.Typ != ProofTyp {
		res.Reason = "typ"
		return res
	}
	if h.Alg != "ES256" && h.Alg != "EdDSA" {
		res.Reason = "alg"
		return res
	}
	var k *JWK
	if h.Kid != "" {
		k = i.ResolveKey(h.Kid)
	} else {
		k = i.ResolveKey("")
	}
	if k == nil {
		res.Reason = "unknown_key"
		return res
	}
	if AlgForJWK(*k) != h.Alg {
		res.Reason = "alg_mismatch"
		return res
	}
	parts := strings.Split(i.Proof, ".")
	sig, err := B64URLDecode(parts[2])
	if err != nil || !verifySig(*k, h.Alg, []byte(parts[0]+"."+parts[1]), sig) {
		res.Reason = "signature"
		return res
	}
	if c.Iss == "" || c.Htm == "" || c.Htu == "" || c.Jti == "" || c.Rh == "" {
		res.Reason = "claims"
		return res
	}
	if strings.ToUpper(c.Htm) != strings.ToUpper(i.Htm) {
		res.Reason = "htm"
		return res
	}
	if NormalizeHtu(c.Htu) != NormalizeHtu(i.Htu) {
		res.Reason = "htu"
		return res
	}
	if c.Rh != i.BodyHash {
		res.Reason = "body_hash"
		return res
	}
	t := i.Now.Unix()
	if c.Iat > t+300 {
		res.Reason = "iat_future"
		return res
	}
	if c.Exp <= t {
		res.Reason = "expired"
		return res
	}
	if t-c.Iat > 300 {
		res.Reason = "too_old"
		return res
	}
	if i.SeenJti != nil && i.SeenJti(c.Jti, c.Exp) {
		res.Reason = "replay"
		return res
	}
	res.OK = true
	res.Claims = c
	return res
}

// ---------- delegation credential + attestation ----------

// DelegationClaims (`atp`) of a delegation credential.
type DelegationClaims struct {
	V            int                       `json:"v"`
	Issuer       struct{ Type, ID string } `json:"issuer"`
	Capabilities CapSet                    `json:"capabilities"`
	Constraints  Constraints               `json:"constraints,omitempty"`
	Effective    CapSet                    `json:"effective"`
	Parent       *string                   `json:"parent"`
	ParentHash   *string                   `json:"parent_hash"`
	Depth        int                       `json:"depth"`
	Task         *string                   `json:"task,omitempty"`
}

// DelegationJWT payload.
type DelegationJWT struct {
	Iss string           `json:"iss"`
	Sub string           `json:"sub"`
	Jti string           `json:"jti"`
	Iat int64            `json:"iat"`
	Nbf *int64           `json:"nbf,omitempty"`
	Exp *int64           `json:"exp,omitempty"`
	Atp DelegationClaims `json:"atp"`
}

// CredentialChainResult of VerifyDelegationChain.
type CredentialChainResult struct {
	OK         bool
	At         int
	Reason     string
	Effective  CapSet
	Chain      []string
	Subject    string
	RootIssuer struct{ Type, ID string }
}

func capsEqual(a, b CapSet) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// VerifyDelegationChain verifies root → leaf offline against the issuing organizations' keys.
func VerifyDelegationChain(tokens []string, resolve KeyResolver, now time.Time) CredentialChainResult {
	if len(tokens) == 0 {
		return CredentialChainResult{Reason: "empty"}
	}
	if len(tokens) > MaxChainDepth {
		return CredentialChainResult{At: len(tokens), Reason: "too_long"}
	}
	var prev *DelegationJWT
	prevToken := ""
	var effective CapSet
	res := CredentialChainResult{Chain: []string{}}
	for i, tok := range tokens {
		var p DelegationJWT
		if r := VerifyJWT(tok, DelegationTyp, resolve, now, &p); r != "" {
			return CredentialChainResult{At: i, Reason: r}
		}
		a := p.Atp
		if a.V != 1 || p.Sub == "" || p.Jti == "" {
			return CredentialChainResult{At: i, Reason: "claims"}
		}
		if i == 0 {
			if a.Parent != nil || a.Depth != 0 {
				return CredentialChainResult{At: i, Reason: "root_expected"}
			}
			if a.Issuer.Type != "principal" {
				return CredentialChainResult{At: i, Reason: "root_requires_principal"}
			}
			effective = a.Capabilities
			res.RootIssuer = a.Issuer
			if !capsEqual(a.Effective, effective) {
				return CredentialChainResult{At: i, Reason: "effective_mismatch"}
			}
		} else {
			if a.Parent == nil || *a.Parent != prev.Jti {
				return CredentialChainResult{At: i, Reason: "parent_link"}
			}
			if a.ParentHash == nil || *a.ParentHash != BodyHash([]byte(prevToken)) {
				return CredentialChainResult{At: i, Reason: "parent_hash"}
			}
			if a.Depth != prev.Atp.Depth+1 {
				return CredentialChainResult{At: i, Reason: "depth"}
			}
			if a.Issuer.Type != "agent" || a.Issuer.ID != prev.Sub {
				return CredentialChainResult{At: i, Reason: "issuer_must_be_parent_subject"}
			}
			if !IsSubset(a.Capabilities, effective) {
				return CredentialChainResult{At: i, Reason: "exceeds_parent"}
			}
			effective = Attenuate(effective, a.Capabilities)
			if !capsEqual(a.Effective, effective) {
				return CredentialChainResult{At: i, Reason: "effective_mismatch"}
			}
		}
		res.Chain = append(res.Chain, p.Jti)
		pp := p
		prev = &pp
		prevToken = tok
	}
	res.OK = true
	res.Effective = effective
	res.Subject = prev.Sub
	return res
}

// AttestationClaims (`atp`) of an authorization attestation.
type AttestationClaims struct {
	V               int      `json:"v"`
	Principal       *string  `json:"principal"`
	Organization    string   `json:"organization"`
	Action          string   `json:"action"`
	Resource        *string  `json:"resource"`
	Decision        string   `json:"decision"`
	Capabilities    CapSet   `json:"capabilities"`
	DelegationChain []string `json:"delegation_chain"`
	HumanApproval   *struct {
		Required   bool    `json:"required"`
		Approved   bool    `json:"approved"`
		Approver   *string `json:"approver"`
		ApprovalID *string `json:"approval_id"`
	} `json:"human_approval"`
	DecisionID    string  `json:"decision_id"`
	// Use is "single" (§9.2: consumed on first acceptance) or "multi"/absent (v0.1).
	Use           string  `json:"use,omitempty"`
	RequestHash   *string `json:"request_hash"`
	PolicyVersion *string `json:"policy_version"`
	// Grant (§17, v0.3 draft): what a brokered permit is for.
	Grant *struct {
		Connection string `json:"connection"`
		Operation  string `json:"operation"`
		ParamsHash string `json:"params_hash"`
	} `json:"grant,omitempty"`
}

// Audience is the JWT aud claim: a string or an array of strings on the wire.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = Audience(many)
	return nil
}

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Contains reports whether the audience names id.
func (a Audience) Contains(id string) bool {
	for _, x := range a {
		if x == id {
			return true
		}
	}
	return false
}

// AttestationJWT payload.
type AttestationJWT struct {
	Iss string            `json:"iss"`
	Sub string            `json:"sub"`
	Jti string            `json:"jti"`
	Iat int64             `json:"iat"`
	Exp int64             `json:"exp"`
	Aud Audience          `json:"aud,omitempty"`
	Atp AttestationClaims `json:"atp"`
}

// VerifyAttestation checks an authorization attestation; expiresIn is seconds left.
func VerifyAttestation(token string, resolve KeyResolver, now time.Time) (AttestationJWT, int64, string) {
	var p AttestationJWT
	if r := VerifyJWT(token, AttestationTyp, resolve, now, &p); r != "" {
		return p, 0, r
	}
	if p.Atp.V != 1 || p.Sub == "" || p.Jti == "" || p.Exp == 0 || p.Atp.Action == "" {
		return p, 0, "claims"
	}
	return p, p.Exp - now.Unix(), ""
}

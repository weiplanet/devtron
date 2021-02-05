package settings

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"path"
	"strings"

	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"

	"github.com/devtron-labs/devtron/pkg/common"
	"github.com/devtron-labs/devtron/pkg/settings/oidc"
	tlsutil "github.com/devtron-labs/devtron/util/tls"
)

// OIDCSettings holds in-memory runtime configuration options.
type OIDCSettings struct {
	// URL is the externally facing URL users will visit to reach Argo CD.
	// The value here is used when configuring SSO. Omitting this value will disable SSO.
	URL string `json:"url,omitempty"`
	// Indicates if status badge is enabled or not.
	StatusBadgeEnabled bool `json:"statusBadgeEnable"`
	// DexConfig contains portions of a dex config yaml
	DexConfig string `json:"dexConfig,omitempty"`
	// OIDCConfigRAW holds OIDC configuration as a raw string
	OIDCConfigRAW string `json:"oidcConfig,omitempty"`
	// ServerSignature holds the key used to generate JWT tokens.
	ServerSignature []byte `json:"serverSignature,omitempty"`
	// Certificate holds the certificate/private key for the Argo CD API server.
	// If nil, will run insecure without TLS.
	Certificate *tls.Certificate `json:"-"`
	// Secrets holds all secrets in argocd-secret as a map[string]string
	Secrets map[string]string `json:"secrets,omitempty"`
	// Indicates if anonymous user is enabled or not
	AnonymousUserEnabled bool `json:"anonymousUserEnabled,omitempty"`
}

type OIDCConfig struct {
	Name                   string                 `json:"name,omitempty"`
	Issuer                 string                 `json:"issuer,omitempty"`
	ClientID               string                 `json:"clientID,omitempty"`
	ClientSecret           string                 `json:"clientSecret,omitempty"`
	CLIClientID            string                 `json:"cliClientID,omitempty"`
	RequestedScopes        []string               `json:"requestedScopes,omitempty"`
	RequestedIDTokenClaims map[string]*oidc.Claim `json:"requestedIDTokenClaims,omitempty"`
	LogoutURL              string                 `json:"logoutURL,omitempty"`
}

// IsSSOConfigured returns whether or not single-sign-on is configured
func (a *OIDCSettings) IsSSOConfigured() bool {
	if a.IsDexConfigured() {
		return true
	}
	if a.OIDCConfig() != nil {
		return true
	}
	return false
}

func (a *OIDCSettings) IsDexConfigured() bool {
	if a.URL == "" {
		return false
	}
	dexCfg, err := UnmarshalDexConfig(a.DexConfig)
	if err != nil {
		log.Warn("invalid dex yaml config")
		return false
	}
	return len(dexCfg) > 0
}

func UnmarshalDexConfig(config string) (map[string]interface{}, error) {
	var dexCfg map[string]interface{}
	err := yaml.Unmarshal([]byte(config), &dexCfg)
	return dexCfg, err
}

func (a *OIDCSettings) OIDCConfig() *OIDCConfig {
	if a.OIDCConfigRAW == "" {
		return nil
	}
	oidcConfig, err := UnmarshalOIDCConfig(a.OIDCConfigRAW)
	if err != nil {
		log.Warnf("invalid oidc config: %v", err)
		return nil
	}
	oidcConfig.ClientSecret = ReplaceStringSecret(oidcConfig.ClientSecret, a.Secrets)
	oidcConfig.ClientID = ReplaceStringSecret(oidcConfig.ClientID, a.Secrets)
	return &oidcConfig
}

func UnmarshalOIDCConfig(config string) (OIDCConfig, error) {
	var oidcConfig OIDCConfig
	err := yaml.Unmarshal([]byte(config), &oidcConfig)
	return oidcConfig, err
}

// TLSConfig returns a tls.Config with the configured certificates
func (a *OIDCSettings) TLSConfig() *tls.Config {
	if a.Certificate == nil {
		return nil
	}
	certPool := x509.NewCertPool()
	pemCertBytes, _ := tlsutil.EncodeX509KeyPair(*a.Certificate)
	ok := certPool.AppendCertsFromPEM(pemCertBytes)
	if !ok {
		panic("bad certs")
	}
	return &tls.Config{
		RootCAs: certPool,
	}
}

func (a *OIDCSettings) IssuerURL() string {
	if oidcConfig := a.OIDCConfig(); oidcConfig != nil {
		return oidcConfig.Issuer
	}
	if a.DexConfig != "" {
		return a.URL + common.DexAPIEndpoint
	}
	return ""
}

func (a *OIDCSettings) OAuth2ClientID() string {
	if oidcConfig := a.OIDCConfig(); oidcConfig != nil {
		return oidcConfig.ClientID
	}
	if a.DexConfig != "" {
		return common.ArgoCDClientAppID
	}
	return ""
}

func (a *OIDCSettings) OAuth2ClientSecret() string {
	if oidcConfig := a.OIDCConfig(); oidcConfig != nil {
		return oidcConfig.ClientSecret
	}
	if a.DexConfig != "" {
		return a.DexOAuth2ClientSecret()
	}
	return ""
}

func appendURLPath(inputURL string, inputPath string) (string, error) {
	u, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, inputPath)
	return u.String(), nil
}

func (a *OIDCSettings) RedirectURL() (string, error) {
	return appendURLPath(a.URL, common.CallbackEndpoint)
}

func (a *OIDCSettings) DexRedirectURL() (string, error) {
	return appendURLPath(a.URL, common.DexCallbackEndpoint)
}

// DexOAuth2ClientSecret calculates an arbitrary, but predictable OAuth2 client secret string derived
// from the server secret. This is called by the dex startup wrapper (argocd-util rundex), as well
// as the API server, such that they both independently come to the same conclusion of what the
// OAuth2 shared client secret should be.
func (a *OIDCSettings) DexOAuth2ClientSecret() string {
	h := sha256.New()
	_, err := h.Write(a.ServerSignature)
	if err != nil {
		panic(err)
	}
	sha := h.Sum(nil)
	return base64.URLEncoding.EncodeToString(sha)[:40]
}

// ReplaceStringSecret checks if given string is a secret key reference ( starts with $ ) and returns corresponding value from provided map
func ReplaceStringSecret(val string, secretValues map[string]string) string {
	if val == "" || !strings.HasPrefix(val, "$") {
		return val
	}
	secretKey := val[1:]
	secretVal, ok := secretValues[secretKey]
	if !ok {
		log.Warnf("config referenced '%s', but key does not exist in secret", val)
		return val
	}
	return secretVal
}

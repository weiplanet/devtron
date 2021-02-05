package settings

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	v1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

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

const (
	// settingServerSignatureKey designates the key for a server secret key inside a Kubernetes secret.
	settingServerSignatureKey = "server.secretkey"
	// settingServerCertificate designates the key for the public cert used in TLS
	settingServerCertificate = "tls.crt"
	// settingServerPrivateKey designates the key for the private key used in TLS
	settingServerPrivateKey = "tls.key"
	// settingURLKey designates the key where Argo CD's external URL is set
	settingURLKey = "url"
	// settingDexConfigKey designates the key for the dex config
	settingDexConfigKey = "dex.config"
	// settingsOIDCConfigKey designates the key for OIDC config
	settingsOIDCConfigKey = "oidc.config"
	// statusBadgeEnabledKey holds the key which enables of disables status badge feature
	statusBadgeEnabledKey = "statusbadge.enabled"
	// anonymousUserEnabledKey is the key which enables or disables anonymous user
	anonymousUserEnabledKey = "users.anonymous.enabled"
)

// SettingsManager holds config info for a new manager with which to access Kubernetes ConfigMaps.
type SettingsManager struct {
	ctx        context.Context
	clientset  kubernetes.Interface
	secrets    v1listers.SecretLister
	configmaps v1listers.ConfigMapLister
	namespace  string
	// subscribers is a list of subscribers to settings updates
	subscribers []chan<- *OIDCSettings
	// mutex protects concurrency sensitive parts of settings manager: access to subscribers list and initialization flag
	mutex             *sync.Mutex
	initContextCancel func()
}

type incompleteSettingsError struct {
	message string
}

func (e *incompleteSettingsError) Error() string {
	return e.message
}

func (mgr *SettingsManager) GetSecretsLister() (v1listers.SecretLister, error) {
	err := mgr.ensureSynced(false)
	if err != nil {
		return nil, err
	}
	return mgr.secrets, nil
}

func (mgr *SettingsManager) getConfigMap() (*apiv1.ConfigMap, error) {
	err := mgr.ensureSynced(false)
	if err != nil {
		return nil, err
	}
	argoCDCM, err := mgr.configmaps.ConfigMaps(mgr.namespace).Get(common.ArgoCDConfigMapName)
	if err != nil {
		return nil, err
	}
	if argoCDCM.Data == nil {
		argoCDCM.Data = make(map[string]string)
	}
	return argoCDCM, err
}

// Returns the ConfigMap with the given name from the cluster.
// The ConfigMap must be labeled with "app.kubernetes.io/part-of: argocd" in
// order to be retrievable.
func (mgr *SettingsManager) GetConfigMapByName(configMapName string) (*apiv1.ConfigMap, error) {
	err := mgr.ensureSynced(false)
	if err != nil {
		return nil, err
	}
	configMap, err := mgr.configmaps.ConfigMaps(mgr.namespace).Get(configMapName)
	if err != nil {
		return nil, err
	}
	return configMap, err
}

// GetSettings retrieves settings from the ArgoCDConfigMap and secret.
func (mgr *SettingsManager) GetSettings() (*OIDCSettings, error) {
	err := mgr.ensureSynced(false)
	if err != nil {
		return nil, err
	}
	argoCDCM, err := mgr.configmaps.ConfigMaps(mgr.namespace).Get(common.ArgoCDConfigMapName)
	if err != nil {
		return nil, err
	}
	argoCDSecret, err := mgr.secrets.Secrets(mgr.namespace).Get(common.ArgoCDSecretName)
	if err != nil {
		return nil, err
	}
	var settings OIDCSettings
	var errs []error
	updateSettingsFromConfigMap(&settings, argoCDCM)
	if err := updateSettingsFromSecret(&settings, argoCDSecret); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return &settings, errs[0]
	}

	return &settings, nil
}

func (mgr *SettingsManager) initialize(ctx context.Context) error {
	tweakConfigMap := func(options *metav1.ListOptions) {
		cmLabelSelector := fields.ParseSelectorOrDie("app.kubernetes.io/part-of=argocd")
		options.LabelSelector = cmLabelSelector.String()
	}

	eventHandler := cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			//mgr.invalidateCache()
		},
	}
	indexers := cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}
	cmInformer := v1.NewFilteredConfigMapInformer(mgr.clientset, mgr.namespace, 3*time.Minute, indexers, tweakConfigMap)
	secretsInformer := v1.NewSecretInformer(mgr.clientset, mgr.namespace, 3*time.Minute, indexers)
	cmInformer.AddEventHandler(eventHandler)
	secretsInformer.AddEventHandler(eventHandler)

	log.Info("Starting configmap/secret informers")
	go func() {
		cmInformer.Run(ctx.Done())
		log.Info("configmap informer cancelled")
	}()
	go func() {
		secretsInformer.Run(ctx.Done())
		log.Info("secrets informer cancelled")
	}()

	if !cache.WaitForCacheSync(ctx.Done(), cmInformer.HasSynced, secretsInformer.HasSynced) {
		return fmt.Errorf("Timed out waiting for settings cache to sync")
	}
	log.Info("Configmap/secret informer synced")

	tryNotify := func() {
		newSettings, err := mgr.GetSettings()
		if err != nil {
			log.Warnf("Unable to parse updated settings: %v", err)
		} else {
			mgr.notifySubscribers(newSettings)
		}
	}
	now := time.Now()
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if metaObj, ok := obj.(metav1.Object); ok {
				if metaObj.GetCreationTimestamp().After(now) {
					tryNotify()
				}
			}

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldMeta, oldOk := oldObj.(metav1.Common)
			newMeta, newOk := newObj.(metav1.Common)
			if oldOk && newOk && oldMeta.GetResourceVersion() != newMeta.GetResourceVersion() {
				tryNotify()
			}
		},
	}
	secretsInformer.AddEventHandler(handler)
	cmInformer.AddEventHandler(handler)
	mgr.secrets = v1listers.NewSecretLister(secretsInformer.GetIndexer())
	mgr.configmaps = v1listers.NewConfigMapLister(cmInformer.GetIndexer())
	return nil
}

func (mgr *SettingsManager) ensureSynced(forceResync bool) error {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	if !forceResync && mgr.secrets != nil && mgr.configmaps != nil {
		return nil
	}

	if mgr.initContextCancel != nil {
		mgr.initContextCancel()
	}
	ctx, cancel := context.WithCancel(mgr.ctx)
	mgr.initContextCancel = cancel
	return mgr.initialize(ctx)
}

// updateSettingsFromConfigMap transfers settings from a Kubernetes configmap into an OIDCSettings struct.
func updateSettingsFromConfigMap(settings *OIDCSettings, argoCDCM *apiv1.ConfigMap) {
	settings.DexConfig = argoCDCM.Data[settingDexConfigKey]
	settings.OIDCConfigRAW = argoCDCM.Data[settingsOIDCConfigKey]
	settings.StatusBadgeEnabled = argoCDCM.Data[statusBadgeEnabledKey] == "true"
	settings.AnonymousUserEnabled = argoCDCM.Data[anonymousUserEnabledKey] == "true"
	if err := validateExternalURL(argoCDCM.Data[settingURLKey]); err != nil {
		log.Warnf("Failed to validate URL in configmap: %v", err)
	}
	settings.URL = argoCDCM.Data[settingURLKey]
}

// validateExternalURL ensures the external URL that is set on the configmap is valid
func validateExternalURL(u string) error {
	if u == "" {
		return nil
	}
	URL, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("Failed to parse URL: %v", err)
	}
	if URL.Scheme != "http" && URL.Scheme != "https" {
		return fmt.Errorf("URL must include http or https protocol")
	}
	return nil
}

// updateSettingsFromSecret transfers settings from a Kubernetes secret into an OIDCSettings struct.
func updateSettingsFromSecret(settings *OIDCSettings, argoCDSecret *apiv1.Secret) error {
	var errs []error
	secretKey, ok := argoCDSecret.Data[settingServerSignatureKey]
	if ok {
		settings.ServerSignature = secretKey
	} else {
		errs = append(errs, &incompleteSettingsError{message: "server.secretkey is missing"})
	}

	serverCert, certOk := argoCDSecret.Data[settingServerCertificate]
	serverKey, keyOk := argoCDSecret.Data[settingServerPrivateKey]
	if certOk && keyOk {
		cert, err := tls.X509KeyPair(serverCert, serverKey)
		if err != nil {
			errs = append(errs, &incompleteSettingsError{message: fmt.Sprintf("invalid x509 key pair %s/%s in secret: %s", settingServerCertificate, settingServerPrivateKey, err)})
		} else {
			settings.Certificate = &cert
		}
	}
	secretValues := make(map[string]string, len(argoCDSecret.Data))
	for k, v := range argoCDSecret.Data {
		secretValues[k] = string(v)
	}
	settings.Secrets = secretValues
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// NewSettingsManager generates a new SettingsManager pointer and returns it
func NewSettingsManager(ctx context.Context, clientset kubernetes.Interface, namespace string) *SettingsManager {

	mgr := &SettingsManager{
		ctx:       ctx,
		clientset: clientset,
		namespace: namespace,
		mutex:     &sync.Mutex{},
	}

	return mgr
}

func (mgr *SettingsManager) ResyncInformers() error {
	return mgr.ensureSynced(true)
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

// Subscribe registers a channel in which to subscribe to settings updates
func (mgr *SettingsManager) Subscribe(subCh chan<- *OIDCSettings) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	mgr.subscribers = append(mgr.subscribers, subCh)
	log.Infof("%v subscribed to settings updates", subCh)
}

// Unsubscribe unregisters a channel from receiving of settings updates
func (mgr *SettingsManager) Unsubscribe(subCh chan<- *OIDCSettings) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	for i, ch := range mgr.subscribers {
		if ch == subCh {
			mgr.subscribers = append(mgr.subscribers[:i], mgr.subscribers[i+1:]...)
			log.Infof("%v unsubscribed from settings updates", subCh)
			return
		}
	}
}

func (mgr *SettingsManager) notifySubscribers(newSettings *OIDCSettings) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	if len(mgr.subscribers) > 0 {
		subscribers := make([]chan<- *OIDCSettings, len(mgr.subscribers))
		copy(subscribers, mgr.subscribers)
		// make sure subscribes are notified in a separate thread to avoid potential deadlock
		go func() {
			log.Infof("Notifying %d settings subscribers: %v", len(subscribers), subscribers)
			for _, sub := range subscribers {
				sub <- newSettings
			}
		}()
	}
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

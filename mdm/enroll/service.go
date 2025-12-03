package enroll

import (
	"bytes"
	"crypto/x509"
	"io/ioutil"
	"log"
	"strings"
	"sync"

	"github.com/micromdm/micromdm/platform/config"
	"github.com/micromdm/micromdm/platform/profile"
	"github.com/micromdm/micromdm/platform/pubsub"
	"github.com/micromdm/scep/v2/challenge"

	"github.com/jessepeterson/cfgprofiles"
	"github.com/micromdm/plist"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

const (
	EnrollmentProfileId string = "com.github.micromdm.micromdm.enroll"
	OTAProfileId        string = "com.github.micromdm.micromdm.ota"

	profilePayloadOrganization = "Hakinet"
	profilePayloadDisplayName  = "Hakinet Enrollment Profile"
	profilePayloadDescription  = "The server may alter your settings"

	mdmPayloadDescription     = "Enrolls with the Hakinet MDM server"
	mdmPayloadServerEndpoint  = "/mdm/connect"
	mdmPayloadCheckInEndpoint = "/mdm/checkin"

	scepPayloadDescription = "Configures SCEP"
	scepPayloadDisplayName = "Hakinet SCEP"
)

type Service interface {
	Enroll(ctx context.Context) (profile.Mobileconfig, error)
	OTAEnroll(ctx context.Context) (profile.Mobileconfig, error)
	OTAPhase2(ctx context.Context) (profile.Mobileconfig, error)
	OTAPhase3(ctx context.Context) (profile.Mobileconfig, error)
}

func NewService(topic TopicProvider, sub pubsub.Subscriber, scepURL, scepChallenge, url, tlsCertPath, scepSubject string, profileDB profile.Store, challengeStore challenge.Store) (Service, error) {
	var tlsCert []byte
	var err error

	if tlsCertPath != "" {
		tlsCert, err = ioutil.ReadFile(tlsCertPath)

		if err != nil {
			return nil, err
		}
	}

	if scepSubject == "" {
		scepSubject = "/O=Hakinet/CN=Hakinet Identity "
	}

	subjectElements := strings.Split(scepSubject, "/")
	var subject [][][]string

	for _, element := range subjectElements {
		if element == "" {
			continue
		}
		subjectKeyValue := strings.Split(element, "=")
		subject = append(subject, [][]string{{subjectKeyValue[0], subjectKeyValue[1]}})
	}

	// fetch the push topic from the db.
	// will be "" if the push certificate hasn't been uploaded yet
	pushTopic, _ := topic.PushTopic()
	svc := &service{
		URL:                url,
		SCEPURL:            scepURL,
		SCEPSubject:        subject,
		SCEPChallenge:      scepChallenge,
		SCEPChallengeStore: challengeStore,
		TLSCert:            tlsCert,
		ProfileDB:          profileDB,
		Topic:              pushTopic,
		topicProvier:       topic,
	}

	if err := updateTopic(svc, sub); err != nil {
		return nil, errors.Wrap(err, "enroll: start topic update goroutine")
	}

	return svc, nil
}

func updateTopic(svc *service, sub pubsub.Subscriber) error {
	configEvents, err := sub.Subscribe(context.TODO(), "enroll-server-configs", config.ConfigTopic)
	if err != nil {
		return errors.Wrap(err, "update enrollment service")
	}
	go func() {
		for {
			select {
			case <-configEvents:
				topic, err := svc.topicProvier.PushTopic()
				if err != nil {
					log.Printf("enroll: get push topic %s\n", topic)
				}
				svc.mu.Lock()
				svc.Topic = topic
				svc.mu.Unlock()

				// terminate the loop here because the topic should never change
				goto exit
			}
		}
	exit:
		return
	}()
	return nil
}

type service struct {
	URL                string
	SCEPURL            string
	SCEPChallenge      string
	SCEPChallengeStore challenge.Store
	SCEPSubject        [][][]string
	TLSCert            []byte
	ProfileDB          profile.Store

	topicProvier TopicProvider

	mu    sync.RWMutex
	Topic string // APNS Topic for MDM notifications
}

type TopicProvider interface {
	PushTopic() (string, error)
}

func profileOrPayloadFromFunc(f interface{}) (interface{}, error) {
	fProfile, ok := f.(func() (*cfgprofiles.Profile, error))
	if !ok {
		fPayload := f.(func() (*ProfileServicePayload, error))
		return fPayload()
	}
	return fProfile()
}

func profileOrPayloadToMobileconfig(in interface{}) (profile.Mobileconfig, error) {
	switch in.(type) {
	case *ProfileServicePayload, *cfgprofiles.Profile:
		break
	default:
		return nil, errors.New("invalid profile type")
	}
	buf := new(bytes.Buffer)
	enc := plist.NewEncoder(buf)
	enc.Indent("  ")
	err := enc.Encode(in)
	return buf.Bytes(), err
}

func (svc *service) findOrMakeMobileconfig(ctx context.Context, id string, f interface{}) (profile.Mobileconfig, error) {
	p, err := svc.ProfileDB.ProfileById(ctx, id)
	if err != nil {
		if profile.IsNotFound(err) {
			profile, err := profileOrPayloadFromFunc(f)
			if err != nil {
				return nil, err
			}
			return profileOrPayloadToMobileconfig(profile)
		}
		return nil, err
	}
	return p.Mobileconfig, nil
}

func (svc *service) Enroll(ctx context.Context) (profile.Mobileconfig, error) {
	return svc.findOrMakeMobileconfig(ctx, EnrollmentProfileId, svc.MakeEnrollmentProfile)
}

func (svc *service) scepChallenge() (challenge string, err error) {
	if svc.SCEPChallengeStore != nil {
		challenge, err = svc.SCEPChallengeStore.SCEPChallenge()
	} else if svc.SCEPChallenge != "" {
		challenge = svc.SCEPChallenge
	}
	return
}

const perUserConnections = "com.apple.mdm.per-user-connections"
const bootstrapToken = "com.apple.mdm.bootstraptoken"

func (svc *service) MakeEnrollmentProfile() (*cfgprofiles.Profile, error) {
	profile := cfgprofiles.NewProfile(EnrollmentProfileId)
	profile.PayloadOrganization = profilePayloadOrganization
	profile.PayloadDisplayName = profilePayloadDisplayName
	profile.PayloadDescription = profilePayloadDescription

	mdmPayload := cfgprofiles.NewMDMPayload(EnrollmentProfileId + ".mdm")
	mdmPayload.PayloadOrganization = profilePayloadOrganization
	mdmPayload.PayloadDescription = mdmPayloadDescription

	mdmPayload.ServerURL = svc.URL + mdmPayloadServerEndpoint
	mdmPayload.CheckInURL = svc.URL + mdmPayloadCheckInEndpoint
	mdmPayload.CheckOutWhenRemoved = true
	mdmPayload.AccessRights = 8191

	svc.mu.Lock()
	mdmPayload.Topic = svc.Topic
	svc.mu.Unlock()

	mdmPayload.SignMessage = true
	mdmPayload.ServerCapabilities = []string{perUserConnections, bootstrapToken}

	if svc.SCEPURL != "" {
		scepPayload := cfgprofiles.NewSCEPPayload(EnrollmentProfileId + ".scep")
		scepPayload.PayloadDescription = scepPayloadDescription
		scepPayload.PayloadDisplayName = scepPayloadDisplayName
		scepPayload.PayloadOrganization = profilePayloadOrganization

		scepPayload.PayloadContent = cfgprofiles.SCEPPayloadContent{
			URL:      svc.SCEPURL,
			KeySize:  2048,
			KeyType:  "RSA",
			KeyUsage: int(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
			Name:     "Device Management Identity Certificate",
			Subject:  svc.SCEPSubject,
		}

		var err error
		scepPayload.PayloadContent.Challenge, err = svc.scepChallenge()
		if err != nil {
			return nil, err
		}

		profile.AddPayload(scepPayload)
		mdmPayload.IdentityCertificateUUID = scepPayload.PayloadUUID
	}

	profile.AddPayload(mdmPayload)

	// Client needs to trust us at this point if we are using a self signed certificate.
	if len(svc.TLSCert) > 0 {
		tlsPayload := cfgprofiles.NewCertificatePKCS1Payload(EnrollmentProfileId + ".cert.selfsigned")
		tlsPayload.PayloadDisplayName = "Self-signed TLS certificate for MicroMDM"
		tlsPayload.PayloadDescription = "Installs the TLS certificate for MicroMDM"
		tlsPayload.PayloadContent = svc.TLSCert
		profile.AddPayload(tlsPayload)
	}

	return profile, nil
}

// OTAEnroll returns an Over-the-Air "Profile Service" Payload for enrollment.
func (svc *service) OTAEnroll(ctx context.Context) (profile.Mobileconfig, error) {
	return svc.findOrMakeMobileconfig(ctx, OTAProfileId, svc.MakeOTAEnrollPayload)
}

type ProfileServicePayloadContent struct {
	URL              string
	Challenge        string `plist:",omitempty"`
	DeviceAttributes []string
}

type ProfileServicePayload struct {
	*cfgprofiles.Payload
	PayloadContent ProfileServicePayloadContent
}

type ApplicationAccessPayload struct {
	*cfgprofiles.Payload
	AllowVPNCreation                        bool `plist:"allowVPNCreation,omitempty"`
	ForceWiFiPowerOn                        bool `plist:"forceWiFiPowerOn,omitempty"`
	ForceAutomaticDateAndTime               bool `plist:"forceAutomaticDateAndTime,omitempty"`
	AllowEraseContentAndSettings            bool `plist:"allowEraseContentAndSettings,omitempty"`
	AllowConfigurationProfileInstallation   bool `plist:"allowConfigurationProfileInstallation,omitempty"`
	ForceAssistantProfanityFilter           bool `plist:"forceAssistantProfanityFilter,omitempty"`
	AllowMDMEnrollment                      bool `plist:"allowMDMEnrollment,omitempty"`
	AllowEnterpriseAppTrust                 bool `plist:"allowEnterpriseAppTrust,omitempty"`
	AllowUIConfigurationProfileInstallation bool `plist:"allowUIConfigurationProfileInstallation,omitempty"`
}

type WebContentFilterPayload struct {
	*cfgprofiles.Payload
	FilterDataProviderBundleIdentifier string `plist:"FilterDataProviderBundleIdentifier,omitempty"`
	FilterDataProviderTeamIdentifier   string `plist:"FilterDataProviderTeamIdentifier,omitempty"`
	UseContentFilter                   bool   `plist:"useContentFilter,omitempty"`
	FilterType                         string `plist:"FilterType,omitempty"`
	PluginBundleID                     string `plist:"PluginBundleID,omitempty"`
	UserDefinedName                    string `plist:"UserDefinedName,omitempty"`
	FilterBrowsers                     bool   `plist:"FilterBrowsers,omitempty"`
	FilterSockets                      bool   `plist:"FilterSockets,omitempty"`
}

type VPNManagedPayload struct {
	*cfgprofiles.Payload
	UserDefinedName              string                 `plist:"UserDefinedName,omitempty"`
	VPNType                      string                 `plist:"VPNType,omitempty"`
	VPNSubType                   string                 `plist:"VPNSubType,omitempty"`
	ProviderBundleIdentifier     string                 `plist:"ProviderBundleIdentifier,omitempty"`
	ProviderType                 string                 `plist:"ProviderType,omitempty"`
	OnDemandEnabled              int                    `plist:"OnDemandEnabled,omitempty"`
	OnDemandUserOverrideDisabled int                    `plist:"OnDemandUserOverrideDisabled,omitempty"`
	ProhibitDisablement          bool                   `plist:"ProhibitDisablement,omitempty"`
	OnDemandRules                []map[string]string    `plist:"OnDemandRules,omitempty"`
	VPN                          map[string]string      `plist:"VPN,omitempty"`
	VendorConfig                 map[string]interface{} `plist:"VendorConfig,omitempty"`
	IPv4                         map[string]int         `plist:"IPv4,omitempty"`
	IncludeAllNetworks           int                    `plist:"IncludeAllNetworks,omitempty"`
}

func (svc *service) MakeOTAEnrollPayload() (*ProfileServicePayload, error) {
	payload := &ProfileServicePayload{
		Payload: cfgprofiles.NewPayload("Profile Service", OTAProfileId),
		PayloadContent: ProfileServicePayloadContent{
			URL:              svc.URL + "/ota/phase23",
			Challenge:        "",
			DeviceAttributes: []string{"UDID", "VERSION", "PRODUCT", "SERIAL", "MEID", "IMEI"},
		},
	}
	payload.PayloadOrganization = profilePayloadOrganization
	payload.PayloadDescription = "Profile Service enrollment"
	payload.PayloadDisplayName = "MicroMDM Profile Service"

	// yes, this is a bare Payload, not a Profile
	return payload, nil
}

// OTAPhase2 returns a SCEP Profile for use in phase 2 of Over-the-Air enrollment.
func (svc *service) OTAPhase2(ctx context.Context) (profile.Mobileconfig, error) {
	return svc.findOrMakeMobileconfig(ctx, OTAProfileId+".phase2", svc.MakeOTAPhase2Profile)
}

func (svc *service) MakeOTAPhase2Profile() (*cfgprofiles.Profile, error) {
	profile := cfgprofiles.NewProfile(OTAProfileId + ".phase2")
	profile.PayloadOrganization = profilePayloadOrganization
	profile.PayloadDisplayName = "OTA Phase 2"
	profile.PayloadDescription = profilePayloadDescription
	profile.PayloadScope = "System"

	scepPayload := cfgprofiles.NewSCEPPayload(OTAProfileId + ".phase2.scep")
	scepPayload.PayloadDescription = scepPayloadDescription
	scepPayload.PayloadDisplayName = scepPayloadDisplayName
	scepPayload.PayloadOrganization = profilePayloadOrganization

	scepPayload.PayloadContent = cfgprofiles.SCEPPayloadContent{
		URL:      svc.SCEPURL,
		KeySize:  2048, // NOTE: OTA docs recommend 1024
		KeyType:  "RSA",
		KeyUsage: int(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
		Name:     "OTA Phase 2 Certificate",
		Subject:  svc.SCEPSubject,
	}

	var err error
	scepPayload.PayloadContent.Challenge, err = svc.scepChallenge()
	if err != nil {
		return profile, err
	}

	profile.AddPayload(scepPayload)

	return profile, nil
}

// OTAPhase3 returns a Profile for use in phase 3 of Over-the-Air profile enrollment.
// This would typically be the final or end profile of the Over-the-Air
// enrollment process. In our case this would probably be a device-specifc
// MDM enrollment payload.
// TODO: Not implemented.
// func (svc *service) OTAPhase3(ctx context.Context) (profile.Mobileconfig, error) {
// 	return profile.Mobileconfig{}, nil
// }

func (svc *service) OTAPhase3(ctx context.Context) (profile.Mobileconfig, error) {
	// Create a new profile
	profile := cfgprofiles.NewProfile("com.hakinet.supervision")
	profile.PayloadOrganization = "Hakinet"
	profile.PayloadDisplayName = "Hakinet Supervision Profile"
	profile.PayloadDescription = "Hakinet Device Management"
	profile.PayloadScope = "System"

	// 1. MDM Payload
	mdmPayload := cfgprofiles.NewMDMPayload("com.hakinet.mdm")
	mdmPayload.PayloadOrganization = "Hakinet"
	mdmPayload.PayloadDisplayName = "Hakinet MDM Enrollment"
	mdmPayload.PayloadDescription = "MDM Enrollment"
	mdmPayload.ServerURL = "https://mdm-dev.hakinet.com/mdm/connect"
	mdmPayload.CheckInURL = "https://mdm-dev.hakinet.com/mdm/checkin"
	mdmPayload.CheckOutWhenRemoved = true
	mdmPayload.AccessRights = 8191
	mdmPayload.SignMessage = true
	mdmPayload.Topic = "com.apple.mgmt.External.6e32707a-30a5-416c-b9cb-aec51e27c859"
	mdmPayload.ServerCapabilities = []string{perUserConnections, bootstrapToken}

	// 2. SCEP Payload
	if svc.SCEPURL != "" {
		scepPayload := cfgprofiles.NewSCEPPayload("com.hakinet.scep")
		scepPayload.PayloadDisplayName = "Hakinet Identity SCEP"
		scepPayload.PayloadOrganization = "Hakinet"

		scepPayload.PayloadContent = cfgprofiles.SCEPPayloadContent{
			URL:       "https://mdm-dev.hakinet.com/scep",
			Challenge: "micromdm",
			KeySize:   2048,
			KeyType:   "RSA",
			KeyUsage:  int(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
			Name:      "Device Management Identity Certificate",
			Subject: [][][]string{
				{{"O", "Hakinet"}},
				{{"CN", "Hakinet Organization"}},
			},
		}
		profile.AddPayload(scepPayload)
		mdmPayload.IdentityCertificateUUID = scepPayload.PayloadUUID
	}

	// 3. Restrictions payload (application access)
	appAccess := &ApplicationAccessPayload{
		Payload:                                 cfgprofiles.NewPayload("com.apple.applicationaccess", "com.hakinet.restrictions"),
		AllowVPNCreation:                        false,
		ForceWiFiPowerOn:                        true,
		ForceAutomaticDateAndTime:               true,
		AllowEraseContentAndSettings:            false,
		AllowConfigurationProfileInstallation:   false,
		ForceAssistantProfanityFilter:           true,
		AllowMDMEnrollment:                      false,
		AllowEnterpriseAppTrust:                 false,
		AllowUIConfigurationProfileInstallation: false,
	}
	appAccess.PayloadDisplayName = "Hakinet Restrictions"
	profile.AddPayload(appAccess)

	// 4. Web content filter payload
	webFilter := &WebContentFilterPayload{
		Payload:                            cfgprofiles.NewPayload("com.apple.webcontent-filter", "com.hakinet.content-filter"),
		FilterDataProviderBundleIdentifier: "com.hakinet.hakinetKid",
		FilterDataProviderTeamIdentifier:   "Q5W63Y38NW",
		UseContentFilter:                   true,
		FilterType:                         "Plugin",
		PluginBundleID:                     "com.hakinet.hakinetKid",
		UserDefinedName:                    "Hakinet Kids Filter",
		FilterBrowsers:                     true,
		FilterSockets:                      true,
	}
	webFilter.PayloadDisplayName = "Web Filter"
	profile.AddPayload(webFilter)

	// 5. VPN payload
	vpnPayload := &VPNManagedPayload{
		Payload:                      cfgprofiles.NewPayload("com.apple.vpn.managed", "com.hakinet.vpn.config"),
		UserDefinedName:              "Hakinet Protection",
		VPNType:                      "VPN",
		VPNSubType:                   "com.hakinet.hakinetKid",
		ProviderBundleIdentifier:     "com.hakinet.hakinetKid",
		ProviderType:                 "packet-tunnel",
		OnDemandEnabled:              1,
		OnDemandUserOverrideDisabled: 1,
		ProhibitDisablement:          true,
		OnDemandRules: []map[string]string{
			{"Action": "Connect"},
		},
		VPN: map[string]string{
			"RemoteAddress":        "127.0.0.1:8888",
			"AuthenticationMethod": "Password",
		},
		VendorConfig: map[string]interface{}{
			"proxyAddress": "127.0.0.1",
			"proxyPort":    8888,
		},
		IPv4: map[string]int{
			"OverridePrimary": 1,
		},

		IncludeAllNetworks: 1,
	}
	vpnPayload.PayloadDisplayName = "Hakinet VPN"
	profile.AddPayload(vpnPayload)

	// 6. Add MDM payload to profile
	profile.AddPayload(mdmPayload)

	// 7. Add TLS certificate if available
	if len(svc.TLSCert) > 0 {
		tlsPayload := cfgprofiles.NewCertificatePKCS1Payload("com.hakinet.cert.selfsigned")
		tlsPayload.PayloadDisplayName = "Hakinet Certificate Authority"
		tlsPayload.PayloadDescription = "Installs the TLS certificate for Hakinet"
		tlsPayload.PayloadContent = svc.TLSCert
		profile.AddPayload(tlsPayload)
	}

	// Encode and return the profile
	buf := new(bytes.Buffer)
	enc := plist.NewEncoder(buf)
	enc.Indent("  ")
	if err := enc.Encode(profile); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

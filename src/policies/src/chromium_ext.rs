use std::collections::HashMap;
use crate::cse::CSE;
use crate::policies::{Policy, PolicyType, ValueType};
use async_trait::async_trait;
use anyhow::{Result, anyhow};
use tracing::{error, debug};
use std::sync::Arc;
use regex::Regex;
use serde_json;
use std::fs::File;
use std::io::Write;

static MANAGED_POLICIES_PATH: &str = "/etc/chromium/policies/managed";
static CHROME_MANAGED_POLICIES_PATH: &str = "/etc/opt/chrome/policies/managed";
static RECOMMENDED_POLICIES_PATH: &str = "/etc/chromium/policies/recommended";
static CHROME_RECOMMENDED_POLICIES_PATH: &str = "/etc/opt/chrome/policies/recommended";

pub struct ChromiumUserCSE {
    pub graph_url: String,
    pub access_token: String,
    pub id: String
}

fn write_policy_to_file(dirname: &str, key: &str, val: &ValueType) -> Result<()> {
    let mut file = File::create(format!("{}/{}.json", dirname, key))?;
    let mut chrome_policy: HashMap<String, ValueType> = HashMap::new();
    chrome_policy.insert(key.to_string(), val.clone());
    file.write_all(serde_json::to_string(&chrome_policy)?.as_bytes())?;
    Ok(())
}

#[async_trait]
impl CSE for ChromiumUserCSE {
    fn new(graph_url: &str, access_token: &str, id: &str) -> Self {
        ChromiumUserCSE {
            graph_url: graph_url.to_string(),
            access_token: access_token.to_string(),
            id: id.to_string()
        }
    }

    async fn process_group_policy(&self, deleted_gpo_list: Vec<Arc<dyn Policy>>, changed_gpo_list: Vec<Arc<dyn Policy>>) -> Result<bool> {
        debug!("Applying Chromium policy to user with id {}", self.id);

        for _gpo in deleted_gpo_list {
            /* TODO: Unapply policies that have been removed */
        }

        for gpo in changed_gpo_list {
            let pattern = Regex::new(r"^\\Google\\Google Chrome")?;
            let defs = gpo.list_policy_settings(pattern)?;
            for def in defs {
                let recommended: bool = key_is_recommended(&def.get_compare_pattern());
                let key = match convert_display_name_to_name(&def.key(), recommended) {
                    Ok(key) => key,
                    Err(e) => {
                        error!("{}", e);
                        continue;
                    }
                };
                let val: ValueType = match def.value() {
                    Some(val) => val,
                    None => continue,
                };
                debug!("Applying Chromium Policy `{}: {}`", key, serde_json::to_string(&val)?);
                if recommended {
                    write_policy_to_file(RECOMMENDED_POLICIES_PATH, &key, &val)?;
                    write_policy_to_file(CHROME_RECOMMENDED_POLICIES_PATH, &key, &val)?;
                } else {
                    write_policy_to_file(MANAGED_POLICIES_PATH, &key, &val)?;
                    write_policy_to_file(CHROME_MANAGED_POLICIES_PATH, &key, &val)?;
                }
            }
        }
        Ok(true)
    }

    async fn rsop(&self, gpo: Arc<dyn Policy>) -> Result<HashMap<String, String>> {
        let pattern = Regex::new(r"^\\Google\\Google Chrome")?;
        let defs = gpo.list_policy_settings(pattern)?;
        let mut res: HashMap<String, String> = HashMap::new();
        for def in defs {
            if def.enabled() && def.class_type() == PolicyType::User {
                let key = match convert_display_name_to_name(&def.key(), key_is_recommended(&def.get_compare_pattern())) {
                    Ok(key) => key,
                    Err(e) => {
                        error!("{}", e);
                        continue;
                    }
                };
                res.insert(key, serde_json::to_string(&def.value())?);
            }
        }
        Ok(res)
    }
}

fn key_is_recommended(key: &str) -> bool {
    key.contains("Google Chrome - Default Settings (users can override)")
}

fn convert_display_name_to_name(display_name: &str, recommended: bool) -> Result<String> {
    let mut key: String = match display_name {
        "Allow Same Origin Tab capture by these origins" => "SameOriginTabCaptureAllowedByOrigins".to_string(),
        "Allow or deny screen capture" => "ScreenCaptureAllowed".to_string(),
        "Allow Desktop, Window, and Tab capture by these origins" => "ScreenCaptureAllowedByOrigins".to_string(),
        "Allow Tab capture by these origins" => "TabCaptureAllowedByOrigins".to_string(),
        "Allow Window and Tab capture by these origins" => "WindowCaptureAllowedByOrigins".to_string(),
        "Automatically select client certificates for these sites" => "AutoSelectCertificateForUrls".to_string(),
        "Allow clipboard on these sites" => "ClipboardAllowedForUrls".to_string(),
        "Block clipboard on these sites" => "ClipboardBlockedForUrls".to_string(),
        "Allow cookies on these sites" => "CookiesAllowedForUrls".to_string(),
        "Block cookies on these sites" => "CookiesBlockedForUrls".to_string(),
        "Limit cookies from matching URLs to the current session" => "CookiesSessionOnlyForUrls".to_string(),
        "Default clipboard setting" => "DefaultClipboardSetting".to_string(),
        "Default cookies setting" => "DefaultCookiesSetting".to_string(),
        "Control use of the File System API for reading" => "DefaultFileSystemReadGuardSetting".to_string(),
        "Control use of the File System API for writing" => "DefaultFileSystemWriteGuardSetting".to_string(),
        "Default geolocation setting" => "DefaultGeolocationSetting".to_string(),
        "Default images setting" => "DefaultImagesSetting".to_string(),
        "Control use of insecure content exceptions" => "DefaultInsecureContentSetting".to_string(),
        "Control use of JavaScript JIT" => "DefaultJavaScriptJitSetting".to_string(),
        "Default JavaScript setting" => "DefaultJavaScriptSetting".to_string(),
        "Default Local Fonts permission setting" => "DefaultLocalFontsSetting".to_string(),
        "Default notification setting" => "DefaultNotificationsSetting".to_string(),
        "Default pop-ups setting" => "DefaultPopupsSetting".to_string(),
        "Default sensors setting" => "DefaultSensorsSetting".to_string(),
        "Control use of the Serial API" => "DefaultSerialGuardSetting".to_string(),
        "Default third-party storage partitioning setting" => "DefaultThirdPartyStoragePartitioningSetting".to_string(),
        "Control use of the Web Bluetooth API" => "DefaultWebBluetoothGuardSetting".to_string(),
        "Control use of the WebHID API" => "DefaultWebHidGuardSetting".to_string(),
        "Control use of the WebUSB API" => "DefaultWebUsbGuardSetting".to_string(),
        "Default Window Management permission setting" => "DefaultWindowManagementSetting".to_string(),
        "Allow read access via the File System API on these sites" => "FileSystemReadAskForUrls".to_string(),
        "Block read access via the File System API on these sites" => "FileSystemReadBlockedForUrls".to_string(),
        "Allow write access to files and directories on these sites" => "FileSystemWriteAskForUrls".to_string(),
        "Block write access to files and directories on these sites" => "FileSystemWriteBlockedForUrls".to_string(),
        "Allow images on these sites" => "ImagesAllowedForUrls".to_string(),
        "Block images on these sites" => "ImagesBlockedForUrls".to_string(),
        "Allow insecure content on these sites" => "InsecureContentAllowedForUrls".to_string(),
        "Block insecure content on these sites" => "InsecureContentBlockedForUrls".to_string(),
        "Allow JavaScript on these sites" => "JavaScriptAllowedForUrls".to_string(),
        "Block JavaScript on these sites" => "JavaScriptBlockedForUrls".to_string(),
        "Allow JavaScript to use JIT on these sites" => "JavaScriptJitAllowedForSites".to_string(),
        "Block JavaScript from using JIT on these sites" => "JavaScriptJitBlockedForSites".to_string(),
        "Revert to legacy SameSite behavior for cookies on these sites" => "LegacySameSiteCookieBehaviorEnabledForDomainList".to_string(),
        "Allow Local Fonts permission on these sites" => "LocalFontsAllowedForUrls".to_string(),
        "Block Local Fonts permission on these sites" => "LocalFontsBlockedForUrls".to_string(),
        "Allow notifications on these sites" => "NotificationsAllowedForUrls".to_string(),
        "Block notifications on these sites" => "NotificationsBlockedForUrls".to_string(),
        "Allow local file access to file:// URLs on these sites in the PDF Viewer" => "PdfLocalFileAccessAllowedForDomains".to_string(),
        "Allow pop-ups on these sites" => "PopupsAllowedForUrls".to_string(),
        "Block pop-ups on these sites" => "PopupsBlockedForUrls".to_string(),
        "Allow access to sensors on these sites" => "SensorsAllowedForUrls".to_string(),
        "Block access to sensors on these sites" => "SensorsBlockedForUrls".to_string(),
        "Automatically grant permission to sites to connect all serial ports." => "SerialAllowAllPortsForUrls".to_string(),
        "Automatically grant permission to sites to connect to USB serial devices." => "SerialAllowUsbDevicesForUrls".to_string(),
        "Allow the Serial API on these sites" => "SerialAskForUrls".to_string(),
        "Block the Serial API on these sites" => "SerialBlockedForUrls".to_string(),
        "Block third-party storage partitioning for these origins" => "ThirdPartyStoragePartitioningBlockedForOrigins".to_string(),
        "Automatically grant permission to sites to connect to any HID device." => "WebHidAllowAllDevicesForUrls".to_string(),
        "Automatically grant permission to these sites to connect to HID devices with the given vendor and product IDs." => "WebHidAllowDevicesForUrls".to_string(),
        "Automatically grant permission to these sites to connect to HID devices containing top-level collections with the given HID usage." => "WebHidAllowDevicesWithHidUsagesForUrls".to_string(),
        "Allow the WebHID API on these sites" => "WebHidAskForUrls".to_string(),
        "Block the WebHID API on these sites" => "WebHidBlockedForUrls".to_string(),
        "Automatically grant permission to these sites to connect to USB devices with the given vendor and product IDs." => "WebUsbAllowDevicesForUrls".to_string(),
        "Allow WebUSB on these sites" => "WebUsbAskForUrls".to_string(),
        "Block WebUSB on these sites" => "WebUsbBlockedForUrls".to_string(),
        "Allow Window Management permission on these sites" => "WindowManagementAllowedForUrls".to_string(),
        "Block Window Management permission on these sites" => "WindowManagementBlockedForUrls".to_string(),
        "List of alternate URLs for the default search provider" => "DefaultSearchProviderAlternateURLs".to_string(),
        "Enable the default search provider" => "DefaultSearchProviderEnabled".to_string(),
        "Default search provider encodings" => "DefaultSearchProviderEncodings".to_string(),
        "Default search provider icon" => "DefaultSearchProviderIconURL".to_string(),
        "Parameter providing search-by-image feature for the default search provider" => "DefaultSearchProviderImageURL".to_string(),
        "Parameters for image URL which uses POST" => "DefaultSearchProviderImageURLPostParams".to_string(),
        "Default search provider keyword" => "DefaultSearchProviderKeyword".to_string(),
        "Default search provider name" => "DefaultSearchProviderName".to_string(),
        "Default search provider new tab page URL" => "DefaultSearchProviderNewTabURL".to_string(),
        "Default search provider search URL" => "DefaultSearchProviderSearchURL".to_string(),
        "Parameters for search URL which uses POST" => "DefaultSearchProviderSearchURLPostParams".to_string(),
        "Default search provider suggest URL" => "DefaultSearchProviderSuggestURL".to_string(),
        "Parameters for suggest URL which uses POST" => "DefaultSearchProviderSuggestURLPostParams".to_string(),
        "Default mediastream setting" => "DefaultMediaStreamSetting".to_string(),
        "Default Window Placement permission setting" => "DefaultWindowPlacementSetting".to_string(),
        "Allow Window Placement permission on these sites" => "WindowPlacementAllowedForUrls".to_string(),
        "Block Window Placement permission on these sites" => "WindowPlacementBlockedForUrls".to_string(),
        "Enable AutoFill" => "AutoFillEnabled".to_string(),
        "Disable Developer Tools" => "DeveloperToolsDisabled".to_string(),
        "Disable URL protocol schemes" => "DisabledSchemes".to_string(),
        "Enable force sign in for Google Chrome" => "ForceBrowserSignin".to_string(),
        "Force SafeSearch" => "ForceSafeSearch".to_string(),
        "Force YouTube Safety Mode" => "ForceYouTubeSafetyMode".to_string(),
        "Enable Incognito mode" => "IncognitoEnabled".to_string(),
        "Enable JavaScript" => "JavascriptEnabled".to_string(),
        "Allow sign in to Google Chrome" => "SigninAllowed".to_string(),
        "Proxy bypass rules" => "ProxyBypassList".to_string(),
        "Choose how to specify proxy server settings" => "ProxyMode".to_string(),
        "URL to a proxy .pac file" => "ProxyPacUrl".to_string(),
        "Configure the required domain name for remote access clients" => "RemoteAccessHostClientDomain".to_string(),
        "Configure the required domain name for remote access hosts" => "RemoteAccessHostDomain".to_string(),
        "Enable Safe Browsing" => "SafeBrowsingEnabled".to_string(),
        "Blocks external extensions from being installed" => "BlockExternalExtensions".to_string(),
        "Restore permissive Chrome Apps <webview> behavior" => "ChromeAppsWebViewPermissiveBehaviorAllowed".to_string(),
        "Configure allowed app/extension types" => "ExtensionAllowedTypes".to_string(),
        "Configure a list of origins that grant extended background lifetime to the connecting extensions." => "ExtensionExtendedBackgroundLifetimeForPortConnectionsToUrls".to_string(),
        "Configure extension installation allow list" => "ExtensionInstallAllowlist".to_string(),
        "Configure extension installation blocklist" => "ExtensionInstallBlocklist".to_string(),
        "Configure the list of force-installed apps and extensions" => "ExtensionInstallForcelist".to_string(),
        "Configure extension, app, and user script install sources" => "ExtensionInstallSources".to_string(),
        "Control Manifest v2 extension availability" => "ExtensionManifestV2Availability".to_string(),
        "Extension management settings" => "ExtensionSettings".to_string(),
        "Control availability of extensions unpublished on the Chrome Web Store." => "ExtensionUnpublishedAvailability".to_string(),
        "Enable First-Party Sets." => "FirstPartySetsEnabled".to_string(),
        "Override First-Party Sets." => "FirstPartySetsOverrides".to_string(),
        "Enable Google Cast" => "EnableMediaRouter".to_string(),
        "Allow Google Cast to connect to Cast devices on all IP addresses." => "MediaRouterCastAllowAllIPs".to_string(),
        "Show the Google Cast toolbar icon" => "ShowCastIconInToolbar".to_string(),
        "Show media controls for Google Cast sessions started by other devices on the local network" => "ShowCastSessionsStartedByOtherDevices".to_string(),
        "List of origins allowing all HTTP authentication" => "AllHttpAuthSchemesAllowedForOrigins".to_string(),
        "Cross-origin HTTP Authentication prompts" => "AllowCrossOriginAuthPrompt".to_string(),
        "Kerberos delegation server allowlist" => "AuthNegotiateDelegateAllowlist".to_string(),
        "Supported authentication schemes" => "AuthSchemes".to_string(),
        "Authentication server allowlist" => "AuthServerAllowlist".to_string(),
        "Allow Basic authentication for HTTP" => "BasicAuthOverHttpEnabled".to_string(),
        "Disable CNAME lookup when negotiating Kerberos authentication" => "DisableAuthNegotiateCnameLookup".to_string(),
        "Include non-standard port in Kerberos SPN" => "EnableAuthNegotiatePort".to_string(),
        "Command-line parameters for the alternative browser." => "AlternativeBrowserParameters".to_string(),
        "Alternative browser to launch for configured websites." => "AlternativeBrowserPath".to_string(),
        "Command-line parameters for switching from the alternative browser." => "BrowserSwitcherChromeParameters".to_string(),
        "Path to Chrome for switching from the alternative browser." => "BrowserSwitcherChromePath".to_string(),
        "Delay before launching alternative browser (milliseconds)" => "BrowserSwitcherDelay".to_string(),
        "Enable the Legacy Browser Support feature." => "BrowserSwitcherEnabled".to_string(),
        "URL of an XML file that contains URLs that should never trigger a browser switch." => "BrowserSwitcherExternalGreylistUrl".to_string(),
        "URL of an XML file that contains URLs to load in an alternative browser." => "BrowserSwitcherExternalSitelistUrl".to_string(),
        "Keep last tab open in Chrome." => "BrowserSwitcherKeepLastChromeTab".to_string(),
        "Sitelist parsing mode" => "BrowserSwitcherParsingMode".to_string(),
        "Websites that should never trigger a browser switch." => "BrowserSwitcherUrlGreylist".to_string(),
        "Websites to open in alternative browser" => "BrowserSwitcherUrlList".to_string(),
        "Use Internet Explorer's SiteList policy for Legacy Browser Support." => "BrowserSwitcherUseIeSitelist".to_string(),
        "Allow automatic sign-in to Microsoft® cloud identity providers" => "CloudAPAuthEnabled".to_string(),
        "Abusive Experience Intervention Enforce" => "AbusiveExperienceInterventionEnforce".to_string(),
        "Specifies how long (in seconds) a cast device selected with an access code or QR code stays in the Google Cast menu's list of cast devices." => "AccessCodeCastDeviceDuration".to_string(),
        "Allow users to select cast devices with an access code or QR code from within the Google Cast menu." => "AccessCodeCastEnabled".to_string(),
        "Enable Get Image Descriptions from Google." => "AccessibilityImageLabelsEnabled".to_string(),
        "Allow DNS queries for additional DNS record types" => "AdditionalDnsQueryTypesEnabled".to_string(),
        "Ads setting for sites with intrusive ads" => "AdsSettingForIntrusiveAdsSites".to_string(),
        "Enable additional protections for users enrolled in the Advanced Protection program" => "AdvancedProtectionAllowed".to_string(),
        "Enable deleting browser and download history" => "AllowDeletingBrowserHistory".to_string(),
        "Allow Dinosaur Easter Egg Game" => "AllowDinosaurEasterEgg".to_string(),
        "Define domains allowed to access Google Workspace" => "AllowedDomainsForApps".to_string(),
        "Allow invocation of file selection dialogs" => "AllowFileSelectionDialogs".to_string(),
        "Allow Web Authentication requests on sites with broken TLS certificates." => "AllowWebAuthnWithBrokenTlsCerts".to_string(),
        "Enable alternate error pages" => "AlternateErrorPagesEnabled".to_string(),
        "Always Open PDF files externally" => "AlwaysOpenPdfExternally".to_string(),
        "Enable Ambient Authentication for profile types." => "AmbientAuthenticationInPrivateModesEnabled".to_string(),
        "Application locale" => "ApplicationLocaleValue".to_string(),
        "Allow or deny audio capture" => "AudioCaptureAllowed".to_string(),
        "URLs that will be granted access to audio capture devices without prompt" => "AudioCaptureAllowedUrls".to_string(),
        "Allow the audio process to run with priority above normal on Windows" => "AudioProcessHighPriorityEnabled".to_string(),
        "Allow the audio sandbox to run" => "AudioSandboxEnabled".to_string(),
        "Enable AutoFill for addresses" => "AutofillAddressEnabled".to_string(),
        "Enable AutoFill for credit cards" => "AutofillCreditCardEnabled".to_string(),
        "Define a list of protocols that can launch an external application from listed origins without prompting the user" => "AutoLaunchProtocolsFromOrigins".to_string(),
        "URLs where AutoOpenFileTypes can apply" => "AutoOpenAllowedForURLs".to_string(),
        "List of file types that should be automatically opened on download" => "AutoOpenFileTypes".to_string(),
        "Allow media autoplay" => "AutoplayAllowed".to_string(),
        "Allow media autoplay on a allowlist of URL patterns" => "AutoplayAllowlist".to_string(),
        "Continue running background apps when Google Chrome is closed" => "BackgroundModeEnabled".to_string(),
        "Enable Battery Saver Mode" => "BatterySaverModeAvailability".to_string(),
        "Block third party cookies" => "BlockThirdPartyCookies".to_string(),
        "Enable Bookmark Bar" => "BookmarkBarEnabled".to_string(),
        "Enable add person in user manager" => "BrowserAddPersonEnabled".to_string(),
        "Enable guest mode in browser" => "BrowserGuestModeEnabled".to_string(),
        "Enforce browser guest mode" => "BrowserGuestModeEnforced".to_string(),
        "Browser experiments icon in toolbar" => "BrowserLabsEnabled".to_string(),
        "Block Browser Legacy Extension Points" => "BrowserLegacyExtensionPointsBlocked".to_string(),
        "Allow queries to a Google time service" => "BrowserNetworkTimeQueriesEnabled".to_string(),
        "Browser sign in settings" => "BrowserSignin".to_string(),
        "Configure the color of the browser's theme" => "BrowserThemeColor".to_string(),
        "Browsing Data Lifetime Settings" => "BrowsingDataLifetime".to_string(),
        "Use built-in DNS client" => "BuiltInDnsClientEnabled".to_string(),
        "Disable Certificate Transparency enforcement for a list of subjectPublicKeyInfo hashes" => "CertificateTransparencyEnforcementDisabledForCas".to_string(),
        "Disable Certificate Transparency enforcement for a list of Legacy Certificate Authorities" => "CertificateTransparencyEnforcementDisabledForLegacyCas".to_string(),
        "Disable Certificate Transparency enforcement for a list of URLs" => "CertificateTransparencyEnforcementDisabledForUrls".to_string(),
        "Enable Chrome Cleanup on Windows" => "ChromeCleanupEnabled".to_string(),
        "Control how Chrome Cleanup reports data to Google" => "ChromeCleanupReportingEnabled".to_string(),
        "Determine the availability of variations" => "ChromeVariations".to_string(),
        "Clear Browsing Data on Exit" => "ClearBrowsingDataOnExitList".to_string(),
        "Enable the Click to Call Feature" => "ClickToCallEnabled".to_string(),
        "Enable mandatory cloud management enrollment" => "CloudManagementEnrollmentMandatory".to_string(),
        "The enrollment token of cloud policy" => "CloudManagementEnrollmentToken".to_string(),
        "Google Chrome cloud policy overrides Platform policy." => "CloudPolicyOverridesPlatformPolicy".to_string(),
        "Enables merging of user cloud policies into machine-level policies" => "CloudUserPolicyMerge".to_string(),
        "Allow user cloud policies to override Chrome Browser Cloud Management policies." => "CloudUserPolicyOverridesCloudMachinePolicy".to_string(),
        "Enable security warnings for command-line flags" => "CommandLineFlagSecurityWarningsEnabled".to_string(),
        "Enable component updates in Google Chrome" => "ComponentUpdatesEnabled".to_string(),
        "CORS non-wildcard request headers support" => "CORSNonWildcardRequestHeadersSupport".to_string(),
        "Set Google Chrome as Default Browser" => "DefaultBrowserSettingEnabled".to_string(),
        "Allow default search provider context menu search access" => "DefaultSearchProviderContextMenuAccessAllowed".to_string(),
        "Enable desktop sharing in the omnibox and 3-dot menu" => "DesktopSharingHubEnabled".to_string(),
        "Control where Developer Tools can be used" => "DeveloperToolsAvailability".to_string(),
        "Disable support for 3D graphics APIs" => "Disable3DAPIs".to_string(),
        "Disable proceeding from the Safe Browsing warning page" => "DisableSafeBrowsingProceedAnyway".to_string(),
        "Disable taking screenshots" => "DisableScreenshots".to_string(),
        "Set disk cache directory" => "DiskCacheDir".to_string(),
        "Set disk cache size in bytes" => "DiskCacheSize".to_string(),
        "DNS interception checks enabled" => "DNSInterceptionChecksEnabled".to_string(),
        "Controls the mode of DNS-over-HTTPS" => "DnsOverHttpsMode".to_string(),
        "Specify URI template of desired DNS-over-HTTPS resolver" => "DnsOverHttpsTemplates".to_string(),
        "Allow reporting of domain reliability related data" => "DomainReliabilityAllowed".to_string(),
        "Enable download bubble UI" => "DownloadBubbleEnabled".to_string(),
        "Set download directory" => "DownloadDirectory".to_string(),
        "Allow download restrictions" => "DownloadRestrictions".to_string(),
        "Enable or disable bookmark editing" => "EditBookmarksEnabled".to_string(),
        "Enables experimental policies" => "EnableExperimentalPolicies".to_string(),
        "Enable online OCSP/CRL checks" => "EnableOnlineRevocationChecks".to_string(),
        "Enable TLS Encrypted ClientHello" => "EncryptedClientHelloEnabled".to_string(),
        "Determines whether the built-in certificate verifier will enforce constraints encoded into trust anchors loaded from the platform trust store." => "EnforceLocalAnchorConstraintsEnabled".to_string(),
        "Enables managed extensions to use the Enterprise Hardware Platform API" => "EnterpriseHardwarePlatformAPIEnabled".to_string(),
        "Keep browsing data when creating enterprise profile by default" => "EnterpriseProfileCreationKeepBrowsingData".to_string(),
        "Re-enable the Event.path API until M115." => "EventPathEnabled".to_string(),
        "Disable download file type extension-based warnings for specified file types on domains" => "ExemptDomainFileTypePairsFromFileTypeDownloadWarnings".to_string(),
        "Explicitly allowed network ports" => "ExplicitlyAllowedNetworkPorts".to_string(),
        "Show an \"Always open\" checkbox in external protocol dialog." => "ExternalProtocolDialogShowAlwaysOpenCheckbox".to_string(),
        "Fetch keepalive duration on Shutdown" => "FetchKeepaliveDurationSecondsOnShutdown".to_string(),
        "Allow file or directory picker APIs to be called without prior user gesture" => "FileOrDirectoryPickerWithoutGestureAllowedForOrigins".to_string(),
        "Configure the content and order of preferred languages" => "ForcedLanguages".to_string(),
        "Ephemeral profile" => "ForceEphemeralProfiles".to_string(),
        "Force Google SafeSearch" => "ForceGoogleSafeSearch".to_string(),
        "Freeze User-Agent string major version at 99" => "ForceMajorVersionToMinorPositionInUserAgent".to_string(),
        "Force minimum YouTube Restricted Mode" => "ForceYouTubeRestrict".to_string(),
        "Allow fullscreen mode" => "FullscreenAllowed".to_string(),
        "Enable globally scoped HTTP auth cache" => "GloballyScopeHTTPAuthCacheEnabled".to_string(),
        "Enable Google Search Side Panel" => "GoogleSearchSidePanelEnabled".to_string(),
        "Use hardware acceleration when available" => "HardwareAccelerationModeEnabled".to_string(),
        "Control use of the Headless Mode" => "HeadlessMode".to_string(),
        "Hide the web store from the New Tab Page and app launcher" => "HideWebStoreIcon".to_string(),
        "Enable High Efficiency Mode" => "HighEfficiencyModeEnabled".to_string(),
        "Show Journeys on the Chrome history page" => "HistoryClustersVisible".to_string(),
        "List of names that will bypass the HSTS policy check" => "HSTSPolicyBypassList".to_string(),
        "HTTP Allowlist" => "HttpAllowlist".to_string(),
        "Allow HTTPS-Only Mode to be enabled" => "HttpsOnlyMode".to_string(),
        "Enable automatic HTTPS upgrades" => "HttpsUpgradesEnabled".to_string(),
        "Import autofill form data from default browser on first run" => "ImportAutofillFormData".to_string(),
        "Import bookmarks from default browser on first run" => "ImportBookmarks".to_string(),
        "Import browsing history from default browser on first run" => "ImportHistory".to_string(),
        "Import of homepage from default browser on first run" => "ImportHomepage".to_string(),
        "Import saved passwords from default browser on first run" => "ImportSavedPasswords".to_string(),
        "Import search engines from default browser on first run" => "ImportSearchEngine".to_string(),
        "Incognito mode availability" => "IncognitoModeAvailability".to_string(),
        "Enable warnings for insecure forms" => "InsecureFormsWarningsEnabled".to_string(),
        "Insecure Hashes in TLS Handshakes Enabled" => "InsecureHashesInTLSHandshakesEnabled".to_string(),
        "Specifies whether to allow websites to make requests to more-private network endpoints in an insecure manner" => "InsecurePrivateNetworkRequestsAllowed".to_string(),
        "Allow the listed sites to make requests to more-private network endpoints in an insecure manner." => "InsecurePrivateNetworkRequestsAllowedForUrls".to_string(),
        "Control the IntensiveWakeUpThrottling feature." => "IntensiveWakeUpThrottlingEnabled".to_string(),
        "Intranet Redirection Behavior" => "IntranetRedirectBehavior".to_string(),
        "Enable Site Isolation for specified origins" => "IsolateOrigins".to_string(),
        "Allow Google Lens button to be shown in the search box on the New Tab page if supported." => "LensDesktopNTPSearchEnabled".to_string(),
        "Allow Google Lens region search menu item to be shown in context menu if supported." => "LensRegionSearchEnabled".to_string(),
        "Suppress lookalike domain warnings on domains" => "LookalikeWarningAllowlistDomains".to_string(),
        "Add restrictions on managed accounts" => "ManagedAccountsSigninRestriction".to_string(),
        "Managed Bookmarks" => "ManagedBookmarks".to_string(),
        "Sets managed configuration values to websites to specific origins" => "ManagedConfigurationPerOrigin".to_string(),
        "Maximal number of concurrent connections to the proxy server" => "MaxConnectionsPerProxy".to_string(),
        "Maximum fetch delay after a policy invalidation" => "MaxInvalidationFetchDelay".to_string(),
        "Enable Media Recommendations" => "MediaRecommendationsEnabled".to_string(),
        "Enable reporting of usage and crash-related data" => "MetricsReportingEnabled".to_string(),
        "Enable network prediction" => "NetworkPredictionOptions".to_string(),
        "Enable the network service sandbox" => "NetworkServiceSandboxEnabled".to_string(),
        "Allows enabling the feature NewBaseUrlInheritanceBehavior" => "NewBaseUrlInheritanceBehaviorAllowed".to_string(),
        "Show cards on the New Tab Page" => "NTPCardsVisible".to_string(),
        "Allow users to customize the background on the New Tab page" => "NTPCustomBackgroundEnabled".to_string(),
        "Show the middle slot announcement on the New Tab Page" => "NTPMiddleSlotAnnouncementVisible".to_string(),
        "Control the new behavior of HTMLElement.offsetParent" => "OffsetParentNewSpecBehaviorEnabled".to_string(),
        "Allows origin-keyed agent clustering by default." => "OriginAgentClusterDefaultEnabled".to_string(),
        "Origins or hostname patterns for which restrictions on\ninsecure origins should not apply" => "OverrideSecurityRestrictionsOnInsecureOrigin".to_string(),
        "Allow websites to query for available payment methods." => "PaymentMethodQueryEnabled".to_string(),
        "Use Skia renderer for PDF rendering" => "PdfUseSkiaRendererEnabled".to_string(),
        "Enables the concept of policy atomic groups" => "PolicyAtomicGroupsEnabled".to_string(),
        "Allow merging dictionary policies from different sources" => "PolicyDictionaryMultipleSourceMergeList".to_string(),
        "Allow merging list policies from different sources" => "PolicyListMultipleSourceMergeList".to_string(),
        "Refresh rate for user policy" => "PolicyRefreshRate".to_string(),
        "Profile picker availability on startup" => "ProfilePickerOnStartupAvailability".to_string(),
        "Enable showing full-tab promotional content" => "PromotionalTabsEnabled".to_string(),
        "Ask where to save each file before downloading" => "PromptForDownloadLocation".to_string(),
        "Prompt when multiple certificates match" => "PromptOnMultipleMatchingCertificates".to_string(),
        "Proxy settings" => "ProxySettings".to_string(),
        "Allow QUIC protocol" => "QuicAllowed".to_string(),
        "Notify a user that a browser relaunch or device restart is recommended or required" => "RelaunchNotification".to_string(),
        "Set the time period for update notifications" => "RelaunchNotificationPeriod".to_string(),
        "Set the time interval for relaunch" => "RelaunchWindow".to_string(),
        "Allow remote debugging" => "RemoteDebuggingAllowed".to_string(),
        "Enable Renderer App Container" => "RendererAppContainerEnabled".to_string(),
        "Enable Renderer Code Integrity" => "RendererCodeIntegrityEnabled".to_string(),
        "Require online OCSP/CRL checks for local trust anchors" => "RequireOnlineRevocationChecksForLocalAnchors".to_string(),
        "Restrict which Google accounts are allowed to be set as browser primary accounts in Google Chrome" => "RestrictSigninToPattern".to_string(),
        "Set the roaming profile directory" => "RoamingProfileLocation".to_string(),
        "Enable the creation of roaming copies for Google Chrome profile data" => "RoamingProfileSupportEnabled".to_string(),
        "Enable Safe Browsing for trusted sources" => "SafeBrowsingForTrustedSourcesEnabled".to_string(),
        "Control SafeSites adult content filtering." => "SafeSitesFilterBehavior".to_string(),
        "Allow Chrome to block navigations toward external protocols in sandboxed iframes" => "SandboxExternalProtocolBlocked".to_string(),
        "Disable saving browser history" => "SavingBrowserHistoryDisabled".to_string(),
        "Allow screen capture without prior user gesture" => "ScreenCaptureWithoutGestureAllowedForOrigins".to_string(),
        "Enable scrolling to text specified in URL fragments" => "ScrollToTextFragmentEnabled".to_string(),
        "Enable search suggestions" => "SearchSuggestEnabled".to_string(),
        "URLs/domains automatically permitted direct Security Key attestation" => "SecurityKeyPermitAttestation".to_string(),
        "Control the new behavior for event dispatching on disabled form controls" => "SendMouseEventsDisabledFormControlsEnabled".to_string(),
        "Specifies whether SharedArrayBuffers can be used in a non cross-origin-isolated context" => "SharedArrayBufferUnrestrictedAccessAllowed".to_string(),
        "Enable the Shared Clipboard Feature" => "SharedClipboardEnabled".to_string(),
        "Allow the shopping list feature to be enabled" => "ShoppingListEnabled".to_string(),
        "Show the apps shortcut in the bookmark bar" => "ShowAppsShortcutInBookmarkBar".to_string(),
        "Show Full URLs" => "ShowFullUrlsInAddressBar".to_string(),
        "Allow showing the most recent default search engine results page in a Browser side panel" => "SideSearchEnabled".to_string(),
        "Enable Signed HTTP Exchange (SXG) support" => "SignedHTTPExchangeEnabled".to_string(),
        "Enable signin interception" => "SigninInterceptionEnabled".to_string(),
        "Require Site Isolation for every site" => "SitePerProcess".to_string(),
        "Enable spellcheck" => "SpellcheckEnabled".to_string(),
        "Force enable spellcheck languages" => "SpellcheckLanguage".to_string(),
        "Force disable spellcheck languages" => "SpellcheckLanguageBlocklist".to_string(),
        "Enable or disable spell checking web service" => "SpellCheckServiceEnabled".to_string(),
        "Allow proceeding from the SSL warning page" => "SSLErrorOverrideAllowed".to_string(),
        "Allow proceeding from the SSL warning page on specific origins" => "SSLErrorOverrideAllowedForOrigins".to_string(),
        "Enable strict MIME type checking for worker scripts" => "StrictMimetypeCheckForWorkerScriptsEnabled".to_string(),
        "Suppress JavaScript Dialogs triggered from different origin subframes" => "SuppressDifferentOriginSubframeDialogs".to_string(),
        "Suppress the unsupported OS warning" => "SuppressUnsupportedOSWarning".to_string(),
        "Disable synchronization of data with Google" => "SyncDisabled".to_string(),
        "List of types that should be excluded from synchronization" => "SyncTypesListDisabled".to_string(),
        "URL pattern Exceptions to tab discarding" => "TabDiscardingExceptions".to_string(),
        "Enable ending processes in Task Manager" => "TaskManagerEndProcessEnabled".to_string(),
        "Enable third party software injection blocking" => "ThirdPartyBlockingEnabled".to_string(),
        "Allows enabling throttling of non-visible, cross-origin iframes" => "ThrottleNonVisibleCrossOriginIframesAllowed".to_string(),
        "Set limit on megabytes of memory a single Chrome instance can use." => "TotalMemoryLimitMb".to_string(),
        "Enable Translate" => "TranslateEnabled".to_string(),
        "Allow access to a list of URLs" => "URLAllowlist".to_string(),
        "Block access to a list of URLs" => "URLBlocklist".to_string(),
        "Enable URL-keyed anonymized data collection" => "UrlKeyedAnonymizedDataCollectionEnabled".to_string(),
        "Control the User-Agent Client Hints GREASE Update feature." => "UserAgentClientHintsGREASEUpdateEnabled".to_string(),
        "Enable or disable the User-Agent Reduction." => "UserAgentReduction".to_string(),
        "Set user data directory" => "UserDataDir".to_string(),
        "Limits the number of user data snapshots retained for use in case of emergency rollback." => "UserDataSnapshotRetentionLimit".to_string(),
        "Allow user feedback" => "UserFeedbackAllowed".to_string(),
        "Allow or deny video capture" => "VideoCaptureAllowed".to_string(),
        "URLs that will be granted access to video capture devices without prompt" => "VideoCaptureAllowedUrls".to_string(),
        "Configure list of force-installed Web Apps" => "WebAppInstallForceList".to_string(),
        "Web App management settings" => "WebAppSettings".to_string(),
        "Allow legacy TLS/DTLS downgrade in WebRTC" => "WebRtcAllowLegacyTLSProtocols".to_string(),
        "Allow collection of WebRTC event logs from Google services" => "WebRtcEventLogCollectionAllowed".to_string(),
        "The IP handling policy of WebRTC" => "WebRtcIPHandling".to_string(),
        "URLs for which local IPs are exposed in WebRTC ICE candidates" => "WebRtcLocalIpsAllowedUrls".to_string(),
        "Allow WebRTC text logs collection from Google Services" => "WebRtcTextLogCollectionAllowed".to_string(),
        "Restrict the range of local UDP ports used by WebRTC" => "WebRtcUdpPortRange".to_string(),
        "Force WebSQL to be enabled." => "WebSQLAccess".to_string(),
        "Enable Window Occlusion" => "WindowOcclusionEnabled".to_string(),
        "Enable WPAD optimization" => "WPADQuickCheckEnabled".to_string(),
        "Configure native messaging allowlist" => "NativeMessagingAllowlist".to_string(),
        "Configure native messaging blocklist" => "NativeMessagingBlocklist".to_string(),
        "Allow user-level Native Messaging hosts (installed without admin permissions)" => "NativeMessagingUserLevelHosts".to_string(),
        "Make Access-Control-Allow-Methods matching in CORS preflight spec conformant" => "AccessControlAllowMethodsInCORSPreflightSpecConformant".to_string(),
        "Enable dismissing compromised password alerts for entered credentials" => "PasswordDismissCompromisedAlertEnabled".to_string(),
        "Enable leak detection for entered credentials" => "PasswordLeakDetectionEnabled".to_string(),
        "Enable saving passwords to the password manager" => "PasswordManagerEnabled".to_string(),
        "Enable Google Cloud Print proxy" => "CloudPrintProxyEnabled".to_string(),
        "Default printer selection rules" => "DefaultPrinterSelection".to_string(),
        "Disable Print Preview" => "DisablePrintPreview".to_string(),
        "Disable printer types on the deny list" => "PrinterTypeDenyList".to_string(),
        "Print Headers and Footers" => "PrintHeaderFooter".to_string(),
        "Restrict background graphics printing mode" => "PrintingAllowedBackgroundGraphicsModes".to_string(),
        "Default background graphics printing mode" => "PrintingBackgroundGraphicsDefault".to_string(),
        "Enable printing" => "PrintingEnabled".to_string(),
        "Default printing page size" => "PrintingPaperSizeDefault".to_string(),
        "Print PDF as Image Available" => "PrintPdfAsImageAvailability".to_string(),
        "Print PostScript Mode" => "PrintPostScriptMode".to_string(),
        "Use System Default Printer as Default" => "PrintPreviewUseSystemDefaultPrinter".to_string(),
        "Print Rasterization Mode" => "PrintRasterizationMode".to_string(),
        "Print Rasterize PDF DPI" => "PrintRasterizePdfDpi".to_string(),
        "Choose whether the Privacy Sandbox ad measurement setting can be disabled" => "PrivacySandboxAdMeasurementEnabled".to_string(),
        "Choose whether the Privacy Sandbox Ad topics setting can be disabled" => "PrivacySandboxAdTopicsEnabled".to_string(),
        "Choose whether the Privacy Sandbox prompt can be shown to your users" => "PrivacySandboxPromptEnabled".to_string(),
        "Choose whether the Privacy Sandbox Site-suggested ads setting can be disabled" => "PrivacySandboxSiteEnabledAdsEnabled".to_string(),
        "Enable or disable PIN-less authentication for remote access hosts" => "RemoteAccessHostAllowClientPairing".to_string(),
        "Allow remote access users to transfer files to/from the host" => "RemoteAccessHostAllowFileTransfer".to_string(),
        "Enable the use of relay servers by the remote access host" => "RemoteAccessHostAllowRelayedConnection".to_string(),
        "Allow remote access connections to this machine" => "RemoteAccessHostAllowRemoteAccessConnections".to_string(),
        "Allow remote support connections to this machine" => "RemoteAccessHostAllowRemoteSupportConnections".to_string(),
        "Allow remote users to interact with elevated windows in remote assistance sessions" => "RemoteAccessHostAllowUiAccessForRemoteAssistance".to_string(),
        "Configure the required domain names for remote access clients" => "RemoteAccessHostClientDomainList".to_string(),
        "The maximum size, in bytes, that can be transferred between client and host via clipboard synchronization" => "RemoteAccessHostClipboardSizeBytes".to_string(),
        "Configure the required domain names for remote access hosts" => "RemoteAccessHostDomainList".to_string(),
        "Enable firewall traversal from remote access host" => "RemoteAccessHostFirewallTraversal".to_string(),
        "Maximum session duration allowed for remote access connections" => "RemoteAccessHostMaximumSessionDurationMinutes".to_string(),
        "Enable curtaining of remote access hosts" => "RemoteAccessHostRequireCurtain".to_string(),
        "Restrict the UDP port range used by the remote access host" => "RemoteAccessHostUdpPortRange".to_string(),
        "Configure the change password URL." => "PasswordProtectionChangePasswordURL".to_string(),
        "Configure the list of enterprise login URLs where password protection service should capture salted hashes of passwords." => "PasswordProtectionLoginURLs".to_string(),
        "Password protection warning trigger" => "PasswordProtectionWarningTrigger".to_string(),
        "Configure the list of domains on which Safe Browsing will not trigger warnings." => "SafeBrowsingAllowlistDomains".to_string(),
        "Enable Safe Browsing Extended Reporting" => "SafeBrowsingExtendedReportingEnabled".to_string(),
        "Safe Browsing Protection Level" => "SafeBrowsingProtectionLevel".to_string(),
        "Use New Tab Page as homepage" => "HomepageIsNewTabPage".to_string(),
        "Configure the home page URL" => "HomepageLocation".to_string(),
        "Configure the New Tab page URL" => "NewTabPageLocation".to_string(),
        "Action on startup" => "RestoreOnStartup".to_string(),
        "URLs to open on startup" => "RestoreOnStartupURLs".to_string(),
        "Show Home button on toolbar" => "ShowHomeButton".to_string(),
        _ => {
            return Err(anyhow!("'{}' not found in chrome definitions", display_name));
        }
    };
    if recommended {
        key = format!("{}_recommended", key);
    }
    Ok(key)
}

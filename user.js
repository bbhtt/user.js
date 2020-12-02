// Original Project: https://github.com/arkenfox/user.js

// Minimum Firefox version supported is FF82-Linux

// (*1) Set the region code below
// (*2) Choose geolocation to block per OS

// Disable about:config warning 

user_pref("general.warnOnAboutConfig", false);
user_pref("browser.aboutConfig.showWarning", false);

// Check for default browser

// user_pref("browser.shell.checkDefaultBrowser", true);

// Startup page, 0 is blank 

user_pref("browser.startup.page", 0);
user_pref("browser.startup.homepage", "about:blank");

// Newtab page activity, loading content from remote locations 

user_pref("browser.newtabpage.enabled", false); // Display a blank page on nw tab currently controlled by MAC
user_pref("browser.newtab.preload", false); // Don't preload content of new tab while in background

// Turn off pocket/snippets telemetry on New Tab page

user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", false);
user_pref("browser.newtabpage.activity-stream.default.sites", "");
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");
user_pref("browser.newtabpage.activity-stream.section.highlights.includeBookmarks", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeDownloads", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeVisited", false);
user_pref("browser.newtabpage.activity-stream.showSearch", false);
user_pref("browser.newtabpage.pinned", "");

// Geolocation and Geo specific configs, always ask reduces fingerprinting

user_pref("permissions.default.geo", 2); // Block location access prompt
user_pref("geo.provider.network.url", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%"); // Use Mozilla location services
user_pref("geo.provider.network.logging.enabled", true);
user_pref("geo.provider.use_gpsd", false); // Linux specific geo location		   (*2)
// user_pref("geo.provider.ms-windows-location", false); // Windows specific geo location  (*2)
// user_pref("geo.provider.use_corelocation", false); // Mac specific geo location	   (*2)	
user_pref("browser.search.geoSpecificDefaults", false); // Remove location specific search
user_pref("browser.search.geoSpecificDefaults.url", ""); // Remove location specific search
user_pref("browser.region.network.url", ""); 
user_pref("browser.region.update.enabled", false); // Don't update browser region
user_pref("browser.search.region", "US"); // (*1)

// Locale and Fonts

user_pref("intl.accept_languages", "en-US, en"); // Default value
user_pref("javascript.use_us_english_locale", true); // If privacy resist fingerprint is set this is default

// Don't download icon fonts

// user_pref("browser.display.use_document_fonts", 0);  // RFP does this by default so not needed
// user_pref("gfx.downloadable_fonts.enabled", false); // Breaks Bitwarden tootips
user_pref("gfx.downloadable_fonts.fallback_delay", -1);

 // Disable SVG images may break sites like YT

user_pref("gfx.font_rendering.opentype_svg.enabled", false); 
user_pref("svg.disabled", true);
user_pref("mathml.disabled", true); // Disable mathml reduce attack surface

user_pref("gfx.font_rendering.graphite.enabled", false); // https://bugzilla.mozilla.org/show_bug.cgi?id=1255731
// user_pref("font.system.whitelist", ""); // Expose only whitelisted font to counter fingerprinting, set to none; RFP does this via default so not needed.

// Auto Update 

user_pref("app.update.auto", false);
user_pref("browser.search.update", false); // Don't update search engines

// Extensions,addons and plugins

 // Don't update extensions by default
 
user_pref("extensions.update.enabled", false); // Don't auto check for extension updates
user_pref("extensions.update.autoUpdateDefault", false); // Don't auto-update extensions 
user_pref("extensions.systemAddon.update.enabled", false); 
user_pref("extensions.getAddons.cache.enabled", false); // Disable extension metadata sends daily ping to Mozilla 
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false); // Stop flash crash reporting
user_pref("dom.ipc.plugins.reportCrashURL", false);  // Stop sending url when crash reporting
user_pref("extensions.getAddons.showPane", false); // Don't display recommended addons
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false); // Don't display recommended addons
user_pref("extensions.blocklist.enabled", true); // Mozilla maintaines a remote blocklist of malicious addons; setting to true prevents installing any
user_pref("extensions.systemAddon.update.url", "");
user_pref("browser.ping-centre.telemetry", false);
user_pref("plugin.state.flash", 0);
user_pref("media.gmp-provider.enabled", false);

 // Disable DRM/encrypted media extension
 
user_pref("media.gmp-widevinecdm.visible", false);
user_pref("media.gmp-widevinecdm.enabled", false);
user_pref("media.eme.enabled", false);

  // Disable Pockets
  
user_pref("extensions.pocket.enabled", false);

 // Disable Screenshots

user_pref("extensions.screenshots.disabled", true); 

 // Disable reader mode
 
user_pref("reader.parse-on-load.enabled", false); 


// Telemetry and Reporting (Disables various telemetry and reporting)

user_pref("toolkit.telemetry.unified", false); // Master switch if set to true below are not used by FF
user_pref("toolkit.telemetry.enabled", false); // Master switch if set to true below are not used by FF
user_pref("toolkit.telemetry.server", "data:,"); // The server telemetry pings are sent to; set to blank
user_pref("toolkit.telemetry.archive.enabled", false); // Allow pings to be archived locally
user_pref("toolkit.telemetry.newProfilePing.enabled", false); // Don't send a new profile ping
user_pref("toolkit.telemetry.shutdownPingSender.enabledFirstSession", false); // // Don't send shutdown ping to Mozilla for first session
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false); // Don't send shutdown ping to Mozilla from second session
user_pref("toolkit.telemetry.updatePing.enabled", false); // Don't send a update ping
user_pref("toolkit.telemetry.bhrPing.enabled", false); // Reports background hangs
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.coverage.opt-out", true); // https://www.ghacks.net/2018/09/21/mozilla-wants-to-estimate-firefoxs-telemetry-off-population/
user_pref("toolkit.coverage.opt-out", true); 
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("datareporting.healthreport.uploadEnabled", false); // Disable FF data reporting
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.shield.optoutstudies.enabled", false); // Opt-out of FF studies
user_pref("browser.discovery.enabled", false);
user_pref("breakpad.reportURL", ""); // Disables crash reporting
user_pref("browser.tabs.crashReporting.sendReport", false); // Disables crash reporting
user_pref("browser.crashReports.unsubmittedCheck.enabled", false); // Disables crash reporting
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // Don't send backlogged crash reports
user_pref("extensions.webcompat-reporter.enabled", false); // Internal extension to report site issues; disables button 
                                                           // https://github.com/webcompat/webcompat-reporter-extensions

// Captive Portal detection https://www.eff.org/deeplinks/2017/08/how-captive-portals-interfere-wireless-security-and-privacy

user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false); // Disable network connectivity checks https://bugzilla.mozilla.org/1460537

// Safe Browsing and Malware/Phishing

user_pref("browser.safebrowsing.downloads.enabled", false); // Sends file name, hash, size to Google, turn off local See  Google Safe Browsing APIv4
user_pref("browser.safebrowsing.downloads.remote.enabled", false); // Sends file name, hash, size to Google, turn off remote
user_pref("browser.safebrowsing.downloads.remote.url", "");
user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", false);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);
user_pref("browser.safebrowsing.allowOverride", false); // https://bugzilla.mozilla.org/1226490


// Mozilla Normandy (temporary studies, user surveys, hotfixes hence disabled)

user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

// Autofill  (Disables various autofills)

user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.available", false); 
user_pref("extensions.formautofill.available", "off"); 
user_pref("extensions.formautofill.creditCards.enabled", false); 
user_pref("extensions.formautofill.heuristics.enabled", false); 
user_pref("signon.autofillForms", false);
user_pref("browser.formfill.enable", false);
user_pref("signon.formlessCapture.enabled", false);

// Network Prefetch

user_pref("network.prefetch-next", false); // Turn off link prefetching https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ
user_pref("network.dns.disablePrefetch", true); // Turn off DNS prefetching
user_pref("network.dns.disablePrefetchFromHTTPS", true); // Turn off DNS prefetching for https
user_pref("network.predictor.enabled", false); 
user_pref("network.predictor.enable-prefetch", false); 
user_pref("network.http.speculative-parallel-limit", 0); // https://bugzilla.mozilla.org/show_bug.cgi?id=814169

 // uBO blocks pings by default

user_pref("browser.send_pings", false); 
user_pref("browser.send_pings.require_same_host", true); 

// Network

user_pref("network.dns.disableIPv6", true); // IPv6 increases fingerprinting apart from security issues
user_pref("network.http.altsvc.enabled", false); // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Alt-Svc
user_pref("network.http.altsvc.oe", false); // See above
user_pref("network.ftp.enabled", false); // By default set to fault https://winaero.com/firefox-drops-ftp-support/
user_pref("network.proxy.socks_remote_dns", true); //proxy sever DNS lookup when using SOCKS
user_pref("network.file.disable_unc_paths", true); 
user_pref("network.gio.supported-protocols", ""); // Disable gio as a potential proxy bypass vector
user_pref("network.auth.subresource-http-auth-allow", 1); // 1=Don't allow cross-origin sub-resources to open HTTP authentication credentials 
                                                          //dialogs

// SSL/TLS deviations from defaults can be used in server side fingerprinting

user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.version.enable-deprecated", false);
user_pref("security.ssl.disable_session_identifiers", true); 
user_pref("security.ssl.errorReporting.automatic", false);
user_pref("security.ssl.errorReporting.enabled", false);
user_pref("security.ssl.errorReporting.url", "");
user_pref("security.tls.enable_0rtt_data", false);
user_pref("security.ssl.enable_false_start", false);
user_pref("security.ssl.enable_ocsp_stapling", true);
user_pref("security.OCSP.enabled", 1);
user_pref("security.OCSP.require", true);

// Certificate 

user_pref("security.pki.sha1_enforcement_level", 1);
user_pref("security.cert_pinning.enforcement_level", 2);


// Mixed Content

user_pref("security.mixed_content.block_active_content", true);
user_pref("security.mixed_content.block_display_content", true);
user_pref("security.mixed_content.block_object_subrequest", true);

// HTTPS only mode

user_pref("dom.security.https_only_mode", true); 
user_pref("dom.security.https_only_mode_pbm", true); 
user_pref("dom.security.https_only_mode.upgrade_local", true); // HTTPS only for local resources
user_pref("dom.security.https_only_mode_send_http_background_request", false); // Disable sending a http request after 3s timeout

// URL and Search Bar behaviour

user_pref("keyword.enabled", false); // Input in location bar automatically resolved by keyword service; disable it
				     // https://bugzilla.mozilla.org/show_bug.cgi?id=100412
user_pref("browser.fixup.alternate.enabled", false);
user_pref("browser.urlbar.trimURLs", false);
user_pref("layout.css.visited_links_enabled", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.urlbar.dnsResolveSingleWordsAfterSearch", 0);
user_pref("browser.urlbar.suggest.history", false);
user_pref("browser.urlbar.suggest.bookmark", false);
user_pref("browser.urlbar.suggest.openpage", false);
user_pref("browser.urlbar.suggest.topsites", false); 
user_pref("places.history.enabled", false);

// Primary password policy

user_pref("security.ask_for_password", 2);
user_pref("security.password_lifetime", 5);

// Cache, cookie and other storage 

user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", false);
user_pref("browser.cache.memory.capacity", 0);
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("media.memory_cache_max_size", 65536);
user_pref("browser.cache.offline.storage.enable", false); // Enforce no offline cache
user_pref("network.cookie.cookieBehavior", 1);
user_pref("browser.contentblocking.category", "custom");
user_pref("network.cookie.thirdparty.sessionOnly", true);
user_pref("network.cookie.thirdparty.nonsecureSessionOnly", true); 
user_pref("dom.caches.enabled", false);
user_pref("dom.storageManager.enabled", false);
user_pref("dom.storage_access.enabled", false);

// Session Restore

user_pref("browser.sessionstore.max_tabs_undo", 0);
user_pref("browser.sessionstore.privacy_level", 2);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.sessionstore.interval", 30000);
user_pref("toolkit.winRegisterApplicationRestart", false);

// Favicon

user_pref("browser.shell.shortcutFavicons", false);
user_pref("browser.chrome.site_icons", false);
user_pref("alerts.showFavicons", false);


// Ciphers 

user_pref("security.ssl3.rsa_des_ede3_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.rsa_aes_128_sha", false); 
user_pref("security.ssl3.rsa_aes_256_sha", false);


// Header/Referer

 // Currently controled by Chameleon
 
// DNT

user_pref("privacy.donottrackheader.enabled", true);

// Tor

user_pref("network.http.referer.hideOnionSource", true);

// Conatiner Mozilla MAC

user_pref("privacy.userContext.ui.enabled", true);
user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.newTabContainerOnLeftClick.enabled", true);

// GPU, camera, media, mic

user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("webgl.disabled", true);
user_pref("webgl.enable-webgl2", false);
user_pref("webgl.min_capability_mode", true);
user_pref("webgl.disable-fail-if-major-performance-caveat", true);
user_pref("media.getusermedia.screensharing.enabled", false);
user_pref("media.getusermedia.browser.enabled", false);
user_pref("media.getusermedia.audiocapture.enabled", false);
user_pref("permissions.default.camera", 2);
user_pref("permissions.default.microphone", 2);
user_pref("media.autoplay.default", 5);
user_pref("media.autoplay.blocking_policy", 2);

// Window or NewTab

user_pref("dom.disable_window_move_resize", true);
user_pref("browser.link.open_newwindow", 3); 
user_pref("browser.link.open_newwindow.restriction", 0);
user_pref("full-screen-api.enabled", false);
user_pref("dom.disable_open_during_load", true);
user_pref("dom.popup_allowed_events", "click dblclick");
user_pref("browser.link.open_newwindow.restriction", 0); // Open links in Tabs instead of a new window

// Web worker

user_pref("dom.serviceWorkers.enabled", false);
user_pref("dom.webnotifications.enabled", false);
user_pref("dom.webnotifications.serviceworker.enabled", false);
user_pref("dom.push.enabled", false);
user_pref("dom.push.userAgentID", "");

// DOM

user_pref("dom.event.contextmenu.enabled", false);
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("dom.allow_cut_copy", false);
user_pref("dom.disable_beforeunload", true);
user_pref("dom.vibrator.enabled", false);
user_pref("dom.storage.next_gen", true);  //Next Generation local storage, new tabs can access set local storage whne opened


// Javascript

user_pref("javascript.options.asmjs", false);
user_pref("javascript.options.wasm", false);
user_pref("dom.targetBlankNoOpener.enabled", true);


// Hardware Fingerprinting

user_pref("dom.battery.enabled", false); // Disable Battery API
user_pref("media.navigator.enabled", false);
user_pref("layers.acceleration.disabled", true);
user_pref("dom.webaudio.enabled", false);
user_pref("media.media-capabilities.enabled", false);
user_pref("dom.vr.enabled", false); // Disable VR 
user_pref("permissions.default.xr", 2); // VR permissions set to block

// Misc

user_pref("accessibility.force_disabled", 1); // Disable accesibility settings
user_pref("beacon.enabled", false);
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.pagethumbnails.capturing_disabled", true); 
user_pref("browser.uitour.enabled", false);
user_pref("browser.uitour.url", "");
user_pref("devtools.chrome.enabled", false);
user_pref("devtools.debugger.remote-enabled", false); 
user_pref("middlemouse.contentLoadURL", false); 
user_pref("network.http.redirection-limit", 7);
user_pref("permissions.default.shortcuts", 2);
user_pref("permissions.manager.defaultsUrl", "");
user_pref("webchannel.allowObject.urlWhitelist", "");
user_pref("network.IDN_show_punycode", true);
user_pref("pdfjs.disabled", false);
user_pref("browser.display.use_system_colors", false);
user_pref("permissions.delegation.enabled", false);
user_pref("privacy.window.name.update.enabled", true); // https://bugzilla.mozilla.org/show_bug.cgi?id=444222

// UI

user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("browser.ssl_override_behavior", 1);
user_pref("browser.xul.error_pages.expert_bad_cert", true);
user_pref("security.insecure_connection_text.enabled", true);

// Downloads

user_pref("browser.download.folderList", 2);
user_pref("browser.download.useDownloadDir", false); // Ask where to save files
user_pref("browser.download.manager.addToRecentDocs", false); // Don't add to recently opened files
user_pref("browser.download.hide_plugins_without_extensions", false);
user_pref("browser.download.forbid_open_with", true); // No 'open with' checkbox


// Security

user_pref("security.csp.enable", true); 
user_pref("security.dialog_enable_delay", 700);

// Shutdown Behaviour

user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true); 
user_pref("privacy.clearOnShutdown.history", true); 
user_pref("privacy.clearOnShutdown.offlineApps", true); 
user_pref("privacy.clearOnShutdown.sessions", true); 
user_pref("privacy.clearOnShutdown.siteSettings", false);
user_pref("privacy.cpd.cache", true);
user_pref("privacy.cpd.cookies", true);
user_pref("privacy.cpd.formdata", true); 
user_pref("privacy.cpd.history", true); 
user_pref("privacy.cpd.offlineApps", true); 
user_pref("privacy.cpd.passwords", false); 
user_pref("privacy.cpd.sessions", true); 
user_pref("privacy.cpd.siteSettings", false); 
user_pref("privacy.clearOnShutdown.openWindows", true);
user_pref("privacy.cpd.openWindows", true);
user_pref("privacy.sanitize.timeSpan", 0);


// First Party Isolation

user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);
user_pref("privacy.resistFingerprinting.letterboxing", true);
user_pref("browser.startup.blankWindow", false);
user_pref("ui.prefersReducedMotion", 1); 

---
name: apple-termination-risk-scan
description: Scan an iOS app's code and metadata before App Store submission for patterns that can get the Apple developer account terminated (3.2(f), 2.5.19, 2.5.2, 3.1.x, 5.6).
compatibility: Requires ripgrep (rg). Works with any agent that supports Agent Skills.
license: MIT
metadata:
  version: "1.0"
---

# Apple Termination Risk Scan

Pre-submission audit that looks for in-app patterns Apple treats as dishonest or as "evading review". These patterns can escalate from a single rejection to **developer account termination** under DPLA 3.2(f) and the Developer Code of Conduct (5.6).

The core idea: Apple punishes apps that **behave differently in review than in production**, hide functionality, bypass IAP, manipulate reviews, impersonate others or mislead users. This skill finds code that *could* do that, judges whether it actually does, and tells the developer how to fix it or disclose it.

Reply in the user's language. Do not modify code unless the user asks.

## Ground rules

1. **Transparency, never evasion.** Never suggest obfuscation, encryption, renaming or any other way to hide something from App Review. That is exactly what 2.5.19 names as grounds for termination. The fix is always one of: remove it, gate it to DEBUG builds only, or make it visible and document it in Notes for Review.
2. **Pattern ≠ violation.** A grep hit is only a finding when the code ships in the release build **and** it changes what the user can do based on review status, remote config, location, date or environment, or it matches a prohibited category below. Read the surrounding code before reporting.
3. **No guarantees.** Never say the app is "safe" or "won't be banned". Say "no high-risk patterns found in what was scanned" and list what was out of scope.
4. **Label the evidence level** of each rule: `Guideline` (the termination language is in Apple's text) or `Reported` (developer cases, forums, community reports).

## Step 1: Identify the project

Detect the stack and the release-only guards so DEBUG-only code can be ignored:

| Stack | Source globs | Release guard to look for |
|---|---|---|
| Swift/ObjC | `*.swift *.m *.mm *.h`, `Info.plist`, `*.entitlements`, `PrivacyInfo.xcprivacy`, `Podfile.lock`, `Package.resolved` | `#if DEBUG`, `#if targetEnvironment(simulator)` |
| Kotlin Multiplatform / Compose MP | `shared/src/**`, `iosMain`, `commonMain`, `*.kt`, `iosApp/**`, `libs.versions.toml`, `build.gradle.kts` | `BuildConfig.DEBUG`, `Platform.isDebugBinary`, build-type source sets |
| React Native / Expo | `*.js *.jsx *.ts *.tsx`, `package.json`, `app.json`, `app.config.*`, `eas.json` | `__DEV__` |
| Flutter | `lib/**/*.dart`, `pubspec.yaml`, `pubspec.lock`, `ios/**` | `kDebugMode`, `kReleaseMode`, `assert(...)` |
| Unity | `Assets/**/*.cs`, `Packages/manifest.json` | `#if DEVELOPMENT_BUILD`, `#if UNITY_EDITOR`, `Debug.isDebugBuild` |

Also list the dependencies (lockfiles), because many risks come from SDKs.

If the user supplies an `.ipa`, you may additionally unzip it and inspect `Payload/*.app` (`strings`, `otool -L`, `nm -u`, embedded `Frameworks/`) for the same signals.

## Step 2: Run the scans

Use `rg -n -i` with the patterns below across the source globs, excluding `node_modules`, `Pods`, `build`, `.gradle`, `DerivedData` and test folders (scan the lockfiles separately). Patterns are starting points. Adapt them to the stack.

### C1. Hidden or dormant features and review cloaking. CRITICAL (Guideline 2.5.19, 2.3.1(a))

2.5.19 (added 16 Oct 2026): no hidden, dormant or undocumented features. Trying to hide them, "such as through code obfuscation", is grounds for app removal and account termination.

```
# review/audit switches
\b(is_?review|in_?review|review_?mode|under_?review|audit(_?mode|_?status)?|review_?version|apple_?review|reviewer|kaiguan|shenhe|is_?check|hide_?for_?review|online_?switch)\b
# date / install-age activation
20(2[6-9]|[3-9]\d)[-/.](0[1-9]|1[0-2])[-/.]\d{2}
(first_?launch|install_?date|days_?since_?install|launch_?count)\s*[<>=]
# geo / locale gating
(regionCode|region\.identifier|countryCode|Storefront|SKStorefront|CTCarrier|mobileCountryCode|isoCountryCode|TimeZone\.current|NSTimeZone|ip-?api|ipinfo|geoip|ipify|ipgeolocation)
# environment detection (reviewer / TestFlight / VPN)
(sandboxReceipt|appStoreReceiptURL|isTestFlight|AppTransaction|\.sandbox\b|isSimulator|utun|ipsec|ppp0|NEVPNStatus)
# remote URL into a web view
(WKWebView|UIWebView|SFSafariViewController|react-native-webview|webview_flutter|InAppWebView|WebView\()
(base64|Base64\.decode|atob\(|decodeBase64)
# debug / secret menus and gesture triggers
(debug_?menu|dev_?menu|developer_?options|secret_?menu|hidden_?menu|easter_?egg|god_?mode|cheat|env_?switch|staging_?toggle|FLEX|Flipper|DebugView)
(numberOfTapsRequired\s*=\s*[4-9]|tap_?count\s*>=?\s*[4-9]|onLongPress.{0,40}(debug|dev|admin))
# feature-flag inventory
(RemoteConfig|remoteConfig|getBoolean\(|configValue\(forKey|LaunchDarkly|Statsig|Optimizely|GrowthBook|Unleash|ConfigCat|Flagsmith|feature_?flag|isFeatureEnabled|experiment)
# hiding of strings or config
(obfuscat|SwiftShield|class-guard|xor_?decrypt|StringObfuscator|decrypt.{0,30}(config|url|feature|endpoint))
```

Triage:
- **CRITICAL** when a release-build branch shows different features or content depending on review status, build number vs. a server "review version", sandbox/TestFlight receipt, VPN, location, storefront, carrier or a future date. Also when a remote value (often base64) decides which URL a web view loads.
- **CRITICAL** when a debug, secret or admin menu is reachable in release (not behind a DEBUG guard).
- **HIGH** when feature flags gate user-facing features. This is legitimate only if every flagged feature is in the submitted binary, can be reached by the reviewer (on during review, or with instructions), and is described in Notes for Review. Produce a flag inventory table for the user.
- **HIGH** when feature code, endpoints or config are obfuscated or encrypted. Note: Flutter `--obfuscate` and Swift symbol stripping are normal build hygiene and only INFO, unless they are used to hide feature strings or URLs.
- Geo or locale code that only does localization, currency or legal compliance (GDPR, age ratings) is fine. Say so explicitly.

### C2. Downloaded or dynamic code and OTA updates. CRITICAL/HIGH (Guideline 2.5.2, DPLA 3.3.2)

```
\b(dlopen|dlsym|NSClassFromString|NSSelectorFromString|performSelector|method_exchangeImplementations|class_replaceMethod|NSInvocation)\b
(JSPatch|Rollout|\bWax\b|luaL_|lua_State|JSContext|evaluateScript|\beval\(|new Function\()
(code-?push|expo-updates|fetchUpdateAsync|Shorebird|hot_?update|hot_?fix|patch_?download|HybridCLR|ILRuntime|xLua|ToLua|puerts)
(\.dylib|\.framework|\.bundle).{0,60}(download|URLSession|http)
```

Triage:
- **CRITICAL** when a remote string or script reaches `dlopen`, `dlsym`, `NSClassFromString`, `performSelector` or swizzling (the exact combination Apple warned about in its 2017 JSPatch/Rollout emails), when native code or binaries are downloaded, or when a JS bridge exposes native APIs to remote scripts.
- **HIGH** for OTA (CodePush, EAS Update, Shorebird, Lua/IL hot-update in Unity). It is allowed only for bug fixes to JS/assets that keep the reviewed purpose and features. `Reported`: several accounts were terminated for "concept or feature switching" after OTA pushes that added screens or features. Recommend: ship new features only through reviewed builds, and mention OTA usage in Notes for Review.
- Local, static uses of these APIs (e.g. `NSClassFromString("UIApplication")` for a hard-coded class) are INFO.

### C3. Payments and paywalls. CRITICAL/HIGH (Guideline 3.1.1, 3.1.2(a))

```
(stripe|braintree|paypal|alipay|wechat_?pay|razorpay|paddle|lemonsqueezy|adyen|mollie|iyzico|paytr|checkout\.com)
(license_?key|activation_?code|unlock_?code|redeem_?code|crypto.{0,20}unlock)
(buy|purchase|subscribe|pricing|checkout|upgrade).{0,60}https?://
(trial_?toggle|free_?trial_?(switch|toggle)|Toggle\(.{0,40}trial|Switch\(.{0,40}trial)
(close|dismiss|x_?button).{0,80}(delay|asyncAfter|postDelayed|Timer|setTimeout|opacity\s*\(?\s*0)
(countdown|limited_?time|offer_?ends|expires_?in|only_?today)
```

Triage:
- **CRITICAL** when digital content or features are unlocked through a non-IAP payment, license key, QR code or crypto (physical goods and real-world services may use external payments), or when an external purchase link is used without a valid entitlement.
- **CRITICAL** for bait-and-switch paywalls (3.1.2(a) names removal from the Developer Program): a free-trial toggle (rejected since Jan 2026), a delayed or hidden close button, the real price shown less prominently than a per-week or "free" figure, auto-renew terms missing, fake countdowns or discounts.
- Ask the user for paywall screenshots if they can't be judged from code.

### C4. Review and rating manipulation. CRITICAL (Guideline 5.6.1, 5.6.3, 3.2.2(x))

```
(rate_?us|rate_?app|review_?prompt|write-review|enjoying.{0,30}app|do you (like|love|enjoy)|rating_?dialog|Appirater|iRate|RateMyApp|AppRate|in_app_review|requestReview|SKStoreReviewController)
(review|rate|rating).{0,60}(reward|coins|gems|unlock|bonus|premium|free)
```

Triage:
- **CRITICAL** for review gating ("Do you like the app?" → Yes opens the store prompt, No opens a feedback form), rewards for reviews, or requiring a rating to unlock functionality.
- **HIGH** for a custom rating popup instead of `requestReview` / `SKStoreReviewController` / the platform in-app-review API. 5.6.1 says custom review prompts are disallowed.
- A deep link to `action=write-review` from a settings row the user taps is fine.

### C5. Impersonation and copycats. CRITICAL (Guideline 4.1(b), 2.3.14)

Scan user-facing strings (`Info.plist` CFBundleDisplayName, `*.strings`, `*.xcstrings`, `strings.xml`, Compose resources, i18n JSON, asset names) and the metadata the user provides:

```
\b(whatsapp|instagram|tiktok|facebook|messenger|snapchat|youtube|netflix|spotify|chatgpt|openai|gemini|claude|zoom|teams|microsoft|google|apple|iphone|siri|airdrop|telegram|discord|roblox|minecraft|fortnite|pokemon|disney|nintendo|uber|amazon)\b
```

- **CRITICAL** when a third-party brand appears in the app name, subtitle or icon, or in phrasing like "X for Teams" or "Join for Zoom" that suggests affiliation. 4.1(b) calls impersonation a Code of Conduct violation.
- Functional integrations ("Sign in with Google", "Share to Instagram") are fine.

### C6. Misleading functionality claims. CRITICAL (Guideline 2.3.1(a))

```
(virus|malware|antivirus|cleaner|junk|boost(er)?|battery_?(saver|doctor)|speed_?up|phone_?cooler|ram_?clean|who_?viewed|track_?(any|someone)|spy)
```

Flag claims iOS apps cannot actually deliver (virus or malware scanning, RAM cleaning, battery boosting), and features advertised in strings or metadata that don't exist in code. 2.3.1(a) lists these as grounds for termination.

### C7. AI and user-generated content safeguards. HIGH (Guideline 1.2, Oct 2026)

```
(replicate|fal\.ai|stability|stable.?diffusion|dall-?e|images/generations|image_?generat|face_?swap|undress|nudif|upload_?image|comments?|posts?|feed|chat_?room)
(report|block_?user|moderat|flag_?content|nsfw|content_?filter|safety_?check)
```

If the app lets users generate or share content (especially AI images of real people), it must have filtering, reporting, blocking and a way to contact the developer. Since Oct 2026, failing to have these safeguards, or failing to fix violations after notice, may be treated as a Code of Conduct violation. Undress or nudify functionality is CRITICAL.

### C8. Private API. HIGH (Guideline 2.5.1)

```
(_UIStatusBar|UIGetScreenImage|LSApplicationWorkspace|MobileGestalt|GSEvent|PrivateFrameworks|valueForKey:\s*@"_|forKey:\s*@"_|value\(forKey:\s*"_)
```

### C9. Privacy, recording and fingerprinting. MEDIUM/HIGH (Guideline 5.1.1, 5.1.2(iii), 2.5.14)

```
(RPScreenRecorder|ReplayKit|AVAudioRecorder|startRecording|keystroke|UIPasteboard|advertisingIdentifier|identifierForVendor|fingerprint|DeviceCheck)
```

Check for a consent and visible indicator when recording, an ATT prompt before IDFA, no device fingerprinting, and that `PrivacyInfo.xcprivacy` exists and covers the Required Reason APIs used.

### C10. VPN and MDM. HIGH (Guideline 5.4, 5.5: removal from the program is written in the text)

```
(NEPacketTunnelProvider|NETunnelProvider|NEVPNManager|ManagedConfiguration|MDM)
```

The app must be on an organization account, declare its data use, and not sell or share user data.

### C11. Clone, template and spam signals. MEDIUM (Guideline 4.3, Reported: escalates to 3.2(f) when combined with other issues)

```
(com\.example|boilerplate|starter_?kit|template|lorem ipsum|TODO:? rename|YOUR_APP_NAME)
```

Also flag multiple targets or flavors that are the same app under different names or bundle IDs. Again: **do not** recommend obfuscation to defeat similarity detection. Recommend real differentiation, or merging the apps into one.

When the app sits in a saturated category (habit tracker, timer, flashlight, notes, simple AI wrapper), suggest concrete platform value that sets it apart: widgets, App Intents / Shortcuts, on-device ML, Live Activities, full Dynamic Type and accessibility support.

### C12. Permission usage descriptions. MEDIUM (Guideline 5.1.1)

Read every `NS*UsageDescription` key in `Info.plist` (and `InfoPlist.strings` / `*.xcstrings` translations; for Expo check `app.json` / `app.config.*` `ios.infoPlist`, for Flutter `ios/Runner/Info.plist`, for KMM `iosApp/iosApp/Info.plist`).

Flag a description when it:
- is generic or vague ("This app needs camera access", "Required for the app to work", "We need your location");
- is shorter than about 40 characters or is a placeholder (`TODO`, `$(PRODUCT_NAME) needs…` with nothing more);
- does not say what the data is used for **and** how the user benefits;
- doesn't match a feature you can find in the code (a permission declared but never used, or used for something other than what the text says);
- is missing for an API the code calls (e.g. camera, photos, microphone, location, contacts, tracking).

Suggest a rewritten description for each flagged key.

### C13. Update hygiene. MEDIUM (Reported)

Only when the project is a git repo and the user is preparing an update. Compare against the last released tag or commit the user names (`git diff --stat <tag>..HEAD`). If the same release changes any of these **and** also contains unrelated code changes, recommend splitting them into separate submissions so each change is easy to review:
- `*.entitlements` or new capabilities;
- `PrivacyInfo.xcprivacy` or new `NS*UsageDescription` keys;
- paywall, pricing, subscription or purchase-flow files;
- new SDKs in the lockfiles.

Any new user-facing feature in the diff must appear in the Notes for Review (see Step 3).

## Step 3: Metadata and submission checklist

Ask the user to paste the following (skip the items they don't have): app name and subtitle, description, keywords, screenshots, Notes for Review, support URL, privacy policy URL, developer/seller name. Then check:

- [ ] **Notes for Review (2.3.1(a))**: every new feature, every feature flag or remote-config switch, every OTA mechanism and every gated area is described *specifically*, with a demo account and steps to reach it.
- [ ] **Update notes are specific**: for updates, the Notes for Review and "What's New" state exactly what changed and where (e.g. "Fixed text truncation on the Settings screen; added a weekly summary widget"), not "Bug fixes and improvements". Flag generic text and propose a specific version based on the diff.
- [ ] **Policy URLs work**: the privacy policy, terms and support URLs load quickly over valid HTTPS, are not empty, and the content is in the HTML itself (not only rendered client-side by a SPA). If network access is available, fetch them and check; otherwise ask the user to confirm.
- [ ] The description and screenshots match the real UI. No features that aren't in the build. No pricing claims in screenshots (2.3.14).
- [ ] No third-party brands in the name, subtitle or keywords (C5).
- [ ] **Developer identity (5.6.2)**: the support site, privacy policy and copyright/footer name match the developer account's legal entity. The privacy policy page is not empty. Contact info works.
- [ ] Pricing shown in the app matches App Store Connect.

## Step 4: Report

Start with a one-line verdict: `High risk`, `Needs fixes before submission` or `No high-risk patterns found in scanned scope`. Then:

| # | Severity | Category | Guideline | Evidence level | Location | What was found | Why it's risky | Fix | Review Notes text |
|---|---|---|---|---|---|---|---|---|---|

- Order the findings CRITICAL → HIGH → MEDIUM → INFO.
- Quote the minimal code snippet.
- For legitimate flags or OTA usage, write the exact sentence the developer can paste into Notes for Review.
- Add the feature-flag inventory table (flag, default, what it gates, reachable in review? Y/N).
- List what was **not** scanned (server-side logic, backend-driven content, binaries not provided, metadata not provided).

End with these account-level reminders, which a code scan can't verify (all `Reported` patterns):
- Don't resubmit a rejected build repeatedly without fixing the cited issue, and reply to App Review in detail.
- Don't post reviews from your own or associated accounts.
- Don't use bots, scripts or AI agents to operate App Store Connect.
- Keep developer accounts isolated (no shared signing machines, certificates, payment methods or backends with unrelated accounts).
- Keep the account's legal entity, address, D-U-N-S and bank details consistent, and change them one at a time with documents ready.
- Don't cancel a submission that is In Review and immediately upload the same build again.
- Be careful who you add to your App Store Connect team. A freelancer or contractor linked to a terminated account can drag your account into the same association.
- Don't register the same test devices (UDIDs) under multiple unrelated developer accounts.
- Keep v1.0 focused and stable. Ship monetization experiments (exit offers, paywall tests) and secondary features later, as separately reviewed updates.

## Background (for explaining findings)

- 3.2(f) is a clause of the Apple Developer Program License Agreement, not an App Review guideline. It covers interfering with the App Store and dishonest or fraudulent conduct. It penalizes the **account** (all apps, payouts frozen), while 4.3 usually rejects a single app.
- Typical Apple wording: "concept or feature switch schemes to evade the review process", "documented indications of fraudulent conduct", "after multiple resubmissions… remain unresolved".
- Appeals are rarely successful: in 2025, 10,127 of 193,035 terminations were appealed and 499 were reinstated (Apple Transparency Report). Prevention matters far more than appeal.
- In the same report, 192,702 of the 193,035 account terminations cited DPLA 3.2(f), and 90,608 apps were removed under 3.2(f), the largest removal reason.
- Key sources: App Review Guidelines (2.3.1, 2.5.1, 2.5.2, 2.5.19, 3.1.1, 3.1.2(a), 4.1, 4.3, 5.1, 5.6.x), Apple Developer News (16 Oct 2026 update), Apple's 2017 JSPatch/Rollout warning, the Trend Micro report on gambling apps switching content via server switches, and Apple Developer Forums termination threads.

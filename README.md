# Apple Termination Risk Scan

An [Agent Skill](https://agentskills.io) that audits an iOS app **before App Store submission** for the patterns Apple treats as dishonest or as evading review: the ones that escalate from a single rejection to **developer account termination** under DPLA 3.2(f) and the Developer Code of Conduct.

The skill walks your agent through a 13-category scan (review cloaking, hidden features, dynamic code and OTA updates, non-IAP payments, review manipulation, impersonation, private API, privacy, permission strings, and more), triages each hit against the actual release-build code, and produces a severity-ranked report with concrete fixes and ready-to-paste Notes for Review text.

It never suggests hiding anything from App Review. The fix is always one of: remove it, gate it to DEBUG builds, or disclose it.

## Install

```bash
npx skills add skyberk/apple-termination-skill
```

Pick the agents you want it installed to when prompted. To install non-interactively for one agent:

```bash
npx skills add skyberk/apple-termination-skill -a claude-code -y
```

Add `-g` to install it globally instead of into the current project. See the [skills CLI reference](https://github.com/vercel-labs/skills/blob/main/docs/commands.md) for all options.

### Claude Code plugin marketplace

The repo also ships a `.claude-plugin/marketplace.json`, so Claude Code users can install it as a plugin instead:

```bash
claude plugin marketplace add skyberk/apple-termination-skill
claude plugin install apple-termination-risk-scan@apple-termination-skill
```

## Usage

Open your agent inside the app's repository and ask for a pre-submission scan, for example:

> Run the Apple termination risk scan on this project before I submit to the App Store.

When installed with `npx skills` into Claude Code, you can also invoke it directly with `/apple-termination-risk-scan`.

The skill will:

1. Detect the stack and its release-build guards, so DEBUG-only code is ignored.
2. Run ripgrep scans across 13 risk categories and read the surrounding code before reporting anything.
3. Ask for your App Store metadata (name, subtitle, description, Notes for Review, policy URLs) and check it.
4. Produce a report: a one-line verdict, a findings table ordered CRITICAL to INFO, a feature-flag inventory, what was out of scope, and account-level reminders.

## Supported stacks

| Stack | What it reads |
|---|---|
| Swift / Objective-C | `*.swift`, `*.m`, `*.mm`, `*.h`, `Info.plist`, entitlements, `PrivacyInfo.xcprivacy`, `Podfile.lock`, `Package.resolved` |
| Kotlin Multiplatform / Compose Multiplatform | `shared/src/**`, `iosMain`, `commonMain`, `iosApp/**`, `libs.versions.toml`, `build.gradle.kts` |
| React Native / Expo | `*.js`, `*.jsx`, `*.ts`, `*.tsx`, `package.json`, `app.json`, `app.config.*`, `eas.json` |
| Flutter | `lib/**/*.dart`, `pubspec.yaml`, `pubspec.lock`, `ios/**` |
| Unity | `Assets/**/*.cs`, `Packages/manifest.json` |

An `.ipa` can also be inspected (`strings`, `otool -L`, `nm -u`, embedded frameworks).

## Requirements

- **ripgrep (`rg`)** on the agent's `PATH`. Install with `brew install ripgrep`, `apt install ripgrep`, or see the [ripgrep install guide](https://github.com/BurntSushi/ripgrep#installation).
- Any agent that supports [Agent Skills](https://agentskills.io): Claude Code, Codex, Cursor, OpenCode and [many more](https://github.com/vercel-labs/skills/blob/main/docs/agents.md).

## What it checks

| # | Category | Guideline |
|---|---|---|
| C1 | Hidden or dormant features, review cloaking | 2.5.19, 2.3.1(a) |
| C2 | Downloaded or dynamic code, OTA updates | 2.5.2, DPLA 3.3.2 |
| C3 | Payments and paywalls | 3.1.1, 3.1.2(a) |
| C4 | Review and rating manipulation | 5.6.1, 5.6.3, 3.2.2(x) |
| C5 | Impersonation and copycats | 4.1(b), 2.3.14 |
| C6 | Misleading functionality claims | 2.3.1(a) |
| C7 | AI and user-generated content safeguards | 1.2 |
| C8 | Private API | 2.5.1 |
| C9 | Privacy, recording and fingerprinting | 5.1.1, 5.1.2(iii), 2.5.14 |
| C10 | VPN and MDM | 5.4, 5.5 |
| C11 | Clone, template and spam signals | 4.3 |
| C12 | Permission usage descriptions | 5.1.1 |
| C13 | Update hygiene | Reported |

## Disclaimer

A code scan cannot verify account-level behavior and cannot guarantee approval. At best the skill reports "no high-risk patterns found in the scanned scope" and lists what was out of scope. It is not legal advice.

## License

[MIT](LICENSE) © Gökberk Yağcı

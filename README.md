# Garmin Connect Auth Add-on Repository

Home Assistant add-on that provides browser-based Garmin Connect authentication
using [garmin-givemydata](https://github.com/nrvim/garmin-givemydata)'s
SeleniumBase UC Chrome engine.

## Why?

Garmin's SSO login is protected by Cloudflare bot detection, which blocks
conventional HTTP-based authentication libraries. This add-on runs a real
Chrome browser (headless) inside a Docker container to perform the login —
the only approach confirmed working as of 2026.

## Installation

1. In Home Assistant, go to **Settings → Add-ons → Add-on Store**
2. Click the **⋮** menu (top right) → **Repositories**
3. Add: `https://github.com/mikejhill/garmin-givemydata-addon`
4. Find **Garmin Auth** in the store and click **Install**
5. Start the add-on

The [Garmin Connect integration](https://github.com/mikejhill/home-assistant-garmin_connect)
will automatically detect the running add-on and use it for authentication.

## How It Works

The add-on runs a lightweight HTTP API server on port 8099 (internal network only).
When you configure the Garmin Connect integration, it sends your credentials to the
add-on, which launches headless Chrome to perform the SSO login. The resulting
authentication tokens are returned to the integration for API access.

- Supports MFA (the integration's config flow prompts for the code)
- Browser profile is persisted across restarts for faster re-authentication
- No credentials are stored by the add-on — they are only used during the login flow

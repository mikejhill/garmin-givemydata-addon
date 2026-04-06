# Garmin Auth Add-on

This add-on provides browser-based Garmin Connect authentication for the
[Garmin Connect integration](https://github.com/mikejhill/home-assistant-garmin_connect).

## How It Works

The add-on runs a headless Chrome browser (via SeleniumBase UC mode) to perform
Garmin's SSO login flow. This bypasses Cloudflare bot detection that blocks
conventional HTTP-based authentication.

The add-on exposes a lightweight HTTP API on port 8099 (internal network only —
not accessible from outside your Home Assistant instance). The Garmin Connect
integration automatically detects the running add-on and uses it during the
config flow.

## Requirements

- Home Assistant OS or Supervised installation
- Sufficient RAM (the browser uses ~300–500 MB during authentication)

## Usage

1. Install and start this add-on
2. Go to **Settings → Devices & Services → Add Integration → Garmin Connect**
3. Enter your Garmin Connect username and password
4. If MFA is enabled, enter the code when prompted
5. The integration will automatically use the add-on for authentication

## Troubleshooting

- **Add-on won't start:** Check the add-on logs for errors
- **Login takes a long time:** Browser-based login takes 30–120 seconds — this is normal
- **Login fails after working previously:** Try restarting the add-on to reset the browser profile

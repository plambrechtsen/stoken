# stoken for Flipper Zero

A Flipper Zero app that generates RSA SecurID 128-bit tokencodes. It ports stoken's token algorithm and adds:

* **Multiple tokens**: one `.stokenrc`-style file per token in `/ext/stoken`, each with a `nickname` that shows on screen.
* **Time zone setting**: the Flipper's clock runs on local time, but SecurID codes are based on UTC. You need to select your local timezone offset in Settings to adjust from local time on the flipper to UTC. Also need +1 hour for DST.
* **USB keyboard typing**: press OK and the Flipper types your static PIN plus the current code into the connected computer.

```
stoken_app.c       GUI (code screen, menu, settings)
stoken_core.c      SecurID code implementation with AES/SHA-256/BASE64 via mbedtls
stoken_store.c     reads token files and settings from the SD card
stoken_hid.c       USB keyboard typing
example.stokenrc   Example .stokenrc token file
```

## Build and install

Using fbt build and deploy to your flipper

```sh
cd applications_user
mkdir stoken
cd stoken
git clone --depth 1 --no-checkout https://github.com/stoken-dev/stoken .
git sparse-checkout init --cone
git sparse-checkout set flipper
git checkout
cd ../../
./fbt fap_stoken
./fbt COMPACT=1 DEBUG=0 launch APPSRC=applications_user/stoken
```

The app was built and checked against the official release SDK 1.5.1. If your Flipper runs different firmware, build it with that firmware's SDK.

## Adding tokens

Make one file per token in `/ext/stoken/` on the SD card. The file name must
end in `.stokenrc` or `.rc`. A file called just `.stokenrc` also works. The
format is the same as stoken's `~/.stokenrc`, with some extra optional keys:

```
version 1
nickname Work VPN
token 258491750817210752367175001073261277346642631755724762324173166222072472716737543
pin 1234
```

| key        | required | meaning |
|------------|----------|---------|
| `version`  | yes      | must be `1` (same as stoken) |
| `token`    | yes      | token string: bare digits, a `com.rsa.securid://ctf?ctfData=...` / `http://127.0.0.1/securid/ctf?ctfData=...` URL, or a v3/v4 base64 string |
| `nickname` | no       | name shown on the Flipper (the rest of the line, spaces allowed). If left out, the file name is used |
| `pin`      | no       | token PIN for PIN-mode tokens, either plain digits or stoken's encrypted 64-hex-character form (needs `password`) |
| `password` | no       | password, if the token is password-protected |
| `devid`    | no       | device ID, if the token is bound to a device |

The easiest way to set up a token is to import it with desktop stoken, then copy the file:

```sh
stoken import --token 'com.rsa.securid://ctf?ctfData=...'   # leave the new password blank
cp ~/.stokenrc work.stokenrc
echo "nickname Work VPN" >> work.stokenrc
# copy work.stokenrc to /ext/stoken/ with qFlipper
```

XML `.sdtid` files are not supported on the Flipper. Convert them to a token string first with `stoken export --file token.sdtid`.

**Security:** token files and `settings.conf` (which holds the static PIN) are plain text on the SD card. Anyone with the SD card can copy your tokens. A `password` line adds no protection, because it is stored right next to the token.

## Using the app

**Code screen** (shown when the app starts; it opens the token you used last):

```
 Work VPN                    1/3
 ───────────────────────────────
            12345678
 Next 87654321               42s
 [██████████████░░░░░░░░░░░░░░]
 UTC 03:14:07        OK:PIN+code
```

* **Left/Right** (or Up/Down): switch to the previous or next token
* **OK**: type static PIN + code over USB (when the USB keyboard is on)
* **Back**: open the menu (token list + Settings). Back again exits.

The bottom line shows the time in UTC, so you can check your time zone
setting. When a token is within 14 days of expiring, the countdown is
replaced by `Exp Nd`.

**Settings:**

| item | meaning |
|------|---------|
| Time zone | the time zone your Flipper's clock is set to, from UTC-12:00 to UTC+14:00 in 15-minute steps. Example: New Zealand is UTC+12:00 in winter and UTC+13:00 during daylight saving. The Flipper has no daylight saving support, so you need to change this when the clocks change. Pick `UTC` if your Flipper's clock is already on UTC. |
| USB keyboard | On: the Flipper acts as a USB keyboard while the app is open, and OK types the code |
| Static PIN | 4–8 digits typed **before** the code (for "PIN + tokencode" logins). Click to set it |
| Clear static PIN | removes the static PIN |
| Press Enter | press Enter after typing the code |

Settings are saved to `/ext/stoken/settings.conf` when you leave the
Settings screen.

Notes on the USB keyboard:

* While the keyboard is on, the Flipper's USB serial port is unavailable
  (qFlipper can't connect). The normal USB mode comes back when you exit the
  app or turn the keyboard off.
* Digits are sent as top-row number keys. This works with US/UK and most
  other layouts, but not with layouts like AZERTY, where the number row
  needs Shift.
* The static PIN is typed in front of the code. This is different from the
  token-file `pin` key, which is mathematically merged into the code for
  PIN-mode software tokens.

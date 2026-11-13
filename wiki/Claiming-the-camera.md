# Claiming the camera

The firmware ships with **no accounts, no passwords and no SSH keys**. After you flash a camera,
you create its first admin yourself. That is called claiming it.

## Do it on a network only you use

Until it is claimed, **anyone who can reach the camera can claim it.** Claim it on an isolated
network or a direct cable, right after the install.

## The 30-minute window

- An unclaimed camera serves only the setup page, for **30 minutes after power-on**. Every other
  page redirects there.
- After 30 minutes every page says setup is closed. **Power-cycle the camera** and claim it
  within 30 minutes.
- The window counts from power-on. Setting the clock doesn't move it.
- Until it is claimed: RTSP and SSH don't start, ONVIF answers "not set up yet", and there are
  no snapshots.

## Claim in a browser

1. Open `https://<camera-ip>/setup`. Use the IP address, not a host name: the camera only
   answers setup at its own address.
   - The camera made its own certificate a moment ago, so your browser warns that it can't
     check it. That is expected for this first visit. You trust the camera's CA after the claim
     (see [HTTPS and the camera CA](HTTPS-and-the-camera-CA)).
   - If HTTPS isn't running (for example, the camera's address is outside the subnet the image was built for), setup
     works on `http://<camera-ip>/setup` instead.
2. Fill in:
   - **Admin name** (default `admin`): 1 to 32 of `A-Z a-z 0-9 . _ -`.
   - **Password**, twice: 8 to 64 printable ASCII characters, never shortened, no space at the
     start or end, not the same as the name.
   - **SSH public key** (optional): one line from a `.pub` file. Without one, SSH stays off until
     you add a key on the web UI's SSH keys page.
3. Submit. The page shows your **recovery code once**. Save it (see below).
4. **Download a first backup** (recommended; over HTTPS only). The same page asks for a backup
   passphrase, twice, then your browser asks you to log in with your new name and password, and
   the backup file downloads. It holds the settings, the admin, the SSH key and the camera's HTTPS
   CA, encrypted with that passphrase, and restores only on this camera. You can skip it and use
   the System page later (see [Settings reference](Settings-reference)).
5. Follow the link to `/ui/` and log in with your new name and password.

## Restore a backup instead of claiming

If the camera was set up before and you kept its backup (`.cambak`), the setup page can restore
it instead: choose the file under **Or restore this camera's backup**, enter its passphrase and
submit. The camera checks the file, restores everything, reboots, and comes back claimed with the
backup's admin and settings. Only this camera's own backup works; a wrong passphrase counts as a
failed login.

## Claim from a terminal

[`scripts/cam-claim.py`](https://github.com/mlaify/openlens-fw/blob/main/scripts/cam-claim.py)
does the same as the setup page. It uses only Python's standard library.

```sh
python3 scripts/cam-claim.py <camera-ip>
```

- It asks for the admin name and the password (twice, never shown), and checks the password
  rules before sending anything.
- It offers your `~/.ssh/*.pub` keys to choose from. Or use `--key <file>.pub`, or `--no-key`.
- It prints the TLS certificate's SHA-256 fingerprint. `--pin <sha256>` makes it refuse any
  other certificate.
- It prints the recovery code once and saves it to
  `~/.config/cam-firmware-dev/recovery-<camera-ip>.txt` (mode 0600).
- `--http` claims over plain HTTP, for a camera whose HTTPS isn't running.
- `--backup <file>` downloads a first backup right after the claim (HTTPS only). It asks for the
  backup's passphrase twice before claiming, and never writes over an existing file.
- `--restore <file>` restores this camera's backup at setup instead of claiming it (it asks for
  the passphrase once).

## The recovery code

- 26 characters, shown in groups of 4. Case, spaces and dashes don't matter when you type it.
- The camera keeps only a slow hash of it, never the code.
- It resets an admin's password at `/recover`. Keep it like a password: anyone with it can reset
  your admin password in the 30 minutes after a power-on.
- Each use replaces it with a new code, shown once. If your old code stops working, someone may
  have used it: check the log (see [Troubleshooting](Troubleshooting)).

## Lost your password: `/recover`

1. Power-cycle the camera. `/recover` is open only in the **30 minutes after power-on**.
2. Open `https://<camera-ip>/recover`.
3. Enter the admin name (leave it empty for the admin the code was made for), the recovery code
   and a new password twice.
4. The page shows the **new** recovery code once. The old one no longer works.

Wrong codes count as failed logins: 5 in a minute from one address lock that address for the
rest of the minute.

## Other ways back in

- **With an SSH key:** log in as root and set a new password:

  ```sh
  ssh root@<camera-ip>
  echo '<new-password>' | camcfg user passwd <admin-name>
  ```

  Mind your shell history when a password is on the command line.
- **Lost the code but still have SSH:** store a new code with `camcfg recovery set` (it reads a
  26-character code of `A-Z` and `2-7` on stdin).
- **Lost the code and every admin SSH key:** there is no way back over the network; the
  CH341A programmer is the only route (see [Installing](Installing)). The accounts live in
  `/mnt/nand/cam` on the DATA partition, which a `rootfs` reflash doesn't touch. The camera is
  unclaimed again only once that folder is gone, and the repository has no tested procedure
  for removing it with the programmer yet.

The camera has no reset button.

## After the claim

- `/setup` returns 404 from now on.
- The web UI and `camcfg` won't delete or demote the last admin.
- Add more users on the web UI's Users page, for example an operator account for your NVR. See
  [NVR setup](NVR-setup).
- Trust the camera's CA in your browser. See [HTTPS and the camera CA](HTTPS-and-the-camera-CA).

# MCP DataBlind – Setup Guide

This guide takes you from nothing to a working **MCP DataBlind** policy protecting an API or MCP server in your own Anypoint Platform account. Follow the steps in order; each one ends with a quick check so you know it worked before moving on.

**What the policy does:** it sits on the response path of an API or MCP server running on Anypoint **Omni Gateway (Flex Gateway)**. It sends the sensitive parts of each response to the DataBlind service, which encrypts or masks them, and the client receives the protected response instead of the original.

**How you get it:** you build the policy from this repository and publish it to **your own** Anypoint Exchange. Then it shows up in API Manager as a custom policy you can apply to your APIs and MCP servers.

```
 Your machine                 Your Anypoint account                Runtime
┌────────────────┐  release  ┌──────────────────────┐  apply    ┌───────────────┐
│ this repo      │ ───────▶  │ Exchange (policy)     │ ───────▶  │ Omni Gateway  │
│ ./release.sh   │           │ API Manager (apply)   │           │ API / MCP     │
└────────────────┘           └──────────────────────┘           └───────────────┘
```

---

## Before you start

You need:

| What | Why |
|---|---|
| An Anypoint Platform account | The policy is published into one of your business groups |
| Permission to publish to Exchange in that business group (**Exchange Contributor**) | Releasing the policy |
| An Omni Gateway (Flex Gateway) **1.6.1 or newer**, connected to your account, with an API or MCP server on it | Somewhere to apply the policy |
| The **DataBlind service URL** and **API key** | The policy calls this service to protect the data. To get a key, contact **mulesoftconnector@ztensor.com** |
| A Mac or Linux computer (on Windows, use WSL) | `release.sh` is a bash script |

---

## Step 1 – Install the tools

Install these once. Run the check command after each one.

| # | Tool | Install | Check |
|---|---|---|---|
| 1 | **Node.js** 18 or newer | <https://nodejs.org> (or `brew install node`) | `node --version` |
| 2 | **Anypoint CLI v4** | `npm install -g anypoint-cli-v4` | `anypoint-cli-v4 --version` |
| 3 | **PDK plugin** for the CLI | `anypoint-cli-v4 plugins:install anypoint-pdk-plugin` | `anypoint-cli-v4 plugins` (must list `anypoint-pdk-plugin`) |
| 4 | **Rust** 1.87 or newer | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | `rustc --version` |
| 5 | **make** | Already on macOS/Linux with developer tools | `make --version` |
| 6 | **git** | <https://git-scm.com> | `git --version` |

You do **not** need to install the WebAssembly target or `cargo-anypoint` by hand. The release script checks for them and installs them if they are missing.

> Docker is only needed if you want to run the project's integration tests. It is not needed to release or use the policy.

---

## Step 2 – Get the code

```bash
git clone https://github.com/datablind/dblpolicy-omnigw.git
cd dblpolicy-omnigw
```

---

## Step 3 – Create credentials for Anypoint

The release script needs to log in to your Anypoint account. You can use either a **Connected App** (recommended) or your **username and password**.

### Option A – Connected App (recommended)

1. Sign in to Anypoint Platform and open **Access Management → Connected Apps**.
2. Click **Create app**.
3. Give it a name (for example `datablind-release`) and choose **App acts on its own behalf (client credentials)**.
4. Click **Add scopes** and add **Exchange Contributor** for the business group you want to publish to.
5. Also add **View Organization** for the same business group. This lets the script show you a list of your business groups to pick from. It is optional; without it you can paste the business group ID instead.
6. Save, then copy the **Client ID** and **Client Secret**. The secret is shown only once.

### Option B – Username and password

Use your normal Anypoint login. Your user must have **Exchange Contributor** (or Exchange Administrator) permission in the target business group. If your account uses single sign-on or multi-factor login, use Option A instead.

---

## Step 4 – Know your business group

Exchange assets are published into one business group, identified by its **ID** (a UUID such as `2fffe86c-fd03-4170-a6cf-c8bda6617fa2`).

To find it: **Access Management → Business Groups →** click your group → copy the **ID**. The release script also lists the groups your account can reach, so you can usually pick from a list instead.

---

## Step 5 – Release the policy to your Exchange

From the project folder, run:

```bash
./release.sh
```

The script walks you through these prompts:

**1. Account.** If you are already logged in, it shows who you are and asks *Proceed with this account? [Y/n]*.

- Press **Enter** to use the current login.
- Type **n** to use a different account. You then choose:
  - **1 – For this release only** (default): the credentials are used for this run and never saved. Your existing login is untouched.
  - **2 – Switch permanently**: the saved login is replaced.

  Then pick Connected App or username/password, and enter the credentials. Leave *Business Group* and *Control plane host* blank unless you need them. EU accounts use the host `eu1.anypoint.mulesoft.com`.

**2. Business group.** The script reads `group_id` from `Cargo.toml` and checks it against your account:

- If it matches a business group you can access, it asks *Publish to this business group? [Y/n]*.
- If not, it shows a numbered list. Pick a number or paste the correct ID. The script updates `Cargo.toml` for you, so you never need to edit it by hand.

**3. Version.** The script checks whether the version in `Cargo.toml` is already published in your Exchange. Exchange never accepts the same version twice.

- If it is free, the script continues.
- If it is taken, the script suggests the next version (for example `1.8.15` → `1.8.16`). Press **Enter** to accept it or type your own (format `MAJOR.MINOR.PATCH`).

**4. Build and publish.** The script checks that the build tools are installed (and installs them if not), builds the policy, and publishes it to Exchange. The first build can take a few minutes.

When it finishes you will see:

```
==> Done. Policy released to Anypoint Exchange.
```

> **Prefer to run the steps yourself?** Log in with `anypoint-cli-v4 conf client_id <ID>` and `anypoint-cli-v4 conf client_secret <SECRET>`, set `group_id` and `version` in `Cargo.toml`, then run `make setup` (first time only), `make build`, and `make release`.

### Check it worked

Open **Anypoint Exchange**, switch to your business group, and look for **MCP DataBlind**. You should see the new version listed.

---

## Step 6 – Apply the policy to an API or MCP server

1. Open **API Manager** and select the environment where your Omni Gateway runs.
2. Open the API or MCP server instance you want to protect.
3. Go to **Policies** and click **Add policy**.
4. Under the **Custom** category, choose **MCP DataBlind**, then pick the version you just released.
5. Fill in the settings (see the reference below), then click **Apply**.

The policy takes effect on the gateway within a short time. It runs on the **response**, so clients simply see protected data in the replies they already get.

---

## Settings reference

| # | Setting | What to enter |
|---|---|---|
| 1 | **Sensitive Data Encryption** | `None` – no encryption.<br>`Specify Sensitive fields` – you list the fields to protect.<br>`Determine Sensitive fields using NLP` – the service finds personal data (financial, contact, identity, auth, device, tax, health, vehicle, government ID, URL) on its own. |
| – | **Sensitive Fields** | Shown only for *Specify Sensitive fields*. A JSON object that maps each field to a type, for example `{ "Name" : "FE:PersonName", "TaxId" : "FE:SSN" }`. |
| 2 | **Message Filter Configuration** | `None`, `Include` (keep only matching messages) or `Exclude` (remove matching messages). |
| – | **Filter Match Operator** | `OR` (any condition matches) or `AND` (all conditions match). |
| – | **Filter Conditions** | One or more rows of **Field** (JSON path such as `person.phone`), **Match Type** (`Simple`, `Exact`, `Regex`) and **Value**. Use commas for several values (`123,456`). |
| 3 | **DataBlind Service URI** | The base URL of the DataBlind service, including the stage, for example `https://…execute-api.us-west-1.amazonaws.com/Dev`. Use the URL you were given. |
| 4 | **DataBlind Service Key** | The API key for the service (sent as the `x-api-key` header). The placeholder text must be replaced or calls fail with **403 Forbidden**. |
| 5 | **Tweak** | A value that makes encryption specific to each record, as a DataWeave expression. The default `#[payload.Id default '12345678']` uses the `Id` field of the response. |
| 6 | **Eligible HTTP Codes** | Only responses with these status codes are protected, for example `#['200,201,202,205,213']`. Other responses pass through untouched. |
| 7 | **DataBlind Token** | A header that, together with the passphrase, lets a trusted caller receive the original unprotected data. Default: the `dataBlindToken` request header. |
| 8 | **DataBlind Passphrase** | The caller's passphrase, in the form `<workload GUID>:<passphrase>`. **Every** request must carry it: the workload GUID in front of the first `:` tells the service which DataBlind workload, and so which app zone's key, to use, and a request without one is blocked. Together with the token it lets a trusted caller receive the original unprotected data. Default: the `dataBlindPassphrase` request header. See [Key resolution](#key-resolution). |
| 9 | **Debug Logging** | Leave **off**. Turning it on writes request and response contents to the gateway logs, which may include sensitive data. Use it only in development environments. |

---

## Key resolution

The policy does not hold the DataBlind key and never sees it. It tells the DataBlind service which workload the request belongs to, and the service gets the key of that workload's app zone from DataBlind. The workload comes from the caller: it is the GUID at the start of the `dataBlindPassphrase`.

**Set up in DataBlind**

1. Open the app zone. The organization must have *save sensitive data* turned on, so the zone's key is stored.
2. Register a workload for **DataBlind** in that app zone, for each caller (or kind of caller), and note its **GUID**.
3. When you create an override token, choose the app zone **and the workload**. The passphrase you must send is shown as `<workload GUID>:<passphrase>`.

**What callers must send**

Every request through the policy must carry a `dataBlindPassphrase` that starts with the caller's workload GUID and a colon, whether or not it is asking for unprotected data. There is nothing to fill in on the policy for this. A request whose passphrase is missing or does not start with a GUID and a colon is **blocked** (the response is replaced by an error), never returned unprotected.

The DataBlind service itself must be set up to reach DataBlind (its URL and a secret that DataBlind shares with it). That is done on the service, not in the policy.

**What happens on each call**

- Every request to the DataBlind service carries the workload GUID taken from the passphrase and no key. The service asks DataBlind for the key each time, proving who it is with the shared secret, and DataBlind only answers if the workload is active, is a DataBlind workload, and its app zone is active.
- The caller chooses the workload, so the policy cannot restrict which zone's key a request uses: that is decided in DataBlind. Deactivating a workload, or its app zone, withdraws that caller's access.
- A caller who sends `dataBlindToken` and a `dataBlindPassphrase` of the form `<workload GUID>:<passphrase>` has both passed on **unchanged** to the DataBlind service, which validates them and returns the unprotected data. The policy does not check them itself. Deactivating an override token, or the workload it was issued for, does **not** stop it: the token works until it expires.
- If the DataBlind service reports a processing failure, the response is blocked with an error instead of returning the failure text in place of the data.

---

## Step 7 – Test it

1. Call your API or MCP server as you normally would.
2. Check the response:
   - The sensitive fields should now be encrypted or masked.
   - The response has a **`DataBlind-Dictum`** header describing what the policy did.
3. If you have been issued an override token and passphrase, call again with them in the `dataBlindToken` and `dataBlindPassphrase` headers. You should get the unprotected data back.

If the response is **not** protected, see the troubleshooting table below.

---

## Releasing a new version later

1. Pull the latest code (`git pull`) or make your changes.
2. Run `./release.sh`. The script spots that the current version is already published and offers the next one.
3. In API Manager, open the applied policy and **edit** it to select the new version.

---

## Troubleshooting

| Problem | Likely cause and fix |
|---|---|
| `anypoint-cli-v4: command not found` | npm's global folder is not on your `PATH`. Run `export PATH="$(npm config get prefix)/bin:$PATH"` and add it to your shell profile. |
| `pdk` commands "not recognized" | The PDK plugin is missing. Run `anypoint-cli-v4 plugins:install anypoint-pdk-plugin`. |
| *Authentication failed* in `release.sh` | The client ID/secret or username/password is wrong, or the control plane host is wrong (EU accounts need `eu1.anypoint.mulesoft.com`). Re-run and re-enter them. |
| Business group list is empty, or your group is missing | The Connected App lacks **View Organization**. Paste the business group ID by hand when asked. |
| Release fails with a permission error | The account or Connected App lacks **Exchange Contributor** in that business group. Ask an organization admin to grant it. |
| Release fails because the version exists | Let the script pick a new version, or set `version` in `Cargo.toml` to an unused one. |
| **MCP DataBlind** is missing in API Manager | Check Exchange: is it in the same business group as your environment's organization? Check the gateway is version 1.6.1 or newer. |
| Calls return **403 Forbidden** from DataBlind | The **DataBlind Service Key** is still the placeholder or is wrong. Contact **mulesoftconnector@ztensor.com** for a key. |
| A policy that used the old **DataBlind Key**, **Key ID**, **Key Service URI** or **Policy Access Key** settings stops working after you move it to this version | Those settings were removed. Register a DataBlind workload for each caller and have them send `<workload GUID>:<passphrase>` in `dataBlindPassphrase`, then re-apply. Always try a new version in a non-production environment first. |
| Calls return **500** and the gateway log says *No usable workload GUID in the pass phrase* | The request's `dataBlindPassphrase` header is missing, or does not start with a GUID and a colon. Send `<workload GUID>:<passphrase>`. |
| Calls return **500** `DataBlind policy failed to apply` | The DataBlind service reported a failure. Most often it could not get the key: the workload is inactive or not a DataBlind workload, its app zone is inactive or has no stored key, or the secret shared between the service and DataBlind does not match. Check the DataBlind service's log and the `app-zone-key-resolve` function's log in DataBlind. |
| An override token no longer unprotects data | The token expired or was deactivated, the workload is inactive, or the passphrase is missing the `<workload GUID>:` prefix. |
| Response is not protected | The response status code is not in **Eligible HTTP Codes**, or **Sensitive Data Encryption** is `None`, or the **Sensitive Fields** names do not match your data. |
| `make: No rule to make target` | You ran `make` outside the project folder. `cd` into the project and try again. |
| Build fails with a missing target or `cargo-anypoint` | Run `make setup`, or just run `./release.sh`, which does this when needed. |

---

## Keeping it secure

- Keep **Debug Logging** off outside development environments.
- Treat the **Service Key** and the Connected App secret like passwords. Do not commit them to git or share them in chat.
- Use a Connected App with only the scopes it needs, and rotate its secret if it is ever exposed.
- The DataBlind key is neither stored in nor passed through the policy. Deactivating a workload in DataBlind withdraws its access without changing the key.
- The workload GUID comes from the caller, so who may use which zone's key is decided entirely by DataBlind (the workload must exist, be active and belong to an active app zone). Do not register workloads for callers that should not reach a zone's key.
- Choose **For this release only** in `release.sh` when releasing from a shared machine, so no credentials are left behind.

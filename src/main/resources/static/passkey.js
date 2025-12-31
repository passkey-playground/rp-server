const $ = (selector) => document.querySelector(selector);

const logEl = $("#log");
const registerBtn = $("#register-btn");
const authenticateBtn = $("#authenticate-btn");

function log(message, level = "info") {
  const time = new Date().toLocaleTimeString();
  const entry = `[${time}] ${message}`;
  logEl.textContent += `${entry}\n`;
  logEl.scrollTop = logEl.scrollHeight;

  if (level === "error") {
    console.error(message);
  } else {
    console.log(message);
  }
}

function setBusy(button, isBusy) {
  button.disabled = isBusy;
  button.textContent = isBusy ? "Working..." : button.dataset.label;
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function bufferToBase64Url(buffer) {
  return bufferToBase64(buffer)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBuffer(base64url) {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function postJson(url, body, rpId) {
  const headers = { "Content-Type": "application/json" };
  if (rpId) {
    headers.rp_id = rpId;
  }

  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (error) {
    data = { raw: text };
  }

  if (!response.ok) {
    throw new Error(data.errorMessage || data.message || response.statusText);
  }

  return data;
}

function buildAuthenticatorSelection() {
  const attachment = $("#reg-attachment").value || undefined;
  const residentKey = $("#reg-residentkey").value || undefined;
  const userVerification = $("#reg-userverification").value || undefined;
  const requireResidentKey = $("#reg-require-rk").checked;

  if (!attachment && !residentKey && !userVerification && !requireResidentKey) {
    return undefined;
  }

  return {
    authenticatorAttachment: attachment,
    residentKey,
    userVerification,
    requireResidentKey,
  };
}

async function handleRegister() {
  const username = $("#reg-username").value.trim();
  const displayName = $("#reg-displayname").value.trim();
  const rpId = $("#reg-rpid").value.trim();
  const attestation = $("#reg-attestation").value;

  if (!username || !displayName) {
    log("Registration requires username and display name.", "error");
    return;
  }

  try {
    setBusy(registerBtn, true);
    log("Requesting registration options...");

    const options = await postJson(
      "/fido2/registration/options",
      {
        username,
        displayName,
        attestation,
        authenticatorSelection: buildAuthenticatorSelection(),
        extensions: { credProps: true },
      },
      rpId
    );

    const publicKey = {
      challenge: base64UrlToBuffer(options.challenge),
      rp: options.rp,
      user: {
        id: base64UrlToBuffer(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams,
      timeout: options.timeout,
      attestation: options.attestation || "none",
      authenticatorSelection: options.authenticatorSelection || undefined,
      excludeCredentials: (options.excludeCredentials || []).map((cred) => ({
        id: base64UrlToBuffer(cred.id),
        type: cred.type || "public-key",
      })),
      extensions: options.extensions || { credProps: true },
    };

    log("Opening platform authenticator...");
    const credential = await navigator.credentials.create({ publicKey });

    if (!credential) {
      throw new Error("No credential returned by authenticator.");
    }

    const response = credential.response;
    const payload = {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64Url(response.attestationObject),
        clientDataJSON: bufferToBase64Url(response.clientDataJSON),
        transports: typeof response.getTransports === "function" ? response.getTransports() : [],
      },
    };

    log("Submitting attestation result...");
    await postJson("/fido2/registration/result", payload, rpId);
    log("Passkey registration completed.");
  } catch (error) {
    log(`Registration failed: ${error.message}`, "error");
  } finally {
    setBusy(registerBtn, false);
  }
}

async function handleAuthenticate() {
  const username = $("#auth-username").value.trim();
  const rpId = $("#auth-rpid").value.trim();
  const userVerification = $("#auth-userverification").value;

  if (!username) {
    log("Authentication requires a username.", "error");
    return;
  }

  try {
    setBusy(authenticateBtn, true);
    log("Requesting authentication options...");

    const options = await postJson(
      "/fido2/authentication/options",
      {
        username,
        userVerification,
      },
      rpId
    );

    const allowCredentials = options.allowCredentials || options.allowedCreds || [];

    const publicKey = {
      challenge: base64UrlToBuffer(options.challenge),
      rpId: options.rpId,
      timeout: options.timeout,
      allowCredentials: allowCredentials.map((cred) => ({
        id: base64UrlToBuffer(cred.id),
        type: cred.type || "public-key",
      })),
      userVerification: userVerification || "preferred",
    };

    log("Waiting for passkey assertion...");
    const assertion = await navigator.credentials.get({ publicKey });

    if (!assertion) {
      throw new Error("No assertion returned by authenticator.");
    }

    const response = assertion.response;
    const clientExtensions = typeof assertion.getClientExtensionResults === "function"
      ? assertion.getClientExtensionResults()
      : {};

    const payload = {
      id: assertion.id,
      type: assertion.type,
      response: {
        authenticatorData: bufferToBase64Url(response.authenticatorData),
        clientDataJSON: bufferToBase64(response.clientDataJSON),
        signature: bufferToBase64Url(response.signature),
        userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : "",
      },
      serverPublicKeyCredential: {
        extensions: clientExtensions,
      },
    };

    log("Submitting assertion result...");
    await postJson("/fido2/authentication", payload, rpId);
    log("Passkey authentication completed.");
  } catch (error) {
    log(`Authentication failed: ${error.message}`, "error");
  } finally {
    setBusy(authenticateBtn, false);
  }
}

registerBtn.dataset.label = registerBtn.textContent;
authenticateBtn.dataset.label = authenticateBtn.textContent;

registerBtn.addEventListener("click", handleRegister);
authenticateBtn.addEventListener("click", handleAuthenticate);

if (!window.PublicKeyCredential) {
  log("WebAuthn is not supported in this browser.", "error");
}

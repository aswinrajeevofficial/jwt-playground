function convertToJWK() {
  const pemInput = document.getElementById("pemInput").value;
  const keyId = document.getElementById("keyId").value;
  const algorithm = document.getElementById("algorithm").value;

  try {
    // Parse the PEM key
    const pubKey = KEYUTIL.getKey(pemInput);

    // Generate the JWK
    const jwk = KEYUTIL.getJWKFromKey(pubKey);

    // Add additional properties
    if (keyId.length != 0) {
      jwk.kid = keyId;
    }
    jwk.alg = algorithm;
    jwk.use = "sig"; // Always set to 'sig' for signing

    // Convert JWK to string for display
    let liferayOutput = {
      keys: [],
    };
    liferayOutput.keys[0] = jwk;
    const jwkString = JSON.stringify(liferayOutput, null, 2);
    // Display the result
    document.getElementById("jwkOutput").textContent = jwkString;
  } catch (error) {
    document.getElementById("jwkOutput").textContent =
      "Error: " + error.message;
  }
}

document.getElementById("jwtForm").addEventListener("submit", function (e) {
  e.preventDefault();

  const header = JSON.parse(document.getElementById("header").value);
  const payload = JSON.parse(document.getElementById("payload").value);
  const privateKey = document.getElementById("privateKey").value;
  const publicKey = document.getElementById("publicKey").value;

  try {
    // Create JWT
    const jwt = KJUR.jws.JWS.sign(header.alg, header, payload, privateKey);
    console.log(jwt);
    // Verify JWT (optional, but good for demonstration)
    const isValid = KJUR.jws.JWS.verifyJWT(jwt, publicKey, {
      alg: [header.alg],
    });

    if (isValid) {
      document.getElementById("jwt").textContent = jwt;
    } else {
      document.getElementById("jwt").textContent =
        "JWT verification failed. Please check your inputs.";
    }
  } catch (error) {
    document.getElementById("jwt").textContent = "Error: " + error.message;
  }
});

async function generateKeyPair() {
  try {
    // Generate an RSA key pair
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );

    // Export the private key
    const privateKey = await window.crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );
    const privateKeyBase64 = btoa(
      String.fromCharCode.apply(null, new Uint8Array(privateKey))
    );
    const privatePem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64
      .match(/.{1,64}/g)
      .join("\n")}\n-----END PRIVATE KEY-----`;

    // Export the public key
    const publicKey = await window.crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeyBase64 = btoa(
      String.fromCharCode.apply(null, new Uint8Array(publicKey))
    );
    const publicPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64
      .match(/.{1,64}/g)
      .join("\n")}\n-----END PUBLIC KEY-----`;

    // Display the keys
    document.getElementById("privateKeyOutput").textContent = privatePem;
    document.getElementById("publicKeyOutput").textContent = publicPem;
  } catch (error) {
    console.error("Error generating key pair:", error);
  }
}

document
  .getElementById("generateKeys")
  .addEventListener("click", generateKeyPair);
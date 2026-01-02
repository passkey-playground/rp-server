async function triggerPasskeyAuthentication(authOptions) {
    try {
        // Decode base64 challenge and any other necessary options for WebAuthn API
        const publicKeyCredentialRequestOptions = {
            challenge: Uint8Array.from(atob(authOptions.challenge), c => c.charCodeAt(0)),
            user: {
                id : "NjVmVUNUbHFQbE9TazIydGtya0oybThJMk1FaHBGNGZDSV9wZG9zTUF6aw==",
                displayName : "Test Display Name"
            },
            rp: {
                id: authOptions.rpId
            },
            allowCredentials: authOptions.allowCredentials.map(cred => ({
                id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)),
                type: cred.type,
                transports: ["internal"],
            })),
            timeout: authOptions.timeout,
            userVerification: authOptions.userVerification || 'preferred',
        };

        // Trigger the WebAuthn API to perform passkey authentication
        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions,
        });

        // Process the assertion and send the response back to your RP server for verification
        const credential = {
            id: assertion.id,
            rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.rawId))),
            type: assertion.type,
            response: {
                authenticatorData: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.authenticatorData))),
                clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.clientDataJSON))),
                signature: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.signature))),
                userHandle: assertion.response.userHandle ? btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.userHandle))) : null
            }
        };

        console.log('Credential created:', JSON.stringify(credential));
        // Post credential to your RP server for validation
        return credential;
    } catch (error) {
        console.error('Error during passkey authentication:', error);
        throw error;
    }
}

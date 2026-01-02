async function createCredentialFromResponse(rpServerResponse) {
    // Convert the challenge from a base64-encoded string to a Uint8Array
    const challenge = Uint8Array.from(atob(rpServerResponse.challenge), c => c.charCodeAt(0));

    // Convert user ID from a base64-encoded string to a Uint8Array
    const userId = Uint8Array.from(atob(rpServerResponse.user.id), c => c.charCodeAt(0));

    // Construct the options object required for navigator.credentials.create()
    const publicKey = {
        rp: {
            name: rpServerResponse.rp.name,
            id: rpServerResponse.rp.id,
            icon: rpServerResponse.rp.icon
        },
        user: {
            id: userId,
            name: rpServerResponse.user.name,
            displayName: rpServerResponse.user.displayName
        },
        challenge: challenge,
        pubKeyCredParams: rpServerResponse.pubKeyCredParams,
        timeout: rpServerResponse.timeout,
        excludeCredentials: rpServerResponse.excludeCredentials.map(cred => ({
            type: cred.type,
            id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0))
        })),
        authenticatorSelection: rpServerResponse.authenticatorSelection,
        attestation: rpServerResponse.attestation,
        extensions: rpServerResponse.extensions
    };

    try {
        // Call navigator.credentials.create to create the credential
        const credential = await navigator.credentials.create({ publicKey });
        console.log('Credential created:', JSON.stringify(credential));


        // The client can now send this credential back to the RP server for registration completion
        return credential;
    } catch (error) {
        console.error('Error creating credential:', error);
        throw error;
    }
}

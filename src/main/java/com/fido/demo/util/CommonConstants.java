package com.fido.demo.util;

public class CommonConstants {



    // Default values for certain fields
    public static final String ATTESTATION_NONE_VALUE = "none";
    public static final String USER_VERIFICATINO_PREFERRED_STRING = "preferred";
    public static final String AUTHN_ATTACHMENT_PLATFORM_STRING = "platform";
    public static final int CHALLENGE_DEFAULT_LENGTH = 32;
    public static final int SESSION_ID_DEFAULT_LENGTH = 32;
    //public static final String DEFAULT_RP_ID="pp-signal-sdk-demo.netlify.app";
    public static final String DEFAULT_RP_ID="www.sowmya.com";


    public static final String ATTESTED_CREDENTIAL_DATA = "attested_credential_data";
    public static final String ATTESTATION_STATEMENT_KEY = "attestation_statement";
    public static final String RP_ID_HASH = "rp_id_hash";
    public static final String AUTHENTICATOR_DATA = "AUTHENTICATOR_DATA";
    public static final String COLLECTED_CLIENT_DATA = "COLLECTED_CLIENT_DATA";
    public static final String AUTHENTICATOR_TRANSPORTS = "AUTHENTICATOR_TRANSPORTS";

    // names for db column or column value (for settings)
    public static final String ATTESTATION = "attestation";
    public static final String REQUIRE_USER_VERIFICATION = "require_user_verification";
    public static final String REQUIRE_RESIDENT_KEY = "require_resident_key";
    public static final String AUTHENTICATOR_ATTACHMENT = "authenticator_attachment";

}

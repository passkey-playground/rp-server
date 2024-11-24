package com.fido.demo.util;

import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import com.fido.demo.controller.pojo.PubKeyCredParam;
import com.fido.demo.data.entity.RelyingPartyConfigEntity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;



@Component
public class RpUtils {

    public List<PubKeyCredParam> getPubKeyCredParam(List<RelyingPartyConfigEntity> rpConfigs) {
        RelyingPartyConfigEntity algorithms = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals("public_key_alg"))
                                                    .findFirst()
                .orElse(null);

        if (algorithms == null) {
            throw new RuntimeException("No Algorithms found in RelyingPartyConfig");
        }

        String alg = algorithms.getSettingValue();

        String[] tokens = alg.split(",");
        List<PubKeyCredParam> pubKeyCredParam = new ArrayList<PubKeyCredParam>();

        for(int i=0; i<tokens.length; i++) {
            PubKeyCredParam p = PubKeyCredParam.builder()
            .type("public-key")
            .alg(Integer.parseInt(tokens[i]))
            .build();
            pubKeyCredParam.add(p);
        }

        return pubKeyCredParam;
    }

    public long getTimeout(List<RelyingPartyConfigEntity> rpConfigs){
        RelyingPartyConfigEntity timeout = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals("timeout"))
                                                    .findFirst().orElse(null);

        if(timeout == null){
            return 180000L;
        }

        String value = timeout.getSettingValue();
        return Long.parseLong(value);

    }

    public String getAttestation(List<RelyingPartyConfigEntity> rpConfigs){
        RelyingPartyConfigEntity attestation = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.ATTESTATION))
                                                    .findFirst().orElse(null);
        if(attestation == null){
            return CommonConstants.ATTESTATION_NONE_VALUE;
        }
        return attestation.getSettingValue();
    }

    public AuthenticatorSelection getAuthenticatorSelection(List<RelyingPartyConfigEntity> rpConfigs){
        /*
        * setting_name
        * require_user_verification
        * authenticator_attachment
        * require_resident_key
        * */
        RelyingPartyConfigEntity userVerificationConfig = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.REQUIRE_USER_VERIFICATION))
                                                    .findFirst().orElse(null);

        RelyingPartyConfigEntity requireResidentKey = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.REQUIRE_RESIDENT_KEY))
                                                    .findFirst().orElse(null);

        RelyingPartyConfigEntity authenticatorAttachment = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.AUTHENTICATOR_ATTACHMENT))
                                                    .findFirst().orElse(null);

        AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection();
        authenticatorSelection.setUserVerification(userVerificationConfig == null ? CommonConstants.USER_VERIFICATINO_PREFERRED_STRING : userVerificationConfig.getSettingValue()); // ToDo : move to constants
        authenticatorSelection.setRequireResidentKey(requireResidentKey == null ? false : Boolean.valueOf(requireResidentKey.getSettingValue()));
        authenticatorSelection.setAuthenticatorAttachment(authenticatorAttachment == null ? CommonConstants.AUTHN_ATTACHMENT_PLATFORM_STRING : authenticatorAttachment.getSettingValue()); // ToDo : reconsider the default value and move to constants

        return authenticatorSelection;
    }
}

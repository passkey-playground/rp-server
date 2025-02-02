package com.fido.demo.util;

import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import com.fido.demo.controller.pojo.PubKeyCredParam;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.service.pojo.CermonyBO;
import com.fido.demo.data.entity.RPConfigEntity;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.repository.RPConfigRepository;
import com.fido.demo.data.repository.RPRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;



@Component
public class RpUtils {

    @Autowired
    RPRepository rpRepository;

    @Autowired
    RPConfigRepository rpConfigRepository;

    public RP getRP(){
        //NOTE: FIDO conformane tests doesn't have RP_ID in the request, default to an RP
        RelyingPartyEntity rpEntity = rpRepository.findByRpId(CommonConstants.DEFAULT_RP_ID);
        if(rpEntity == null){
            throw new ResourceNotFoundException("RP not found");
        }
        return RP.builder()
                .id(rpEntity.getRpId())
                .name(rpEntity.getName())
                .origin(rpEntity.getOrigin())
                .build();
    }

    public List<PubKeyCredParam> getPubKeyCredParam(List<RPConfigEntity> rpConfigs) {
        RPConfigEntity algorithms = rpConfigs.stream()
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

    public long getTimeout(List<RPConfigEntity> rpConfigs){
        RPConfigEntity timeout = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals("timeout"))
                                                    .findFirst().orElse(null);

        if(timeout == null){
            return 180000L;
        }

        String value = timeout.getSettingValue();
        return Long.parseLong(value);

    }

    public String getAttestation(List<RPConfigEntity> rpConfigs){
        RPConfigEntity attestation = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.ATTESTATION))
                                                    .findFirst().orElse(null);
        if(attestation == null){
            return CommonConstants.ATTESTATION_NONE_VALUE;
        }
        return attestation.getSettingValue();
    }

    public AuthenticatorSelection getAuthenticatorSelection(List<RPConfigEntity> rpConfigs){
        /*
        * setting_name
        * require_user_verification
        * authenticator_attachment
        * require_resident_key
        * */

        RPConfigEntity userVerificationConfig = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.REQUIRE_USER_VERIFICATION))
                                                    .findFirst().orElse(null);

        RPConfigEntity requireResidentKey = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.REQUIRE_RESIDENT_KEY))
                                                    .findFirst().orElse(null);

        RPConfigEntity authenticatorAttachment = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals(CommonConstants.AUTHENTICATOR_ATTACHMENT))
                                                    .findFirst().orElse(null);

        AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection();
        authenticatorSelection.setUserVerification(userVerificationConfig == null ? CommonConstants.USER_VERIFICATINO_PREFERRED_STRING : userVerificationConfig.getSettingValue()); // ToDo : move to constants
        authenticatorSelection.setRequireResidentKey(requireResidentKey == null ? false : Boolean.valueOf(requireResidentKey.getSettingValue()));
        authenticatorSelection.setAuthenticatorAttachment(authenticatorAttachment == null ? CommonConstants.AUTHN_ATTACHMENT_PLATFORM_STRING : authenticatorAttachment.getSettingValue()); // ToDo : reconsider the default value and move to constants

        return authenticatorSelection;
    }

    public CermonyBO getCermonyConfigs(String rpId){
        RelyingPartyEntity rpEntity;
        if(rpId == null || rpId.length() == 0){
            rpEntity = rpRepository.findByRpId(rpId);
        }else {
            rpEntity = rpRepository.findByRpId(CommonConstants.DEFAULT_RP_ID);
        }

        RP rp = RP.builder()
                .id(rpEntity.getRpId())
                .name(rpEntity.getName())
                .origin(rpEntity.getOrigin())
                .build();

        List<RPConfigEntity> rpConfigs = rpConfigRepository.findByRelyingPartyId(rpEntity.getId());
        if(CollectionUtils.isEmpty(rpConfigs)){
            //ToDO: retrun default values
        }

        AuthenticatorSelection authenticatorSelection = this.getAuthenticatorSelection(rpConfigs);
        String attestation = this.getAttestation(rpConfigs);

        List<PubKeyCredParam> pubKeyCredParam = this.getPubKeyCredParam(rpConfigs);
        long timeout = this.getTimeout(rpConfigs);

        CermonyBO cermonyBO = CermonyBO.builder()
                .rp(rp)
                .authenticatorSelection(authenticatorSelection)
                .pubKeyCredPams(pubKeyCredParam)
                .attestation(attestation)
                .timeout(timeout)
                .build();

        return cermonyBO;
    }
}

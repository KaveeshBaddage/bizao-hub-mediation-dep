package com.wso2telco.dep.mediator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class has implementation to  encrypt the variable named `UNENCRYPTED_PARAM` in messageContext using MD5
 * Encryption Algorithm and assign encrypted value to variable named  `ENCRYPTED_PARAM`
 */
public final class EncryptionMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(EncryptionMediator.class);

    private static final String UNENCRYPTED_PARAM = "UNENCRYPTED_PARAM";

    public boolean mediate(MessageContext messageContext) {

        String unencryptedString = (String) messageContext.getProperty(UNENCRYPTED_PARAM);

        if(unencryptedString != null && !unencryptedString.isEmpty()){
            messageContext.setProperty("ENCRYPTED_PARAM", getMd5Value(unencryptedString) );
        }else{
            log.error("Cannot find value for UNENCRYPTED_PARAM variable");
            messageContext.setProperty("ENCRYPTED_PARAM", null);
            messageContext.setProperty("errorText", "Cannot find value for UNENCRYPTED_PARAM variable");
        }

        return true;
    }

    private String getMd5Value(String inputString) {
        try {

            MessageDigest md = MessageDigest.getInstance("MD5");

            byte[] messageDigest = md.digest(inputString.getBytes());

            BigInteger no = new BigInteger(1, messageDigest);

            String encryptedString = no.toString(16);
            while (encryptedString.length() < 32) {
                encryptedString = "0" + encryptedString;
            }
            return encryptedString;
        } catch (NoSuchAlgorithmException e) {
            log.error("Cannot encrypt the given string using MD5 encryption algorithm");
            throw new RuntimeException(e);
        }
    }


}

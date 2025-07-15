/*
 *  *******************************************************************************
 *  Copyright (c) 2023-24 Harman International
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 *  *******************************************************************************
 */

package org.eclipse.ecsp.auth.lib.util;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.auth.lib.config.AuthProperty;
import org.eclipse.ecsp.common.config.EnvConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.ComponentScan;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class for device activation operations.
 * This class provides methods for generating device IDs, passcodes, decrypting qualifiers,
 * validating qualifiers, and generating device association codes.
 */
@Configurable
@ComponentScan(basePackages = "org.eclipse.ecsp")
public class DeviceActivationUtil {
    private static final int MAX_LENGTH = 14;
    private static final int PREFIX = 2;
    private static final int ALPHANUM_LENGTH = 50;
    private static final int VALUE_5 = 5;
    private static final int VALUE_8 = 8;
    private static final int VALUE_2 = 2;
    private static final int VALUE_4 = 4;
    private static final int INDEX = -1;
    private static final int GCM_TAG_LENGTH = 16;
    private static final long RANDOM_NUMBER = -1L;
    private static final int DEVICE_ASSOCIATION_RANDOM_STRING_LENGTH = 6;
    private static final int DEVICE_ASSOCIATION_UNIQUE_DEVICE_ID_LENGTH = 6;
    // ignoring confusing combinations such as 1I, 1l, 2Z, 5S ...
    private static final char[] RANDOM_CHARSET =
      {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'U', 'V',
          'W', 'X', 'Y', '3', '4', '6', '7', '8', '9'};
    private static final String RANDOM_DEVICE_ASSOCIATION_STRING_FORMAT = "%1s-%2s-%3s";
    private static final String AEAD_STRING = "aadstr";
    // char[] RANDOM_ALPHANUMERIC_CHARSET has alphanumeric letters[a-zA-Z0-9]
    // and used to generate random alphanumeric string
    private static final char[] RANDOM_ALPHANUMERIC_CHARSET =
      {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
          'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
          'a', 'b', 'c', 'd',
          'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
          'z'};
    private static final Logger LOGGER = LoggerFactory.getLogger(DeviceActivationUtil.class);
    private static SecureRandom secureRandom = new SecureRandom();
    @Autowired
    private EnvConfig<AuthProperty> config;

    /**
     * Generates a device ID by combining a prefix, a random alphanumeric string, and a suffix.
     *
     * @param prefix   the prefix to be added to the device ID
     * @param idSuffix the suffix to be added to the device ID
     * @return the generated device ID
     */
    public static String generateDeviceId(String prefix, Long idSuffix) {

        int idLength = idSuffix.toString().length();
        // 14 is the total length, 2 for prefix HU and rest is random string
        int lengthOfRandomString = MAX_LENGTH - (PREFIX + idLength);
        String randomString = (RandomStringUtils.randomAlphanumeric(lengthOfRandomString)).toUpperCase();
        return prefix + randomString + idSuffix;
    }

    /**
     * Generates a passcode by combining a random alphanumeric string with the current system time.
     *
     * @return the generated passcode
     */
    public static String getPasscode() {
        return getRandomAlphanumericString(ALPHANUM_LENGTH) + System.currentTimeMillis();
    }

    /**
     * Decrypts the given encrypted data using the specified key and associated data.
     *
     * @param key             the key used for decryption
     * @param encrypted       the encrypted data to be decrypted
     * @param associatedData  the associated data used for authentication (MAC)
     * @return the decrypted data
     * @throws NoSuchAlgorithmException             if the specified algorithm is not available
     * @throws NoSuchPaddingException               if the specified padding scheme is not available
     * @throws InvalidKeyException                  if the specified key is invalid
     * @throws InvalidAlgorithmParameterException   if the specified algorithm parameters are invalid
     * @throws IllegalBlockSizeException            if the block size of the cipher is invalid
     * @throws BadPaddingException                   if the padding of the cipher is invalid
     */
    public static byte[] decrypt(byte[] key, byte[] encrypted, byte[] associatedData) throws NoSuchAlgorithmException,
        NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
        IllegalBlockSizeException, BadPaddingException {
        // Decrypt the encrypted text
        /* Story 465232 - Implemented GCM cipher mode to fix the following major Sonar vulnerabilities
         ** The cipher does not provide data integrity
         ** The cipher is susceptible to padding oracle attacks
         */
        try {
            LOGGER.info("Decrypting using AES/GCM/NoPadding cipher");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_LENGTH * VALUE_8, key));
            // Story 546176, 550679, 554403 - Enabled AAD Authentication method (MAC)
            if (associatedData != null && associatedData.length > 0) {
                LOGGER.debug("Associated Data is NOT NULL. Updating AAD.");
                cipher.updateAAD(associatedData);
            }
            return cipher.doFinal(encrypted);
        } catch (AEADBadTagException e) {
            LOGGER.info(
                "Decryption failed using AES/GCM/NoPadding cipher. Retrying decryption using AES/CBC/PKCS5Padding"
                    + " cipher");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(key));
            return cipher.doFinal(encrypted);
        }
    }

    /**
     * Checks the qualifier for a given VIN, serial number, qualifier, secret key, and AAD.
     *
     * @param vin           The VIN (Vehicle Identification Number) of the device.
     * @param serialNumber  The serial number of the device.
     * @param qualifier     The qualifier to be checked.
     * @param secretKey     The secret key used for encryption.
     * @param aad           The AAD (Additional Authenticated Data) used for encryption.
     * @return              The generated random number if the qualifier is valid, otherwise a default random number.
     */
    public static long checkQualifier(String vin, String serialNumber, String qualifier, String secretKey, String aad) {

        long randomNumber = RANDOM_NUMBER;

        String separator = "@";
        String keyPartFromVin = "";
        String keyPartFromSerialNumber = "";
        String decryptedString = "";

        byte[] assocData = null;

        try {
            if (vin.trim().length() < VALUE_5) {
                keyPartFromVin = "XXXXX"; /* Vin empty, so consider 5 X's */
            } else {
                keyPartFromVin = vin.substring(0, VALUE_5); /* Second part of key */
            }

            if (serialNumber.trim().length() < VALUE_2) {
                // Serial Number empty, so consider 2 X's
                keyPartFromSerialNumber = "XX";
            } else {
                // Third part of key
                keyPartFromSerialNumber = serialNumber.substring(0, VALUE_2);
            }

            /*
             * Key format: Prefix + 5 characters of VIN + 2 characters of
             * SerialNumber
             */
            secretKey = secretKey + keyPartFromVin + keyPartFromSerialNumber;
            // Avoiding binary characters by hex-coding
            // Alternative way of avoiding binary characters by hex-coding
            byte[] encrypted = DatatypeConverter.parseBase64Binary(qualifier);

            // Story 546176, 550679, 554403 - Enabled AAD Authentication method (MAC)
            LOGGER.info("aad: {}", aad);

            assocData = addAadAndAssociatedData(aad, serialNumber);

            decryptedString = new String(decrypt(secretKey.getBytes(StandardCharsets.UTF_8), encrypted, assocData),
                StandardCharsets.UTF_8);
            LOGGER.debug("checkQualifier:decryptedString with # padding: {}", decryptedString);
            if (decryptedString.indexOf('#') != INDEX) {
                // Remove padding of '#' at the end. This is done on client side
                // to generate string length as multiple of 16 (required by AES)
                int startIndex = decryptedString.indexOf('#');
                decryptedString = decryptedString.substring(0, startIndex);
            }

            LOGGER.debug("checkQualifier:decryptedString after # removal: {}", decryptedString);

            /*
             * For cases where serial number or vin might have @ in them, use
             * -delim- as separator
             */
            if (decryptedString.indexOf("-delim-") != INDEX) {
                separator = "-delim-";
            }
            String[] parts = decryptedString.split(separator);

            if (parts[0].equals(vin) && parts[1].equals(serialNumber)) {
                randomNumber = Long.parseLong(parts[VALUE_2]);
            } else {
                return RANDOM_NUMBER;
            }
        } catch (Exception e) {
            randomNumber = RANDOM_NUMBER;
            LOGGER.error("Error in checkQualifier", e);
        }

        return randomNumber;

    }

    /**
     * Adds the Additional Authenticated Data (AAD) and Associated Data to the given serial number.
     *
     * @param aad           the Additional Authenticated Data (AAD) flag
     * @param serialNumber  the serial number to add AAD and Associated Data to
     * @return              the byte array containing the AAD and Associated Data, or null if AAD is not enabled
     */
    private static byte[] addAadAndAssociatedData(String aad, String serialNumber) {
        String associatedData = "";
        byte[] assocData = null;
        if (aad != null && StringUtils.isNotEmpty(aad) && aad.equalsIgnoreCase("yes")) {
            int len = serialNumber.trim().length();
            if (len < VALUE_5) {
                LOGGER.debug("serialNumber length < 5");
                String part = serialNumber + StringUtils.repeat("x", VALUE_5 - len);
                associatedData = part + AEAD_STRING + part;
                assocData = associatedData.getBytes(StandardCharsets.UTF_8);
            } else {
                LOGGER.debug("serialNumber length >= 5");
                String part1 = serialNumber.substring(0, VALUE_5);
                String part2 = serialNumber.substring(len - VALUE_5, len);
                associatedData = part1 + AEAD_STRING + part2;
                assocData = associatedData.getBytes(StandardCharsets.UTF_8);
            }
        }
        return assocData;
    }

    /**
     * Generates a device association code by combining a random string and a unique device ID.
     *
     * @param idSuffix The suffix of the unique device ID.
     * @return The generated device association code.
     */
    public static String generateDeviceAssociationCode(Long idSuffix) {

        String randomStr = RandomStringUtils.random(
            DEVICE_ASSOCIATION_RANDOM_STRING_LENGTH, RANDOM_CHARSET)
            + UniqueDeviceIdEncoder.encode(idSuffix,
            DEVICE_ASSOCIATION_UNIQUE_DEVICE_ID_LENGTH);
        return String.format(RANDOM_DEVICE_ASSOCIATION_STRING_FORMAT,
            randomStr.substring(0, VALUE_4), randomStr.substring(VALUE_4, VALUE_8),
            randomStr.substring(VALUE_8));

    }

    /**
     * Generates a random alphanumeric string of the specified length.
     *
     * @param length The length of the random string to generate.
     * @return A random alphanumeric string.
     */
    public static String getRandomAlphanumericString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(RANDOM_ALPHANUMERIC_CHARSET[secureRandom.nextInt(RANDOM_ALPHANUMERIC_CHARSET.length)]);
        }
        return sb.toString();
    }

    /**
     * Returns the time-to-live (TTL) value for the authentication token.
     *
     * @return The TTL value for the authentication token.
     */
    public int getTtl() {
        return Integer.parseInt(config.getStringValue(AuthProperty.AUTH_TOKEN_TTL).trim());
    }

    /**
     * Retrieves the configuration for device activation.
     *
     * @return The configuration for device activation.
     */
    public EnvConfig<AuthProperty> getConfig() {
        return config;
    }

    /**
     * Sets the configuration for the device activation utility.
     *
     * @param config the configuration to set
     */
    public void setConfig(EnvConfig<AuthProperty> config) {
        this.config = config;
    }
}

package com.github.klaidoshka.solution;

import static com.github.klaidoshka.util.CipherUtil.toBytes;
import static com.github.klaidoshka.util.StringUtil.toHex;

import java.util.Arrays;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Solution for the symmetric block cipher encryption task.
 *
 * <li>
 * Encrypts and decrypts a text using a symmetric block cipher.
 * </li>
 * <li>
 * Modifies the first byte of the input text, re-encrypts and re-decrypts it.
 * </li>
 * <li>
 * Shortens the input text, tries to encrypt it and catches the exception.
 * </li>
 * <li>
 * Modifies the first byte of the ciphertext, re-decrypts it and logs the result.
 * </li>
 */
public final class SymmetricBlockEncryptSolution implements Solution {

  /**
   * Logger of the class.
   */
  private static final Logger LOGGER = Logger.getLogger(
      SymmetricBlockEncryptSolution.class.getName()
  );

  /**
   * Cipher algorithm.
   */
  private static final String CIPHER = "AES";

  /**
   * Cipher mode.
   */
  private static final String MODE = "ECB";

  /**
   * Cipher blocks padding.
   */
  private static final String PADDING = "NoPadding";

  /**
   * Cipher transformation label.
   */
  private static final String CIPHER_TRANSFORMATION = "%s/%s/%s".formatted(CIPHER, MODE, PADDING);

  /**
   * Cipher key.
   */
  private static final byte[] KEY = toBytes("0001020304050607 08090A0B0C0D0E0F");

  /**
   * Input for the cipher to process.
   */
  private static final byte[] INPUT = toBytes(
      "719AEAA97C5A673B 5C4B61E822F5E5F5 3280868F660CA282 2488E8BDCA6AC6EB"
  );

  @Override
  public void execute() throws Exception {
    var cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
    var key = new SecretKeySpec(KEY, CIPHER);

    LOGGER.info("• Transformation: " + CIPHER_TRANSFORMATION);
    LOGGER.info("• Key: " + toHex(KEY));
    LOGGER.info("Encrypting and decrypting...");

    cipher.init(Cipher.ENCRYPT_MODE, key);

    var encrypted = cipher.doFinal(INPUT);

    cipher.init(Cipher.DECRYPT_MODE, key);

    var decrypted = cipher.doFinal(encrypted);

    LOGGER.info("• Text: " + toHex(INPUT));
    LOGGER.info("  Ciphertext: " + toHex(encrypted));
    LOGGER.info("  Text (2): " + toHex(decrypted));
    LOGGER.info("Modifying first byte of input, encrypting, decrypting...");

    var byteOld = INPUT[0];

    INPUT[0] ^= 0x01;

    cipher.init(Cipher.ENCRYPT_MODE, key);

    var encryptedModified = cipher.doFinal(INPUT);

    cipher.init(Cipher.DECRYPT_MODE, key);

    var decryptedModified = cipher.doFinal(encryptedModified);

    LOGGER.info("• Text: " + toHex(INPUT));
    LOGGER.info("  Ciphertext: " + toHex(encryptedModified));
    LOGGER.info("  Text (2): " + toHex(decryptedModified));
    LOGGER.info("Shortening input, encrypting, decrypting...");

    INPUT[0] = byteOld;

    try {
      var inputShortened = Arrays.copyOfRange(
          INPUT,
          0,
          INPUT.length - 16 // If not a multiple of 16, exception is thrown
      );

      cipher.init(Cipher.ENCRYPT_MODE, key);

      var encryptedShortened = cipher.doFinal(inputShortened);

      cipher.init(Cipher.DECRYPT_MODE, key);

      var decryptedShortened = cipher.doFinal(encryptedShortened);

      LOGGER.info("• Text: " + toHex(inputShortened));
      LOGGER.info("  Ciphertext: " + toHex(encryptedShortened));
      LOGGER.info("  Text (2): " + toHex(decryptedShortened));
    } catch (Exception e) {
      LOGGER.severe("• Exception thrown when encrypting with shortened input: " + e.getMessage());
    }

    LOGGER.info("Modifying ciphertext, decrypting...");

    encrypted[0] ^= 0x01;

    cipher.init(Cipher.DECRYPT_MODE, key);

    var decryptedModifiedCipher = cipher.doFinal(encrypted);

    LOGGER.info("• Text: " + toHex(INPUT));
    LOGGER.info("  Ciphertext: " + toHex(encrypted));
    LOGGER.info("  Text (2): " + toHex(decryptedModifiedCipher));
  }
}
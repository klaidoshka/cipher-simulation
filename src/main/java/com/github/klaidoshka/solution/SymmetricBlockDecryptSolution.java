package com.github.klaidoshka.solution;

import static com.github.klaidoshka.util.CipherUtil.toBytes;
import static com.github.klaidoshka.util.StringUtil.toHex;

import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Solution for the symmetric block cipher decryption task.
 *
 * <li>
 * Decrypts, encrypts and decrypts again a ciphertext using a symmetric block cipher.
 * </li>
 * <li>
 * Modifies the last bit of the decrypted text and re-encrypts it.
 * </li>
 * <li>
 * Modifies the first bit of the ciphertext and re-decrypts it.
 * </li>
 * <li>
 * Modifies the last bit of the initialization vector and re-decrypts the ciphertext.
 * </li>
 */
public final class SymmetricBlockDecryptSolution implements Solution {

  /**
   * Logger of the class.
   */
  private static final Logger LOGGER = Logger.getLogger(
      SymmetricBlockDecryptSolution.class.getName()
  );

  /**
   * Cipher algorithm.
   */
  private static final String CIPHER = "xTEA";

  /**
   * Cipher mode.
   */
  private static final String MODE = "CBC";

  /**
   * Cipher blocks padding.
   */
  private static final String PADDING = "PKCS7Padding";

  /**
   * Cipher transformation label.
   */
  private static final String CIPHER_TRANSFORMATION = "%s/%s/%s".formatted(CIPHER, MODE, PADDING);

  /**
   * Cipher key.
   */
  private static final byte[] KEY = toBytes("6665566666655666 3331133333311333");

  /**
   * Initialization vector.
   */
  private static final byte[] INITIALIZATION_VECTOR = toBytes("0706050403020100");

  /**
   * Ciphertext for the cipher to decrypt.
   */
  private static final byte[] CIPHERTEXT = toBytes(
      "6294DF99EB4F2429 42FCCC8291FB9CC4 63788C13122A1D80"
  );

  @Override
  public void execute() throws Exception {
    var cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
    var key = new SecretKeySpec(KEY, CIPHER);
    var iv = new IvParameterSpec(INITIALIZATION_VECTOR);

    LOGGER.info("• Transformation: " + CIPHER_TRANSFORMATION);
    LOGGER.info("• Key: " + toHex(KEY));
    LOGGER.info("• IV: " + toHex(INITIALIZATION_VECTOR));
    LOGGER.info("Decrypting, encrypting and decrypting again...");

    cipher.init(Cipher.DECRYPT_MODE, key, iv);

    var decrypted = cipher.doFinal(CIPHERTEXT);

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);

    var encrypted = cipher.doFinal(decrypted);

    LOGGER.info("• Ciphertext: " + toHex(CIPHERTEXT));
    LOGGER.info("  Text: " + toHex(decrypted));
    LOGGER.info("  Ciphertext (2): " + toHex(encrypted));
    LOGGER.info("Modifying text's last bit and re-encrypting...");

    var decryptedModified = decrypted.clone();

    decryptedModified[decrypted.length - 1] ^= 0x01;

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);

    encrypted = cipher.doFinal(decryptedModified);

    LOGGER.info("• Text: " + toHex(decryptedModified));
    LOGGER.info("  Ciphertext: " + toHex(encrypted));
    LOGGER.info("Modifying ciphertext's first bit and re-decrypting...");

    var ciphertextModified = CIPHERTEXT.clone();

    ciphertextModified[0] ^= 0x01;

    cipher.init(Cipher.DECRYPT_MODE, key, iv);

    decrypted = cipher.doFinal(ciphertextModified);

    LOGGER.info("• Ciphertext: " + toHex(ciphertextModified));
    LOGGER.info("  Text: " + toHex(decrypted));
    LOGGER.info("Modifying initialization vector and re-decrypting...");

    var ivModified = INITIALIZATION_VECTOR.clone();

    ivModified[7] ^= 0x01;

    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivModified));

    // IV is used for the 1st block only, all other blocks are decrypted correctly
    decrypted = cipher.doFinal(CIPHERTEXT);

    LOGGER.info("• IV: " + toHex(ivModified));
    LOGGER.info("  Ciphertext: " + toHex(CIPHERTEXT));
    LOGGER.info("  Text: " + toHex(decrypted));
  }
}
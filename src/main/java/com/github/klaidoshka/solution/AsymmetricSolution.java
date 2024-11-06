package com.github.klaidoshka.solution;

import static com.github.klaidoshka.util.CipherUtil.toBytes;
import static com.github.klaidoshka.util.StringUtil.toHex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Logger;
import javax.crypto.Cipher;

/**
 * Asymmetric solution to decrypt a ciphertext.
 *
 * <li>
 * It uses the RSA algorithm to decrypt a ciphertext.
 * </li>
 * <li>
 * Then it encrypts and decrypts the decrypted message again.
 * </li>
 */
public final class AsymmetricSolution implements Solution {

  /**
   * Logger of the class.
   */
  private static final Logger LOGGER = Logger.getLogger(AsymmetricSolution.class.getName());

  /**
   * Cipher algorithm.
   */
  private static final String CIPHER = "RSA";

  /**
   * Padding of the cipher.
   */
  private static final String PADDING = "PKCS1Padding";

  /**
   * Public exponent of the key.
   */
  private static final BigInteger E = new BigInteger("010001", 16);

  /**
   * Modulus of the key.
   */
  private static final BigInteger N = new BigInteger(
      "00B3446AF443CD84 13C155114359C501 DF6616282F89F3B1 78CFB62B689E899E 03".replaceAll(
          "\\s+",
          ""
      ),
      16
  );

  /**
   * Private exponent of the key.
   */
  private static final BigInteger D = new BigInteger(
      "3D4224F641712A30 0201CABB6422B127 8E7008C9D6D3AFA6 3A67D919CED15719".replaceAll(
          "\\s+",
          ""
      ),
      16
  );

  /**
   * Ciphertext to decrypt.
   */
  private static final byte[] CIPHERTEXT = toBytes(
      "1F0E15B0D491DB7B 6C8F66883E809CE1 7F8CC510C314E320 2D0811455E335DA7"
  );

  /**
   * Cipher transformation label.
   */
  private static final String CIPHER_TRANSFORMATION = "%s/%s/%s".formatted(CIPHER, "None", PADDING);

  @Override
  public void execute() throws Exception {
    var cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, "BC");
    var keyFactory = KeyFactory.getInstance(CIPHER, "BC");
    var privateKey = keyFactory.generatePrivate(new RSAPrivateKeySpec(N, D));
    var publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(N, E));

    cipher.init(Cipher.DECRYPT_MODE, privateKey);

    var decrypted = cipher.doFinal(CIPHERTEXT, 0, CIPHERTEXT.length);

    LOGGER.info("• Transformation: " + CIPHER_TRANSFORMATION);
    LOGGER.info("• Private key: " + toHex(privateKey.getEncoded()));
    LOGGER.info("• Public key: " + toHex(publicKey.getEncoded()));
    LOGGER.info("• Ciphertext: " + toHex(CIPHERTEXT));
    LOGGER.info("  Decrypted: " + toHex(decrypted));
    LOGGER.info("Encrypting and decrypting again...");

    cipher.init(Cipher.ENCRYPT_MODE, publicKey);

    var encrypted = cipher.doFinal(decrypted);

    cipher.init(Cipher.DECRYPT_MODE, privateKey);

    decrypted = cipher.doFinal(encrypted);

    LOGGER.info("• Ciphertext: " + toHex(encrypted));
    LOGGER.info("  Decrypted: " + toHex(decrypted));
  }
}
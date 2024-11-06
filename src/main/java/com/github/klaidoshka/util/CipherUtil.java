package com.github.klaidoshka.util;

import com.github.klaidoshka.CipherTask;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for cipher/cryptographic library operations.
 */
public final class CipherUtil {

  /**
   * Prevent instantiation of this utility class.
   */
  private CipherUtil() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Check if the Bouncy Castle provider is installed.
   *
   * @return true if the Bouncy Castle provider is installed, false otherwise
   */
  public static boolean checkBouncyCastleInstallation() {
    return Security.getProvider("BC") != null;
  }

  /**
   * Convert bit-length to a byte array.
   *
   * @param bitLength the bit length to convert
   * @return the byte array
   */
  private static byte[] convertToByteArray(int bitLength) {
    var length = bitLength / 8;
    var array = new byte[length];

    for (int i = 0; i < length; i++) {
      array[i] = (byte) i;
    }

    return array;
  }

  /**
   * Lists available capabilities for ciphers, key agreement, macs, message digests, signatures and
   * other objects in the BC provider to the system's standard output.
   */
  public static void printBouncyCastleCapabilities() {
    var provider = Security.getProvider("BC");

    for (var instance : provider.keySet()) {
      var entry = (String) instance;

      // Indicates that entry refers to another entry
      if (entry.startsWith("Alg.Alias.")) {
        entry = entry.substring("Alg.Alias.".length());
      }

      var factoryClass = entry.substring(0, entry.indexOf('.'));
      var name = entry.substring(factoryClass.length() + 1);

      CipherTask.logger.info(factoryClass + ": " + name);
    }
  }

  /**
   * Test to make sure the unrestricted policy files are installed.
   *
   * @throws Exception if the test fails
   */
  public static void testUnrestrictedPolicy() throws Exception {
    var data = new byte[]{0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    var cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");

    for (var length : new int[]{64, 128, 192}) {
      var key = new SecretKeySpec(
          convertToByteArray(length),
          "Blowfish"
      );

      cipher.init(Cipher.ENCRYPT_MODE, key);

      cipher.doFinal(data);

      CipherTask.logger.info(length + "-bit key test: passed");
    }
  }

  /**
   * Convert a hexadecimal string to a byte array.
   *
   * @param hex the hexadecimal string to convert
   * @return the byte array
   */
  public static byte[] toBytes(String hex) {
    hex = hex.replaceAll("\\s+", "");

    var length = hex.length();
    var data = new byte[length / 2];

    for (int i = 0; i < length; i += 2) {
      data[i / 2] = (byte) (
          (Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16)
      );
    }

    return data;
  }
}
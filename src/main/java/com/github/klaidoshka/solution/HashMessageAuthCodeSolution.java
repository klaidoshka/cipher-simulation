package com.github.klaidoshka.solution;

import static com.github.klaidoshka.util.CipherUtil.toBytes;
import static com.github.klaidoshka.util.StringUtil.toHex;
import static java.security.MessageDigest.isEqual;

import java.util.Arrays;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Solution for the hash message authentication code task.
 *
 * <li>
 * Calculates the MAC of three texts using three different methods.
 * </li>
 * <li>
 * Compares the calculated MACs with the expected ones.
 * </li>
 * <li>
 * Shortens the key and recalculates the MAC.
 * </li>
 */
public final class HashMessageAuthCodeSolution implements Solution {

  /**
   * Logger of the class.
   */
  private static final Logger LOGGER = Logger.getLogger(
      HashMessageAuthCodeSolution.class.getName()
  );

  /**
   * Keys for the MAC.
   */
  private static final byte[][] KEYS = {
      toBytes("7132333435363738 393A"),
      toBytes("5172333435363738 393A"),
      toBytes("517233343536")
  };

  /**
   * MACs of the appropriate indexed texts.
   */
  private static final byte[][] MACS = {
      toBytes("7AE7819F782E54B7 4FC53C55C6B372AF 5A1064FF"),
      toBytes(
          "A828DE429941828E 1837FF67003DAFFC 8AD64C82BFFFB3FB " +
              "0C85E654596CB60D 8B0B47906D1AEC18 4AAEC73AED5ADE4F"
      ),
      toBytes("D634AE8023C5957E D5178A0DD37EAD81 A7A77B76")
  };

  /**
   * Methods to be used for the MAC.
   */
  private static final String[] METHODS = {
      "HMac-RipeMD160",
      "HmacSHA384",
      "HmacSHA1"
  };

  /**
   * Texts to be checked.
   */
  private static final byte[][] TEXTS = {
      toBytes("DAFF000000010203 040506070809"),
      toBytes("FACEB00000010203 040506070809"),
      toBytes("BABCE00000010203 040500")
  };

  @Override
  public void execute() throws Exception {
    for (var i = 0; i < TEXTS.length; i++) {
      var macCode = MACS[i];
      var hmac = Mac.getInstance(METHODS[i], "BC");
      var hmacKey = new SecretKeySpec(macCode, METHODS[i]);
      var text = TEXTS[i];
      var key = KEYS[i];

      hmac.init(hmacKey);

      hmac.update(text, 0, text.length);

      var mac = hmac.doFinal();

      LOGGER.info("• Method: " + METHODS[i]);
      LOGGER.info("  Text: " + toHex(text));
      LOGGER.info("  Key: " + toHex(key));
      LOGGER.info("  MAC: " + toHex(macCode));
      LOGGER.info("  MAC (Calculated): " + toHex(mac));
      LOGGER.info("    • MACs are equal: " + isEqual(macCode, mac));
      LOGGER.info("Shortening key...");

      var keyModified = Arrays.copyOfRange(key, 0, key.length / 5 * 4);

      hmacKey = new SecretKeySpec(keyModified, METHODS[i]);

      hmac.init(hmacKey);

      hmac.update(text, 0, text.length);

      mac = hmac.doFinal();

      LOGGER.info("  Key (Modified): " + toHex(keyModified));
      LOGGER.info("  MAC: " + toHex(macCode));
      LOGGER.info("  MAC (Calculated): " + toHex(mac));
    }
  }
}
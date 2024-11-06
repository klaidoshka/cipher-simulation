package com.github.klaidoshka.solution;

import static com.github.klaidoshka.util.CipherUtil.toBytes;
import static com.github.klaidoshka.util.StringUtil.toHex;
import static java.security.MessageDigest.isEqual;

import java.security.MessageDigest;
import java.util.logging.Logger;

/**
 * Solution for the hash task.
 *
 * <li>
 * Hashes three texts using three different hashing methods.
 * </li>
 * <li>
 * Compares the calculated hashes with the expected ones.
 * </li>
 * <li>
 * If hashes were equal, modifies the first bit of the text and recalculates the hash.
 * </li>
 */
public final class HashSolution implements Solution {

  /**
   * Logger of the class.
   */
  private static final Logger LOGGER = Logger.getLogger(HashSolution.class.getName());

  /**
   * Methods to use for hashing.
   */
  private static final String[] METHODS = {"Tiger", "RipeMD320", "RipeMD128"};

  /**
   * Hashes of the texts.
   */
  private static final byte[][] HASHES = {
      toBytes("983FB88C4524C020 A5957B416C16FD49 1A4CBA8909583C"),
      toBytes(
          "85399BCEC86662AA 1379862A91CB79E7 D50C1050CCEC2726 C9B086F44735B134 FB44BB8BA99B326D"
      ),
      toBytes("82C9967ED8C8453D F46CED7238FA67D3")
  };

  /**
   * Texts to hash.
   */
  private static final byte[][] TEXTS = {
      toBytes("FACE000004050607 08090A0B0C0D00"),
      toBytes("ABBA000004050607 08090A0B0C0D50"),
      toBytes("BABCE00004050607 08090A0B0C0D0E")
  };

  @Override
  public void execute() throws Exception {
    for (var i = 0; i < TEXTS.length; i++) {
      var text = TEXTS[i];
      var hash = HASHES[i];
      var instance = MessageDigest.getInstance(METHODS[i], "BC");

      instance.update(text, 0, text.length);

      var digest = instance.digest();
      var equal = isEqual(hash, digest);

      LOGGER.info("• Method: " + METHODS[i]);
      LOGGER.info("  Text: " + toHex(text));
      LOGGER.info("  Hash: " + toHex(hash));
      LOGGER.info("  Hash (Calculated): " + toHex(digest));
      LOGGER.info("    • Hashes are equal: " + equal);

      if (!equal) {
        return;
      }

      var textModified = text.clone();

      textModified[0] ^= 0x01;

      instance.update(textModified, 0, textModified.length);

      var digestModified = instance.digest();

      LOGGER.info("  Text (Modified): " + toHex(textModified));
      LOGGER.info("  Hash: " + toHex(digestModified));
    }
  }
}
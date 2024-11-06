package com.github.klaidoshka.util;

/**
 * The string utility class.
 */
public final class StringUtil {

  /**
   * The digits used in the hex string representation.
   */
  private static final char[] digits = "0123456789ABCDEF".toCharArray();

  /**
   * Prevent instantiation of this utility class.
   */
  private StringUtil() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Transform a byte array into a hex string.
   *
   * @param data   the byte array to transform into a hex string
   * @param length the length of the byte array
   * @return the hex string representation of the byte array
   */
  public static String toHex(byte[] data, int length) {
    var builder = new StringBuilder();

    for (int i = 0; i != length; i++) {
      var value = data[i] & 0xff;

      builder
          .append(digits[value >> 4])
          .append(digits[value & 0xf]);

      if ((i + 1) % 8 == 0) {
        builder.append(" ");
      }
    }

    return builder.toString();
  }

  /**
   * Transform a byte array into a hex string.
   *
   * @param data the byte array to transform into a hex string
   * @return the hex string representation of the byte array
   */
  public static String toHex(byte[] data) {
    return toHex(data, data.length);
  }
}

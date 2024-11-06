package com.github.klaidoshka;

import static com.github.klaidoshka.util.CipherUtil.checkBouncyCastleInstallation;
import static com.github.klaidoshka.util.CipherUtil.printBouncyCastleCapabilities;
import static com.github.klaidoshka.util.CipherUtil.testUnrestrictedPolicy;

import com.github.klaidoshka.solution.AsymmetricSolution;
import com.github.klaidoshka.solution.HashMessageAuthCodeSolution;
import com.github.klaidoshka.solution.HashSolution;
import com.github.klaidoshka.solution.Solution;
import com.github.klaidoshka.solution.SymmetricBlockDecryptSolution;
import com.github.klaidoshka.solution.SymmetricBlockEncryptSolution;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Main class of the application.
 */
public final class CipherTask {

  /*
   * Static block to load properties from the application properties file
   * before any other code is executed.
   */
  static {
    loadProperties();
  }

  /**
   * Root logger of the application.
   */
  public static final Logger logger = Logger.getLogger(CipherTask.class.getName());

  /**
   * Main method to check if the Bouncy Castle library is installed and to test the unrestricted
   * policy.
   *
   * @param args the command line arguments
   */
  public static void main(String[] args) {
    if (checkBouncyCastleInstallation()) {
      logger.info("Bouncy Castle library is installed");

      if (false) {
        logger.info("Printing capabilities:");

        printBouncyCastleCapabilities();
      }
    } else {
      logger.severe("Bouncy Castle library is not installed");
    }

    try {
      logger.info("Starting unrestricted policy tests");

      testUnrestrictedPolicy();

      logger.info("Tests passed");
    } catch (Exception e) {
      logger.severe("Tests of 3 iterations failed: " + e.getMessage());
    }

    for (var solution : new Solution[]{
        new SymmetricBlockEncryptSolution(),
        new SymmetricBlockDecryptSolution(),
        new HashSolution(),
        new HashMessageAuthCodeSolution(),
        new AsymmetricSolution()
    }) {
      try {
        logger.info(
            "Running %s (No. %d)".formatted(
                solution.getClass().getSimpleName(),
                solution.getId()
            )
        );

        solution.execute();

        logger.info("Solution completed successfully\n");
      } catch (Exception e) {
        logger.severe("Solution failed: " + e.getMessage() + "\n");
      }
    }
  }

  /**
   * Load properties from the application properties file and set them onto system properties for
   * the application to use.
   */
  private static void loadProperties() {
    var file = "application.properties";

    try (
        var stream = Objects.requireNonNull(
                CipherTask.class
                    .getClassLoader()
                    .getResource(file),
                "Could not find " + file + " under resources"
            )
            .openStream()
    ) {
      System
          .getProperties()
          .load(stream);
    } catch (Exception e) {
      throw new IllegalStateException("Could not load " + file, e);
    }
  }
}
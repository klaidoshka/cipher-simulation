package com.github.klaidoshka.solution;

/**
 * Interface for the solution of some task.
 */
public interface Solution {

  /**
   * Get the id of the solution.
   *
   * @return the id of the solution
   */
  default int getId() {
    return 17;
  }

  /**
   * Execute the solution.
   *
   * @throws Exception if an error occurs during the execution
   */
  void execute() throws Exception;
}
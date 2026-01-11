package io.jenkins.plugins.openmfa.base;

public class MFAException extends RuntimeException {

  public MFAException(String message) {
    super(message);
  }

  public MFAException(String message, Throwable cause) {
    super(message, cause);
  }

  public MFAException(Throwable cause) {
    super(cause);
  }

}

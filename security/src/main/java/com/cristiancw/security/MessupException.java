package com.cristiancw.security;

/**
 * @author Cristian C. Wolfram
 *
 *         Class to handle the {@link Messup} exceptions.
 */
public final class MessupException extends Exception {

	private static final long serialVersionUID = 4445370575496232139L;

	/**
	 * Basic constructor.
	 */
	public MessupException() {
		super();
	}

	/**
	 * Constructor with some params.
	 * 
	 * @param message
	 *            - the detail message.
	 */
	public MessupException(final String message) {
		super(message);
	}

	/**
	 * Constructor with some params.
	 * 
	 * @param throwable
	 *            - the cause. (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
	 */
	public MessupException(final Throwable throwable) {
		super(throwable);
	}

	/**
	 * Constructor with some params.
	 * 
	 * @param message
	 *            - the detail message.
	 * @param throwable
	 *            - the cause. (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
	 */
	public MessupException(final String message, final Throwable throwable) {
		super(message, throwable);
	}

	/**
	 * Constructor with some params.
	 * 
	 * @param message
	 *            - the detail message.
	 * @param throwable
	 *            - the cause. (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
	 * @param enableSuppression
	 *            - whether or not suppression is enabled or disabled
	 * @param writableStackTrace
	 *            - whether or not the stack trace should be writable
	 */
	public MessupException(final String message, final Throwable throwable, final boolean enableSuppression, final boolean writableStackTrace) {
		super(message, throwable, enableSuppression, writableStackTrace);
	}
}

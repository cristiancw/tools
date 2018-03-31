package com.cristiancw.security;

public final class MessupException extends Exception {

	private static final long serialVersionUID = 4445370575496232139L;

	public MessupException() {
		super();
	}

	public MessupException(final String message) {
		super(message);
	}

	public MessupException(final Throwable throwable) {
		super(throwable);
	}

	public MessupException(final String message, final Throwable throwable) {
		super(message, throwable);
	}

	public MessupException(final String message, final Throwable throwable, final boolean enableSuppression, final boolean writableStackTrace) {
		super(message, throwable, enableSuppression, writableStackTrace);
	}
}

package com.cristiancw.security;

public final class MessupException extends Exception {

	private static final long serialVersionUID = 4445370575496232139L;

	public MessupException() {
		super();
	}

	public MessupException(String message) {
		super(message);
	}

	public MessupException(Throwable throwable) {
		super(throwable);
	}

	public MessupException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public MessupException(String message, Throwable throwable, boolean enableSuppression, boolean writableStackTrace) {
		super(message, throwable, enableSuppression, writableStackTrace);
	}
}

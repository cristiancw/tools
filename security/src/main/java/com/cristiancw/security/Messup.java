package com.cristiancw.security;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

final class Messup {

	private static final int IVBYTES = 16;
	private static final int KEY_SIZE = 256;
	private static final int ITERATIONS = 65536;

	private static final byte[] SECRET_KEY_ALGORITHM = { 80, 66, 75, 68, 70, 50, 87, 105, 116, 104, 72, 109, 97, 99, 83, 72, 65, 50, 53, 54 };
	private static final byte[] SECRET_SPEC_ALGORITHM = { 65, 69, 83 };
	private static final byte[] CIPHER_TRANSFORMATION = { 65, 69, 83, 47, 67, 66, 67, 47, 80, 75, 67, 83, 53, 80, 65, 68, 68, 73, 78, 71 };
	private static final byte[] PREFIX_CHAR = { 94 };
	private static final byte[] MIDDLE_CHAR = { 46, 42 };
	private static final byte[] PREFIX = { 77, 69, 83, 83 };
	private static final byte[] SUFIX = { 85, 80 };
	private static final byte[] PASS = { 35, 35, 32, 71, 114, 101, 97, 116, 32, 74, 111, 98, 33, 33, 32, 89, 111, 117, 32, 99, 97, 110, 32, 102, 105, 103, 117, 114, 101, 32, 111, 117, 116, 32, 119, 104, 97, 116, 32, 116, 104, 101, 32, 109, 97, 105, 110, 32, 112, 97, 115, 115, 32, 105, 115, 46, 32, 71, 111, 32, 116, 114, 121, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 105, 110, 116, 101, 114, 110, 97, 108, 32, 97, 110, 100, 32, 117, 115, 101, 114, 32, 115, 116, 114, 105, 110,
			103, 32, 98, 108, 111, 99, 107, 32, 111, 102, 32, 115, 97, 108, 116, 115, 46, 46, 46, 32, 35, 35, 32, 86, 58, 48, 48, 49 };
	private static final byte[] SALT = { 64, 64, 32, 67, 111, 110, 103, 114, 97, 116, 117, 108, 97, 116, 105, 111, 110, 115, 33, 32, 89, 111, 117, 32, 100, 105, 115, 99, 111, 118, 101, 114, 101, 100, 32, 116, 104, 101, 32, 105, 110, 116, 101, 114, 110, 97, 108, 32, 115, 97, 108, 116, 32, 112, 97, 114, 116, 32, 111, 102, 32, 116, 104, 101, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 32, 78, 111, 119, 32, 121, 111, 117, 32, 110, 101, 101, 100, 32, 116, 111, 32, 102, 105, 110, 100,
			32, 116, 104, 101, 32, 117, 115, 101, 114, 32, 115, 97, 108, 116, 46, 32, 71, 111, 111, 100, 32, 108, 117, 99, 107, 33, 32, 64, 64 };

	private static final String MSG_PARAM_IS_EMPTY = "The secret String is empty";

	private Messup() {
		// Can instance
	}

	static boolean isMessupString(final String secret) {
		if (secret == null || secret.trim().isEmpty()) {
			return false;
		}
		return Pattern.compile(new StringBuilder(byteToString(PREFIX_CHAR)).append(byteToString(PREFIX)).append(byteToString(MIDDLE_CHAR)).append(byteToString(SUFIX)).toString()).matcher(secret).matches();
	}

	static String doSomeMess(final String secret, final byte... userSalt) throws MessupException {
		if (secret == null || secret.trim().isEmpty()) {
			throw new InvalidParameterException(MSG_PARAM_IS_EMPTY);
		}

		try {
			final byte ivBytes[] = new byte[IVBYTES];
			final IvParameterSpec ivParam = createIVParam(ivBytes);

			final SecretKeySpec skeySpec = createKey(userSalt);

			final Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, ivParam, skeySpec);
			final byte[] messed = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));

			final byte[] secretBytes = join(ivBytes, messed);

			return new StringBuilder(byteToString(PREFIX)).append(DatatypeConverter.printBase64Binary(secretBytes)).append(byteToString(SUFIX)).toString();
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			throw new MessupException(e);
		}
	}

	static String undoTheMess(final String secret, final byte... userSalt) throws MessupException {
		if (secret == null || secret.trim().isEmpty()) {
			throw new InvalidParameterException(MSG_PARAM_IS_EMPTY);
		}

		try {
			final byte[] secretBytes = DatatypeConverter.parseBase64Binary(secret.substring(byteToString(PREFIX).length(), secret.indexOf(byteToString(SUFIX))));

			final byte[] encrypted = new byte[secretBytes.length - IVBYTES];
			final IvParameterSpec ivParam = loadIVParam(secretBytes, encrypted);

			final SecretKeySpec skeySpec = createKey(userSalt);

			final Cipher cipher = getCipher(Cipher.DECRYPT_MODE, ivParam, skeySpec);
			final byte[] original = cipher.doFinal(encrypted);

			return byteToString(original);
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			throw new MessupException(e);
		}
	}

	private static IvParameterSpec createIVParam(final byte[] ivBytes) {
		final SecureRandom random = new SecureRandom();
		random.nextBytes(ivBytes);
		return new IvParameterSpec(ivBytes);
	}

	private static IvParameterSpec loadIVParam(final byte[] parseBase64Binary, final byte[] encrypted) {
		final byte[] ivBytes = new byte[IVBYTES];
		System.arraycopy(parseBase64Binary, 0, encrypted, 0, encrypted.length);
		System.arraycopy(parseBase64Binary, encrypted.length, ivBytes, 0, ivBytes.length);
		return new IvParameterSpec(ivBytes);
	}

	private static SecretKeySpec createKey(final byte... userSalt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		final byte[] salt = createSalt(userSalt);
		final PBEKeySpec keySpec = new PBEKeySpec(byteToString(PASS).toCharArray(), salt, ITERATIONS, KEY_SIZE);
		final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(byteToString(SECRET_KEY_ALGORITHM));
		final SecretKey secretKey = keyFactory.generateSecret(keySpec);
		return new SecretKeySpec(secretKey.getEncoded(), byteToString(SECRET_SPEC_ALGORITHM));
	}

	private static byte[] createSalt(final byte... userSalt) {
		if (userSalt != null && userSalt.length > 0) {
			final byte[] salt = new byte[SALT.length + userSalt.length];
			System.arraycopy(SALT, 0, salt, 0, SALT.length);
			System.arraycopy(userSalt, 0, salt, SALT.length, userSalt.length);
			return salt;
		}
		return SALT;
	}

	private static Cipher getCipher(final int encryptMode, final IvParameterSpec ivParam, final SecretKeySpec skeySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		final Cipher cipher = Cipher.getInstance(byteToString(CIPHER_TRANSFORMATION));
		cipher.init(encryptMode, skeySpec, ivParam);
		return cipher;
	}

	private static byte[] join(final byte[] ivBytes, final byte[] messed) {
		final byte[] secretBytes = new byte[messed.length + ivBytes.length];
		System.arraycopy(messed, 0, secretBytes, 0, messed.length);
		System.arraycopy(ivBytes, 0, secretBytes, messed.length, ivBytes.length);
		return secretBytes;
	}

	private static String byteToString(final byte[] bytes) {
		return new String(bytes, StandardCharsets.UTF_8);
	}
}

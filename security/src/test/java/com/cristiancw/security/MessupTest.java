package com.cristiancw.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;

import org.junit.Test;

public class MessupTest {

	private static final String MSG_PARAM_IS_EMPTY = "The secret String is empty";

	@Test
	public void isMessupStringOkayWithoutString() {
		assertTrue(Messup.isMessupString("MESSUP"));
	}

	@Test
	public void isMessupStringOkay() {
		assertTrue(Messup.isMessupString("MESSaaaUP"));
	}

	@Test
	public void isMessupStringErrorPrefix01() {
		assertFalse(Messup.isMessupString("messaaaUP"));
	}

	@Test
	public void isMessupStringErrorPrefix02() {
		assertFalse(Messup.isMessupString("MESsaaaUP"));
	}

	@Test
	public void isMessupStringErrorPrefix03() {
		assertFalse(Messup.isMessupString("MEsSaaaUP"));
	}

	@Test
	public void isMessupStringErrorPrefix04() {
		assertFalse(Messup.isMessupString("MeSSaaaUP"));
	}

	@Test
	public void isMessupStringErrorPrefix05() {
		assertFalse(Messup.isMessupString("mESSaaaUP"));
	}

	@Test
	public void isMessupStringErrorPrefix06() {
		assertFalse(Messup.isMessupString("aMESSaaaUP"));
	}

	@Test
	public void isMessupStringErrorSufix01() {
		assertFalse(Messup.isMessupString("MESSaaaUPa"));
	}

	@Test
	public void isMessupStringErrorSufix02() {
		assertFalse(Messup.isMessupString("MESSaaaUp"));
	}

	@Test
	public void isMessupStringErrorSufix03() {
		assertFalse(Messup.isMessupString("MESSaaauP"));
	}

	@Test
	public void isMessupStringErrorSufix04() {
		assertFalse(Messup.isMessupString("MESSaaaup"));
	}

	@Test
	public void isMessupStringErrorSufix05() {
		assertFalse(Messup.isMessupString("MESSaaaU"));
	}

	@Test
	public void isMessupStringErrorSufix06() {
		assertFalse(Messup.isMessupString("MESSaaaP"));
	}

	@Test
	public void isMessupStringErrorNull() {
		assertFalse(Messup.isMessupString(null));
	}

	@Test
	public void isMessupStringErrorEmpty() {
		assertFalse(Messup.isMessupString(""));
	}

	@Test
	public void doSomeMessTest() throws MessupException {
		final String secret = "test";

		final String doSomeMess = Messup.doSomeMess(secret);
		assertEquals(50, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessSimpleLetter() throws MessupException {
		final String secret = "abcdefghijklmnopqrstuvwxyz";

		final String doSomeMess = Messup.doSomeMess(secret);
		assertEquals(70, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessSimpleNumber() throws MessupException {
		final String secret = "0123456789";

		final String doSomeMess = Messup.doSomeMess(secret);
		assertEquals(50, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessSimpleChar() throws MessupException {
		final String secret = "\"'!@#$%*()-_=+'`[{ç~^]}\\|,<.>;:/?";

		final String doSomeMess = Messup.doSomeMess(secret);
		assertEquals(94, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessMixedChar() throws MessupException {
		final String secret = "a\"0'b!1@c#2$d%3*e(4)f-5_g=6+h'7`i[8{jç9~k^0]l}1\\m|2,n<3.o>4;p:5/q?6";

		final String doSomeMess = Messup.doSomeMess(secret);
		assertEquals(134, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessLongWord() throws MessupException {
		final String secret = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

		final String doSomeMess = Messup.doSomeMess(secret);
		assertEquals(626, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessTestWithUserSalt() throws MessupException {
		final String secret = "test";
		final byte[] salt = "test".getBytes(StandardCharsets.UTF_8);

		final String doSomeMess = Messup.doSomeMess(secret, salt);
		assertEquals(50, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess, salt);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessSimpleLetterWithUserSalt() throws MessupException {
		final String secret = "abcdefghijklmnopqrstuvwxyz";
		final byte[] salt = "test".getBytes(StandardCharsets.UTF_8);

		final String doSomeMess = Messup.doSomeMess(secret, salt);
		assertEquals(70, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess, salt);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessSimpleNumberWithUserSalt() throws MessupException {
		final String secret = "0123456789";
		final byte[] salt = "test".getBytes(StandardCharsets.UTF_8);

		final String doSomeMess = Messup.doSomeMess(secret, salt);
		assertEquals(50, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess, salt);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessSimpleCharWithUserSalt() throws MessupException {
		final String secret = "\"'!@#$%*()-_=+'`[{ç~^]}\\|,<.>;:/?";
		final byte[] salt = "test".getBytes(StandardCharsets.UTF_8);

		final String doSomeMess = Messup.doSomeMess(secret, salt);
		assertEquals(94, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess, salt);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessMixedCharWithUserSalt() throws MessupException {
		final String secret = "a\"0'b!1@c#2$d%3*e(4)f-5_g=6+h'7`i[8{jç9~k^0]l}1\\m|2,n<3.o>4;p:5/q?6";
		final byte[] salt = "test".getBytes(StandardCharsets.UTF_8);

		final String doSomeMess = Messup.doSomeMess(secret, salt);
		assertEquals(134, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess, salt);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessLongWordWithUserSalt() throws MessupException {
		final String secret = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
		final byte[] salt = "test".getBytes(StandardCharsets.UTF_8);

		final String doSomeMess = Messup.doSomeMess(secret, salt);
		assertEquals(626, doSomeMess.length());
		assertTrue(Messup.isMessupString(doSomeMess));

		final String undoTheMess = Messup.undoTheMess(doSomeMess, salt);
		assertEquals(secret, undoTheMess);
	}

	@Test
	public void doSomeMessNull() {
		try {
			Messup.doSomeMess(null);
		} catch (final Exception e) {
			assertTrue(e instanceof InvalidParameterException);
			assertEquals(MSG_PARAM_IS_EMPTY, e.getMessage());
		}
	}

	@Test
	public void doSomeMessEmpty() {
		try {
			Messup.doSomeMess("");
		} catch (final Exception e) {
			assertTrue(e instanceof InvalidParameterException);
			assertEquals(MSG_PARAM_IS_EMPTY, e.getMessage());
		}
	}

	@Test
	public void doSomeMessEmptyWithSpace() {
		try {
			Messup.doSomeMess("   ");
		} catch (final Exception e) {
			assertTrue(e instanceof InvalidParameterException);
			assertEquals(MSG_PARAM_IS_EMPTY, e.getMessage());
		}
	}

	@Test
	public void undoTheMessNull() {
		try {
			Messup.undoTheMess(null);
		} catch (final Exception e) {
			assertTrue(e instanceof InvalidParameterException);
			assertEquals(MSG_PARAM_IS_EMPTY, e.getMessage());
		}
	}

	@Test
	public void undoTheMessEmpty() {
		try {
			Messup.undoTheMess("");
		} catch (final Exception e) {
			assertTrue(e instanceof InvalidParameterException);
			assertEquals(MSG_PARAM_IS_EMPTY, e.getMessage());
		}
	}

	@Test
	public void undoTheMessEmptyWithSpace() {
		try {
			Messup.undoTheMess("   ");
		} catch (final Exception e) {
			assertTrue(e instanceof InvalidParameterException);
			assertEquals(MSG_PARAM_IS_EMPTY, e.getMessage());
		}
	}
}

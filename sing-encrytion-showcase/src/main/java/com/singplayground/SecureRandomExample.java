package com.singplayground;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;

public class SecureRandomExample {

	public String getSecureRandom1() throws NoSuchAlgorithmException, NoSuchProviderException {
		// The following will create SUN SHA1PRNG on Windows with 
		// default configuration and Sun JRE, and on Solaris/Linux
		// if securerandom.source is modified in java.security
		SecureRandom sr = new SecureRandom();

		// The following will create SUN SHA1PRNG if the highest 
		// priority CSP is SUN
		// **SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG");

		// The following will always create SUN SHA1PRNG
		// **SecureRandom sr3 = SecureRandom.getInstance("SHA1PRNG", "SUN");

		//Always use a SecureRandom generator
		//SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		//SecureRandom sr = new SecureRandom();
		//Create array for salt
		byte[] salt = new byte[16];
		//Get a random salt
		sr.nextBytes(salt);
		//return salt
		return salt.toString();
	}

	public String getSecureRandom2() throws NoSuchAlgorithmException, NoSuchProviderException {

		// The following will create SUN SHA1PRNG if the highest 
		// priority CSP is SUN
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

		// The following will always create SUN SHA1PRNG
		// **SecureRandom sr3 = SecureRandom.getInstance("SHA1PRNG", "SUN");

		//Always use a SecureRandom generator
		//SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		//SecureRandom sr = new SecureRandom();
		//Create array for salt
		byte[] salt = new byte[16];
		//Get a random salt
		sr.nextBytes(salt);
		//return salt
		return salt.toString();
	}

	public String getSecureRandom3() throws NoSuchAlgorithmException, NoSuchProviderException {

		// The following will always create SUN SHA1PRNG
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");

		//Always use a SecureRandom generator
		//SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		//SecureRandom sr = new SecureRandom();
		//Create array for salt
		byte[] salt = new byte[16];
		//Get a random salt
		sr.nextBytes(salt);
		//return salt
		return salt.toString();
	}

	public String getSecureRandom4() throws NoSuchAlgorithmException, NoSuchProviderException {

		// The following will always create SUN SHA1PRNG
		//java.security.SecureRandom.setSeed(java.security.SecureRandom.generateSeed(int)).
		//
		Date date = new Date();
		//date.getTime()

		//SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		SecureRandom sr = new SecureRandom();
		sr.generateSeed(16);
		sr.setSeed(sr.generateSeed(16));

		//sr.setSeed(date.getTime());
		//Always use a SecureRandom generator
		//SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		//SecureRandom sr = new SecureRandom();
		//Create array for salt
		byte[] salt = new byte[16];
		//Get a random salt
		sr.nextBytes(salt);
		//return salt
		return salt.toString();
	}

}

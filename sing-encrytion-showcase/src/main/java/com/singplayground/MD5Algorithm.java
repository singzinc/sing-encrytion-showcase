package com.singplayground;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class MD5Algorithm {

	public String example1() {

		String passwordToHash = "password";
		String generatedPassword = null;
		try {
			// Create MessageDigest instance for MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			//Add password bytes to digest
			md.update(passwordToHash.getBytes());

			//Get the hash's bytes 
			byte[] bytes = md.digest();
			//This bytes[] has bytes in decimal format;
			//Convert it to hexadecimal format
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			//Get complete hashed password in hex format
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		System.out.println("generatedPassword : " + generatedPassword);
		return generatedPassword;

	}

	public String example2(String passwordToHash, String salt) {
		String generatedPassword = null;
		try {
			// Create MessageDigest instance for MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			//Add password bytes to digest
			md.update(salt.getBytes());
			//Get the hash's bytes 
			byte[] bytes = md.digest(passwordToHash.getBytes());
			//This bytes[] has bytes in decimal format;
			//Convert it to hexadecimal format
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			//Get complete hashed password in hex format
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatedPassword;
	}

	//Add salt
	public String getSalt() throws NoSuchAlgorithmException, NoSuchProviderException {

		// The following will create SUN SHA1PRNG on Windows with 
		// default configuration and Sun JRE, and on Solaris/Linux
		// if securerandom.source is modified in java.security
		// **SecureRandom sr1 = new SecureRandom();

		// The following will create SUN SHA1PRNG if the highest 
		// priority CSP is SUN
		// **SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG");

		// The following will always create SUN SHA1PRNG
		// **SecureRandom sr3 = SecureRandom.getInstance("SHA1PRNG", "SUN");

		//Always use a SecureRandom generator
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
		//SecureRandom sr = new SecureRandom();
		//Create array for salt
		byte[] salt = new byte[16];
		//Get a random salt
		sr.nextBytes(salt);
		//return salt
		return salt.toString();
	}

}

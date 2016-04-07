package com.singplayground;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Main {

	public static void main(String[] args) {
		try {

			// ===============================================
			// ================ hash =========== 
			//			md5AlgorithmExample1();
			//			md5AlgorithmExample2();
			//			secureRandomExample1();
			//			shaAlgorithmsExample1();

			// =============== encrypt ==================
			aesAlgorithmsExample1();

		} catch (Exception e) {
			System.out.println("error : " + e);
		}
	}

	public static void md5AlgorithmExample1() {
		// ==================== Example 1 ==============
		try {
			MD5Algorithm md5Algorithm = new MD5Algorithm();
			System.out.println("start example 1");
			md5Algorithm.example1();
			System.out.println("finish example 1");
		} catch (Exception e) {
			System.out.println(e);
		}

	}

	private static void md5AlgorithmExample2() {
		try {
			MD5Algorithm md5Algorithm = new MD5Algorithm();
			System.out.println("start example 2");
			String passwordToHash = "password";
			String salt = md5Algorithm.getSalt();
			System.out.println("salt : " + salt);

			String securePassword = md5Algorithm.example2(passwordToHash, salt);
			System.out.println(securePassword); //Prints 83ee5baeea20b6c21635e4ea67847f66
												//Prints b3210c095093f7c08b82aacb0dbbad3a

			String regeneratedPassowrdToVerify = md5Algorithm.example2(passwordToHash, salt);
			System.out.println(regeneratedPassowrdToVerify); //Prints 83ee5baeea20b6c21635e4ea67847f66
			System.out.println("finish example 2");
		} catch (Exception e) {

		}
	}

	public static void secureRandomExample1() {
		// ==================== Example 1 ==============
		try {
			System.out.println("------ start secure random example -----");
			SecureRandomExample secureRandomExample = new SecureRandomExample();
			System.out.println(secureRandomExample.getSecureRandom1());
			System.out.println(secureRandomExample.getSecureRandom2());
			System.out.println(secureRandomExample.getSecureRandom3());
			System.out.println(secureRandomExample.getSecureRandom4());
			System.out.println("------ finish secure random example -----");
		} catch (Exception e) {
			System.out.println(e);
		}

	}

	public static void shaAlgorithmsExample1() {
		// ==================== Example 1 ==============
		try {

			String passwordToHash = "password";
			SecureRandomExample secureRandomExample = new SecureRandomExample();
			String salt = secureRandomExample.getSecureRandom1();
			//String salt = md5Algorithm.getSalt();

			SHAAlgorithms shaAlgorithms = new SHAAlgorithms();
			System.out.println("SHA-1 hash");
			System.out.println(shaAlgorithms.getSHASecurePassword(passwordToHash, salt, "SHA-1"));
			System.out.println("SHA-256 hash");
			System.out.println(shaAlgorithms.getSHASecurePassword(passwordToHash, salt, "SHA-256"));
			System.out.println("SHA-384 hash");
			System.out.println(shaAlgorithms.getSHASecurePassword(passwordToHash, salt, "SHA-384"));
			System.out.println("SHA-512 hash");
			System.out.println(shaAlgorithms.getSHASecurePassword(passwordToHash, salt, "SHA-512"));
			//iris_uat_2016
			salt = "s@ltValue";
			System.out.println(shaAlgorithms.getSHASecurePassword("iris_uat_2016", "", "SHA-1"));
			System.out.println("SHA-1 with salt");
			System.out.println(shaAlgorithms.getSHASecurePassword("iris_uat_2016", salt, "SHA-1"));

		} catch (Exception e) {
			System.out.println(e);
		}

	}

	public static void aesAlgorithmsExample1() {
		// ==================== Example 1 ==============
		try {
			String passwordToHash = "iris_uat_2016";
			SecureRandomExample secureRandomExample = new SecureRandomExample();
			String salt = "";
			//String salt = md5Algorithm.getSalt();

			SHAAlgorithms shaAlgorithms = new SHAAlgorithms();
			System.out.println("SHA-1 hash");
			String privateKey = shaAlgorithms.getSHASecurePassword(passwordToHash, salt, "SHA-1");
			byte[] privateKeyByte = shaAlgorithms.getSHASecurePassword2(passwordToHash, salt, "SHA-1");
			System.out.println("this is privateKey: " + privateKey);

			AESEncryption aesEncryption = new AESEncryption();
			//aesEncryption.encrypt1("1458627424923");
			//aesEncryption.encypt2();
			//aesEncryption.encypt3(privateKey);
			//aesEncryption.encypt4(privateKeyByte);
			System.out.println("**************************");
			shaAlgorithms.getSHASecurePassword3(passwordToHash, "");

		} catch (Exception e) {
			System.out.println(e);
		}

	}

	public static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) {

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);

			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();
			return res;

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

}

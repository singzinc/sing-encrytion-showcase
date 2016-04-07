package com.singplayground;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class SHAAlgorithms {

	public static String getSHASecurePassword(String passwordToHash, String salt, String shaType) {
		String generatedPassword = null;
		try {
			//MessageDigest md = MessageDigest.getInstance("SHA-1");
			MessageDigest md = MessageDigest.getInstance(shaType);
			md.update(salt.getBytes());
			byte[] bytes = md.digest(passwordToHash.getBytes());
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatedPassword;
	}

	public static byte[] getSHASecurePassword2(String passwordToHash, String salt, String shaType) {
		String generatedPassword = null;
		String content = "1458627424923";
		try {
			//MessageDigest md = MessageDigest.getInstance("SHA-1");
			MessageDigest md = MessageDigest.getInstance(shaType);
			md.update(salt.getBytes());
			byte[] bytes = md.digest(passwordToHash.getBytes());
			System.out.println("----------- " + bytes);
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			generatedPassword = sb.toString();
			System.out.println("generatedPassword :" + generatedPassword);
			byte[] key = null;
			key = Arrays.copyOf(bytes, 16);

			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

			StringBuilder sb2 = new StringBuilder();
			// Instantiate the cipher
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			byte[] encrypted = cipher.doFinal(content.getBytes());

			for (int i = 0; i < encrypted.length; i++) {
				sb2.append(Integer.toString((encrypted[i] & 0xff) + 0x100, 16).substring(1));
			}

			//String encryptedString = Base64.encodeBase64String(encrypted);
			System.out.println("ccc : " + sb2.toString());
			System.out.println(" Base64.encodeBase64String(encrypted) : " + Base64.encodeBase64String(encrypted));

			return bytes;
			/*
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			generatedPassword = sb.toString();
			*/
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// follow the example  
	// https://steelmon.wordpress.com/2013/07/01/simple-interoperable-encryption-in-java-and-net/
	public byte[] getSHASecurePassword3(String passwordToHash, String shaType) {
		String cleartext = "1458627424923";
		try {
			String password = "final_Uat@0161!2@3#4$5%6^";
			byte[] salt = new byte[] { -84, -119, 25, 56, -100, 100, -120, -45, 84, 67, 96, 10, 24, 111, 112, -119, 3 };
			//byte[] salt = new byte[] {};

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1024, 128);

			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secret = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			//AlgorithmParameters params = cipher.getParameters();
			//byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

			byte[] ciphertext = cipher.doFinal(cleartext.getBytes("UTF-8"));

			//System.out.println("IV:" + Base64.encode(iv));
			//System.out.println("Cipher text:" + Base64.encode(ciphertext));
			System.out.println("Key:" + Base64.encodeBase64String(secret.getEncoded()));
			//System.out.println("IV:" + Base64.encodeBase64String(iv));
			System.out.println("Cipher text:" + Base64.encodeBase64String(ciphertext));
			//System.out.println("iv:" + Base64.encodeBase64String(iv));
			/*
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
			String plaintext = new String(cipher.doFinal(ciphertext), "UTF-8");
			System.out.println("return plaintext" + plaintext);
			*/
			//System.out.println("Key:" + Base64.encode(secret.getEncoded()));
			//System.out.println("Key:" + Base64.encodeBase64String(secret.getEncoded()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/*
	private static String get_SHA_1_SecurePassword(String passwordToHash, String salt)
	{
	    String generatedPassword = null;
	    try {
	        MessageDigest md = MessageDigest.getInstance("SHA-1");
	        md.update(salt.getBytes());
	        byte[] bytes = md.digest(passwordToHash.getBytes());
	        StringBuilder sb = new StringBuilder();
	        for(int i=0; i< bytes.length ;i++)
	        {
	            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
	        }
	        generatedPassword = sb.toString();
	    } 
	    catch (NoSuchAlgorithmException e) 
	    {
	        e.printStackTrace();
	    }
	    return generatedPassword;
	}
	 
	private static String get_SHA_256_SecurePassword(String passwordToHash, String salt)
	{
	    //Use MessageDigest md = MessageDigest.getInstance("SHA-256");
	}
	 
	private static String get_SHA_384_SecurePassword(String passwordToHash, String salt)
	{
	    //Use MessageDigest md = MessageDigest.getInstance("SHA-384");
	}
	 
	private static String get_SHA_512_SecurePassword(String passwordToHash, String salt)
	{
	    //Use MessageDigest md = MessageDigest.getInstance("SHA-512");
	}
	*/

	//Add salt
	/*
	private static String getSalt() throws NoSuchAlgorithmException
	{
	    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
	    byte[] salt = new byte[16];
	    sr.nextBytes(salt);
	    return salt.toString();
	}
	*/

}

package com.singplayground;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESEncryption {

	public static void encrypt1(String Data) throws Exception {
		char[] password = new char[] { '1', '2', '3', '4', '5' };
		byte[] salt = new byte[] { 1, 2, 3, 4, 5 };
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		System.out.println("Algorithm : " + tmp.getAlgorithm());
		System.out.println("encoded : " + secret.getEncoded());
		System.out.println("to string : " + secret.getEncoded().toString());
	}

	public static void encypt2() throws Exception {

		try {

			String privateKey = "iris_uat_2016";
			String content = "1458627424923";
			byte[] key = (privateKey).getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");

			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			System.out.println("this is provider info : " + sha.getProvider().getInfo());
			System.out.println("get provider name : " + sha.getProvider().getName());

			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

			// Instantiate the cipher
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			byte[] encrypted = cipher.doFinal(content.getBytes());

			String encryptedString = Base64.encodeBase64String(encrypted);

			System.out.println("this is encrypted String :" + encryptedString);

			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			//byte[] original = cipher.doFinal(encrypted);

			//System.out.println("********** " + Base64.encodeBase64String(encrypted));
			//String originalString = new String(original);
			//System.out.println("Original string: " + originalString + "\nOriginal string encryptedString : " + encryptedString);

		} catch (Exception e) {
			System.out.println(e);

		}

	}

	public static void encypt3(String privateKey) throws Exception {

		try {

			//String privateKey = "iris_uat_2016";
			System.out.println("this is the private key: " + privateKey);
			String content = "1458627424923";
			byte[] key = (privateKey).getBytes(StandardCharsets.US_ASCII);
			//MessageDigest sha = MessageDigest.getInstance("SHA-1");
			System.out.println("no trim key :  " + Base64.encodeBase64String(key));
			//key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			//System.out.println("this is provider info : " + sha.getProvider().getInfo());
			//System.out.println("get provider name : " + sha.getProvider().getName());
			System.out.println("trim key1 US_ASCII :  " + Base64.encodeBase64String(key));

			key = (privateKey).getBytes("UTF-8");
			key = Arrays.copyOf(key, 16);
			System.out.println("trim key2 UTF-8: " + Base64.encodeBase64String(key));
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

			// Instantiate the cipher
			//Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			byte[] encrypted = cipher.doFinal(content.getBytes(StandardCharsets.US_ASCII));

			String encryptedString = Base64.encodeBase64String(encrypted);
			System.out.println("this is encrypted String :" + encryptedString);

			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] original = cipher.doFinal(encrypted);

			//System.out.println("********** " + Base64.encodeBase64String(encrypted));
			String originalString = new String(original);
			System.out.println("Original string: " + originalString + "\nOriginal string encryptedString : " + encryptedString);

		} catch (Exception e) {
			System.out.println(e);

		}

	}

	public static void encypt4(byte[] privateKeyByte) throws Exception {

		try {

			String content = "1458627424923";
			byte[] key = null;

			key = Arrays.copyOf(privateKeyByte, 16); // use only first 128 bit
			//System.out.println("this is provider info : " + sha.getProvider().getInfo());
			//System.out.println("get provider name : " + sha.getProvider().getName());
			//System.out.println("trim key1 US_ASCII :  " + Base64.encodeBase64String(key));

			//key = (privateKey).getBytes("UTF-8");
			//key = Arrays.copyOf(key, 16);
			System.out.println("trim key2 UTF-8: " + Base64.encodeBase64String(key));
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

			// Instantiate the cipher
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			//Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			byte[] encrypted = cipher.doFinal(content.getBytes(StandardCharsets.US_ASCII));

			String encryptedString = Base64.encodeBase64String(encrypted);
			System.out.println("this is encrypted String :" + encryptedString);

			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] original = cipher.doFinal(encrypted);

			//System.out.println("********** " + Base64.encodeBase64String(encrypted));
			String originalString = new String(original);
			System.out.println("Original string: " + originalString + "\nOriginal string encryptedString : " + encryptedString);

		} catch (Exception e) {
			System.out.println(e);

		}

	}

}

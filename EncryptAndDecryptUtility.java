package com.emudhra.emidamUser.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EncryptAndDecryptUtility {
	

	
	@Value("${pfxPath}")
	String pfxPath;
	
	
	private static SecureRandom random = new SecureRandom();
	
	public  String createHash(String signedHash) {

		byte[] bytehasg = signedHash.getBytes();

		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");

			ByteArrayInputStream fis12 = new ByteArrayInputStream(bytehasg);
			byte[] dataBytes = new byte[1024];
			int nread = 0;
			while ((nread = fis12.read(dataBytes)) != -1) {
				md.update(dataBytes, 0, nread);
			}
			byte[] hashedData = md.digest();
			String encoded_data = Base64.encodeBase64URLSafeString(hashedData);
			return encoded_data;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}
	
	
	public  String generatePassword(int len, String dic) {
		String result = "";
		for (int i = 0; i < len; i++) {
			int index = random.nextInt(dic.length());
			result += dic.charAt(index);
		}
		return result;
	}
	
	
	
	
	
    public PublicKey getPublicKey()  
    {
    	ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outStream);
        PublicKey publicKey = null;
        try
        {
          //loading PFX keystore
          String password = "tpm";
	      String alias = null ;
	      String tbs = "hsdakhfkjh";
	      char[] pass = password.toCharArray();
          KeyStore ks = KeyStore.getInstance("PKCS12");
          //ks.load(new FileInputStream("E://IDAMPFX//tpm.pfx"), pass);
          System.out.println("pfxPath == "+pfxPath);
          ks.load(new FileInputStream(pfxPath), pass);
          Enumeration enumeration = ks.aliases();
          while(enumeration.hasMoreElements()) 
           {
             alias = (String)enumeration.nextElement(); 
           }   
       
          //fetching certificate
          X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
          //fetching public key
          publicKey = cert.getPublicKey(); 
        }
        catch(Exception e)
        {
        	e.printStackTrace();
        }
        return publicKey;
    }

    public PrivateKey getPrivateKey()  
    {
    	ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outStream);
        PrivateKey privateKey = null;
        try
        {
          //loading PFX keystore
          String password = "tpm";
	      String alias = null ;
	      
	      char[] pass = password.toCharArray();
          KeyStore ks = KeyStore.getInstance("PKCS12");
        //ks.load(new FileInputStream("E://IDAMPFX//tpm.pfx"), pass);
          System.out.println("pfxPath == "+pfxPath);
          ks.load(new FileInputStream(pfxPath), pass);
    
          Enumeration enumeration = ks.aliases();
          while(enumeration.hasMoreElements()) 
           {
             alias = (String)enumeration.nextElement(); 
           }   
       
          //fetching certificate
          X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
          
        //fetching private key       
          privateKey = (PrivateKey) ks.getKey(alias, pass); 
        }
        catch(Exception e)
        {
        	e.printStackTrace();
        }
        return privateKey;
    }

    
    public  String encrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
        byte[] base64encodedByte = Base64.encodeBase64(cipher.doFinal(message.getBytes()));
		return new String(base64encodedByte);
		
    }
    
    public  String decrypt(PrivateKey privateKey, String encryptedString) throws Exception {
    	byte[] encryptedbBytes = Base64.decodeBase64(encryptedString);
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(encryptedbBytes));
    }
	
}

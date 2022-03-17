package com.khaica.provider.jceremote.main;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import com.khaica.provider.JCERemote;
import com.khaica.provider.jceremote.JCERemotePrivateKey;

public class Main {
	public static void main(String[] args) {
		Security.addProvider(new JCERemote());
		try {
			JCERemotePrivateKey privateKey = new JCERemotePrivateKey();
			privateKey.setKeyId("KhaiPT");
			Signature signature = Signature.getInstance("SHA1withRSA", "JCERemote");
			signature.initSign(privateKey);
			signature.update("hello world".getBytes());
			byte[] dataSigned = signature.sign();
			System.out.println("Data Signed Base64: " + java.util.Base64.getEncoder().encodeToString(dataSigned));
//			System.out.println(signature.getProvider());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}
}

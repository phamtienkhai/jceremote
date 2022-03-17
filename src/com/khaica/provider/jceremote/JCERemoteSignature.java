package com.khaica.provider.jceremote;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import com.khaica.provider.jceremote.client.RemoteSigner;

public class JCERemoteSignature extends SignatureSpi {
	
	private JCERemotePrivateKey privateKey;
	public PublicKey publicKey;
	private byte[] dataToSign;
	private String alg;
	
	public JCERemoteSignature(String alg) {
		this.alg = alg;
	}

	@Override
	protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
		this.publicKey = publicKey;
	}

	@Override
	protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
		this.privateKey = (JCERemotePrivateKey) privateKey;
	}

	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		dataToSign = new byte[] {b};
	}

	@Override
	protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		os.write(b, off, len);
		dataToSign = os.toByteArray();
		try {
			os.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	protected byte[] engineSign() throws SignatureException {
		byte[] dataSigned = RemoteSigner.remoteSignData(privateKey.getKeyId(), dataToSign, alg);
//		System.out.println("vao ham ky");
		return dataSigned;
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
		return false;
	}

	@Override
	protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
		
	}

	@Override
	protected Object engineGetParameter(String param) throws InvalidParameterException {
		return null;
	}
	
	public static final class SHA1withRSA extends JCERemoteSignature {
		public SHA1withRSA() {
			super("SHA1withRSA");
		}
	}
	
	public static final class SHA256withRSA extends JCERemoteSignature {
		public SHA256withRSA() {
			super("SHA256withRSA");
		}
	}
}

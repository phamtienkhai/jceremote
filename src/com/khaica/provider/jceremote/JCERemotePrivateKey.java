package com.khaica.provider.jceremote;

import java.security.PrivateKey;

public class JCERemotePrivateKey implements PrivateKey {

	private static final long serialVersionUID = -5979726219827697388L;
	
	private String keyId;

	public String getKeyId() {
		return keyId;
	}

	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}

	@Override
	public String getAlgorithm() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}
	
}

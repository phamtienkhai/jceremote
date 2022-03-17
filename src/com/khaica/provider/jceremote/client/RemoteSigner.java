package com.khaica.provider.jceremote.client;

import javax.ws.rs.core.MediaType;

import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource.Builder;

public class RemoteSigner {

	private static Client client;

	static {
		client = Client.create();
	}

	public static byte[] remoteSignData(String keyId, byte[] data, String alg) {
		WebResource webResource = client.resource("http://192.168.44.55:8080/SparkAPIPKIv1/signData");
		String inputFormat = "{\r\n" + "	\"data\":\"%s\",\r\n" + "	\"alg\":\"%s\",\r\n"
				+ "	\"keyId\":\"%s\"\r\n" + "}";
		String dataBase64 = java.util.Base64.getEncoder().encodeToString(data);
		String input = String.format(inputFormat, dataBase64, alg, keyId);
		ClientResponse response = webResource.type("application/json").post(ClientResponse.class, input);
//		webResource.type("").get(ClientResponse.class, input);
		if (response.getStatus() != 200) {
			System.out.println("Failed : HTTP error code : " + response.getStatus());

			String error = response.getEntity(String.class);
			System.out.println("Error: " + error);
			return null;
		}

		System.out.println("Output from Server .... \n");

		String output = response.getEntity(String.class);

		Object object = JSONValue.parse(output);
		JSONObject jsonObject = (JSONObject) object;

//		String data2 = (String) jsonObject.get("data");
		
		jsonObject = (JSONObject) jsonObject.get("data");
//		jsonObject = (JSONObject) object;
		String dataSignedBase64 = (String) jsonObject.get("dataSigned");
		String certBase64 = (String) jsonObject.get("certificate");

		System.out.println("Data Signed Base64: " + dataSignedBase64);
		System.out.println("certificate: "+certBase64);
		byte[] dataSigned = java.util.Base64.getDecoder().decode(dataSignedBase64);
		return dataSigned;
//		return null;
	}

	public static String remoteGetCertificate(String keyId) {
		WebResource webResource = client.resource("http://192.168.44.55:8080/SparkAPIPKIv1/getCertificate");
		String inputFormat = "{\r\n" + "    \"aliase\":\"%s\"\r\n" + "}";
		String input = String.format(inputFormat, keyId);
		Builder builder = webResource.accept(MediaType.APPLICATION_JSON) //
				.header("content-type", MediaType.APPLICATION_JSON);

//		ClientResponse response = builder.get(ClientResponse.class);
//		System.out.println(response.getClass());
		ClientResponse response = webResource.type("application/json").post(ClientResponse.class, input);
		if (response.getStatus() != 200) {
			System.out.println("Failed : HTTP error code : " + response.getStatus());

			String error = response.getEntity(String.class);
			System.out.println("Error: " + error);
			return null;
		}

		System.out.println("Output from Server .... \n");

		String output = response.getEntity(String.class);

		Object object = JSONValue.parse(output);
		JSONObject jsonObject = (JSONObject) object;

		String certificateBase64 = (String) jsonObject.get("message");

		System.out.println("Certificate Base64: " + certificateBase64);
//		byte[] dataSigned = java.util.Base64.getDecoder().decode(dataSignedBase64);
//		return dataSigned;
		return certificateBase64;
	}

	public static void main(String[] args) {
//		Client client = Client.create();
//		WebResource webResource = client.resource("http://192.168.44.55:8080/SparkAPIPKIv1/signData");
//		String input = "{\r\n" + "	\"data\":\"aGVsbG8gd29ybGQ\",\r\n" + "	\"alg\":\"SHA256withRSA\",\r\n"
//				+ "	\"keyId\":\"KhaiPT\"\r\n" + "}";
//		ClientResponse response = webResource.type("application/json").post(ClientResponse.class, input);
//		if (response.getStatus() != 200) {
//			System.out.println("Failed : HTTP error code : " + response.getStatus());
//
//			String error = response.getEntity(String.class);
//			System.out.println("Error: " + error);
//			return;
//		}
//
//		System.out.println("Output from Server .... \n");
//
//		String output = response.getEntity(String.class);
//
//		System.out.println(output);
//		remoteSignData("KhaiPT", "hello world".getBytes(), "SHA256withRSA");
		remoteGetCertificate("KhaiPT");
	}
}

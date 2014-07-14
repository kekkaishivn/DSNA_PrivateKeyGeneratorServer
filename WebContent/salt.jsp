<%@page import="java.util.Arrays"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ page import="java.util.Date" %>
<%@ page import="java.util.Calendar" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.TreeMap" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileInputStream" %>
<%@ page import="java.io.FileOutputStream" %>
<%@ page import="com.google.gson.Gson" %>
<%@ page import="org.bouncycastle.crypto.AsymmetricCipherKeyPair" %>
<%@ page import="org.bouncycastle.crypto.CipherParameters" %>
<%@ page import="com.dsna.crypto.asn1.exception.InvalidCertificateException" %>
<%@ page import="com.dsna.crypto.asn1.exception.UnsupportedFormatException" %>
<%@ page import="com.dsna.crypto.ibbe.cd07.IBBECD07" %>
<%@ page import="com.dsna.crypto.ibbe.cd07.params.CD07KeyParameters" %>
<%@ page import="com.dsna.crypto.signature.ps06.PS06" %>
<%@ page import="com.dsna.entity.encrypted.KeyHeader" %>
<%@ page import="com.dsna.entity.encrypted.KeyInfo" %>
<%@ page import="org.bouncycastle.crypto.CipherParameters" %>
<%@ page import="com.dsna.crypto.asn1.params.IBESecretParameters" %>
<%@ page import="com.dsna.crypto.asn1.params.IBEClientSecretParams" %>
<%@ page import="com.dsna.util.ASN1Util" %>
<%@ page import="com.dsna.util.HashUtil" %>
<%@ page import="com.dsna.util.FileUtil" %>
<%@ page import="java.security.InvalidKeyException" %>
<%@ page import="java.security.NoSuchAlgorithmException" %>
<%@ page import="javax.crypto.BadPaddingException" %>
<%@ page import="javax.crypto.Cipher" %>
<%@ page import="javax.crypto.IllegalBlockSizeException" %>
<%@ page import="javax.crypto.NoSuchPaddingException" %>
<%@ page import="javax.crypto.spec.SecretKeySpec" %>
<%@ page import="rice.p2p.util.Base64" %>
<%@ page import="com.dsna.crypto.asn1.params.IBEPublicParameters" %>
<%@ page import="com.dsna.crypto.asn1.params.IBESysPublicParams" %>
<%@ page import="it.unisa.dia.gas.crypto.jpbc.signature.ps06.params.PS06KeyParameters" %>
<%@ page import="it.unisa.dia.gas.jpbc.Element;" %>   

<% 
{
	//ServletContext.this.getContextPath();
	//out.println((new FileInputStream()));
	//out.println(getServletContext().getRealPath(getServletContext().getContextPath()));
	
		
	String encodedSystemMasterSecretParams = FileUtil.readString(new FileInputStream("/home/datletien/masterscret/MasterSystemSecret.txt"));
	String material = FileUtil.readString(new FileInputStream("/home/datletien/masterscret/material"));
	material = material.trim();
	TreeMap<String, String> source = (TreeMap<String, String>)FileUtil.readObject(new FileInputStream("/home/datletien/mastersource/File.dat"));
	TreeMap<String, byte[]> plainSource = new TreeMap<String, byte[]>();
	byte[] bytes = HashUtil.doSHA1Hash(material);
	byte[] decryptKey = Arrays.copyOf(bytes, 16);
	
   	{
		for( String path : source.keySet())	
		{
		    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		    SecretKeySpec secretKey = new SecretKeySpec(decryptKey, "AES");
		    cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] encryptedBytes = Base64.decode(source.get(path));
			byte[] plainBytes = cipher.doFinal(encryptedBytes);
			plainSource.put(path, plainBytes);
		}
			
	}  
	
 	
	String encodedSystemPublicParams = FileUtil.readString(getServletContext().getResourceAsStream("/SystemPublic.txt")); 
	
	CipherParameters[] publicKeys = ASN1Util.extractPublicKey(ASN1Util.decodeIBESysPublicParams(encodedSystemPublicParams));
	CipherParameters[] masterKeys = ASN1Util.extractMasterSecretKey(ASN1Util.decodeIBESysMasterSecretParams(encodedSystemMasterSecretParams));
	
	AsymmetricCipherKeyPair[] keyPairs = new AsymmetricCipherKeyPair[2];
	keyPairs[0] = new AsymmetricCipherKeyPair(publicKeys[0], masterKeys[0]);
	keyPairs[1] = new AsymmetricCipherKeyPair(publicKeys[1], masterKeys[1]);
	
	String clientId = request.getParameter("clientid");
	String[] ids = new String[]{ clientId };
	if (clientId!=null && clientId.length()>0)	{
		clientId = clientId.toLowerCase();		
		
		IBBECD07 cd07 = new IBBECD07();		
		
		Element[] cd07Ids = cd07.map(publicKeys[1], ids);
		byte[][] ciphertext = cd07.encaps(publicKeys[1], cd07Ids);
		byte[] keyMaterial = ciphertext[0];
		byte[] keyHeader = ciphertext[1];
		TreeMap<String, String> dynamicEncryptedSource = new TreeMap<String, String>();
		
	    String headerKey = Base64.encodeBytes(HashUtil.doSHA256Hash(clientId));
	    String headerValue = Base64.encodeBytes(keyHeader);
	    dynamicEncryptedSource.put(headerKey, headerValue);
	    String materialKey =  Base64.encodeBytes(HashUtil.doSHA256Hash(clientId+clientId.substring(5)));
	    String materialValue =  Base64.encodeBytes(keyMaterial);
	    dynamicEncryptedSource.put(materialKey, materialValue);		
		
		{
			byte[] encryptedKey = Arrays.copyOf(keyMaterial, 16);
		    
		    for (String path : plainSource.keySet())
		    {
			    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			    SecretKeySpec secretKey = new SecretKeySpec(encryptedKey, "AES");
			    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		    	String newKey = Base64.encodeBytes(HashUtil.doSHA1Hash(path+materialValue));
		    	String newValue = Base64.encodeBytes(cipher.doFinal(plainSource.get(path)));
		    	dynamicEncryptedSource.put(newKey, newValue);
		    }
		    
		}
		
		Gson gson = new Gson();
	    out.println(gson.toJson(dynamicEncryptedSource));  
	}  
    
}

%>
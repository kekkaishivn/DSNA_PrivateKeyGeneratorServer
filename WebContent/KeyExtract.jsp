<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ page import="java.util.Date" %>
<%@ page import="java.util.Calendar" %>
<%@ page import="java.io.FileInputStream" %>
<%@ page import="java.io.FileOutputStream" %>
<%@ page import="org.bouncycastle.crypto.AsymmetricCipherKeyPair" %>
<%@ page import="org.bouncycastle.crypto.CipherParameters" %>
<%@ page import="com.dsna.crypto.asn1.exception.InvalidCertificateException" %>
<%@ page import="com.dsna.crypto.asn1.exception.UnsupportedFormatException" %>
<%@ page import="com.dsna.crypto.ibbe.cd07.IBBECD07" %>
<%@ page import="com.dsna.crypto.ibbe.cd07.params.CD07KeyParameters" %>
<%@ page import="com.dsna.crypto.signature.ps06.PS06" %>
<%@ page import="org.bouncycastle.crypto.CipherParameters" %>
<%@ page import="com.dsna.crypto.asn1.params.IBESecretParameters" %>
<%@ page import="com.dsna.crypto.asn1.params.IBEClientSecretParams" %>
<%@ page import="com.dsna.util.ASN1Util" %>
<%@ page import="com.dsna.util.FileUtil" %>
<%@ page import="com.dsna.crypto.asn1.params.IBEPublicParameters" %>
<%@ page import="com.dsna.crypto.asn1.params.IBESysPublicParams" %>
<%@ page import="it.unisa.dia.gas.crypto.jpbc.signature.ps06.params.PS06KeyParameters" %>
<%@ page import="it.unisa.dia.gas.jpbc.Element;" %>    

<% 
{
	//ServletContext.this.getContextPath();
	//out.println((new FileInputStream()));
	//out.println(getServletContext().getRealPath(getServletContext().getContextPath()));
	Calendar cal = Calendar.getInstance();
	cal.set(2014, 1, 1);
    Date notBefore = cal.getTime();
    cal.set(2015, 5, 10);
    Date notAfter = cal.getTime();	    
   		
		
	String encodedSystemMasterSecretParams = FileUtil.readString(new FileInputStream("/home/datletien/masterscret/MasterSystemSecret.txt"));
	String encodedSystemPublicParams = FileUtil.readString(getServletContext().getResourceAsStream("/SystemPublic.txt"));
	
	CipherParameters[] publicKeys = ASN1Util.extractPublicKey(ASN1Util.decodeIBESysPublicParams(encodedSystemPublicParams));
	CipherParameters[] masterKeys = ASN1Util.extractMasterSecretKey(ASN1Util.decodeIBESysMasterSecretParams(encodedSystemMasterSecretParams));
	
	AsymmetricCipherKeyPair[] keyPairs = new AsymmetricCipherKeyPair[2];
	keyPairs[0] = new AsymmetricCipherKeyPair(publicKeys[0], masterKeys[0]);
	keyPairs[1] = new AsymmetricCipherKeyPair(publicKeys[1], masterKeys[1]);
	
	String clientId = request.getParameter("clientid");
	if (clientId!=null && clientId.length()>0)	{
		clientId = clientId.toLowerCase();		
		
		PS06 ps06 = new PS06();
		IBBECD07 cd07 = new IBBECD07();		
		
		CipherParameters[] clientKeys = new CipherParameters[2];
		clientKeys[0] = ps06.extract(keyPairs[0], clientId);
		clientKeys[1] = cd07.extract(keyPairs[1], clientId);
		
		System.out.println(((PS06KeyParameters) publicKeys[0]).getParameters().getCurveParams());
		System.out.println(((CD07KeyParameters) publicKeys[1]).getParameters().getCurveParams());
		
		IBESecretParameters ps06SecretKeyObject = (IBESecretParameters)ASN1Util.toASN1Object(clientKeys[0]);
	    IBESecretParameters cd07SecretKeyObject = (IBESecretParameters)ASN1Util.toASN1Object(clientKeys[1]);
	    IBEClientSecretParams clientSecretKeys = new IBEClientSecretParams(1, "KTH - Mobile Service Lab", 10001, notBefore, notAfter, ps06SecretKeyObject, cd07SecretKeyObject);
	    
	    ASN1Util.extractClientSecretKey(clientSecretKeys, publicKeys);
	    
	    out.println(ASN1Util.encode(clientSecretKeys));  
	}
    
}

%>
import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Enumeration;

/**
 * Created by Anil on 25/1/16.
 */
public class TokenInitializerTest {
    public Long tokenSlot;
    HttpClient httpClient;
    private String curLib="";

    public static void main(String[] args) throws Exception {
        System.out.println("os.name "+System.getProperty("os.name"));
        String userId = args[0];
        String password = args[1];
        String panId = args[2];
        System.out.println("Testing DSS for User name : "+userId+" password : "+password+" pan : "+panId);
        TokenInitializerTest t = new TokenInitializerTest();
        t.setLibrary(System.getProperty("os.name").toLowerCase().contains("win"),args.length>3 && args[3].trim().equalsIgnoreCase("alladin"));
        String signature = t.getSignature(userId,password,panId);
        System.out.println("Generated Signature :: \n"+signature);
        String panDetails = t.panInquiry(userId + "^" + panId, signature);
        System.out.println("Pan details recevied from NSDL is ::\n"+panDetails);
        System.exit(0);
    }

    private void setLibrary(final boolean isWin,final boolean isAlladin){
        if(!isWin){
            if(isAlladin)
                curLib = "/usr/lib/libeTPkcs11.so";
            else
                curLib= "/usr/lib/libaetpkss.so.3";
        } else {
            if(isAlladin)
                curLib = "C:/Windows/System32/etpkcs11.dll";
            else
                curLib= "C:/Windows/System32/aetpkss1.dll";
        }
        System.out.println("Lib set to : "+curLib);
    }

    /**
     * Mapping of EToken Serial Number to Slot IDs
     * Whenever a new Etoken is introduced in system this function should be called to
     * create fresh mapping
     */
    private void slotMapping(){
        System.out.println("******************************EToken Mapping Start******************************");
        try {
            PKCS11 p11 = PKCS11.getInstance(curLib, "C_GetFunctionList", null, false);
            long[] slotList = p11.C_GetSlotList(true);  //Returns array of all connected token slots for given library.
            CK_TOKEN_INFO ck_token_info;
            for (Long slot : slotList){
                try{
                    ck_token_info = p11.C_GetTokenInfo(slot);
                    char[] serialNum = ck_token_info.serialNumber;
                    System.out.println("Serial Number of token is "+ serialNum+" available at slot "+slot);
                    tokenSlot = slot;    //Mapping serial Number --> Slot
                }
                catch (PKCS11Exception ex){
                    System.out.println("Unable to access Token Info for slot " + slot + " for library " + curLib);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PKCS11Exception e) {
            e.printStackTrace();
        }
        System.out.println("******************************EToken Mapping END******************************");
    }

    /**
     * Digital signature generation using Hardware token
     * On the basis of serial number defined in config for the bank.
     * @return signature : Generated signature for the given data using Etoken
     */
    public String getSignature(String userId,String password,String panNo) {
        String data=userId+"^"+panNo;
        byte[] dataToSign;
        slotMapping();
        String config = "name=" + panNo + "\nlibrary=" + curLib + "\nslot=" + tokenSlot;       // Config for Bank Id EToken
        Provider userProvider = new SunPKCS11(new ByteArrayInputStream(config.getBytes()));
        dataToSign = data.getBytes();
        return getSignature(userProvider,dataToSign,password.toCharArray());
    }

    /**
     * Private Helper method for getSignature with additional parameters
     * @param userProvider  : Provider initialized with proper slot and library
     * @param dataToSign  : Data To be signed
     * @param password  : EToken Password
     * @return signature : Generated signature for the given data using Etoken
     */
    private String getSignature(Provider userProvider,byte[] dataToSign,char[] password)
    {
        Security.addProvider(userProvider);
        System.out.println("Adding security provider : " + userProvider.getName());
        String signature = null;
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS11", userProvider);      // Logging into token
            ks.load(null, password);    //Loading Keystore
            Enumeration e = ks.aliases();   //enumeration alias
            String alias = null;
            while (e.hasMoreElements()){
                alias = (String) e.nextElement();
                System.out.println("Alias of the e-Token used : " + alias);
                String tokenProvider = userProvider.getName();
                signature = generateSignature(ks,tokenProvider,dataToSign,alias,password);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            Security.removeProvider(userProvider.getName());
        }
        return signature;
    }

    /**
     * Digital Signature Geneartion
     * @param ks  : PKCS11 Keystore for Provider
     * @param tokenProvider : Provider used for signing
     * @param dataToSign  : Data To be signed
     * @param alias : Used for finding certificates in EToken
     * @param password  : EToken Password
     * @return signature : Generated signature for the given data using Etoken
     */
    private String generateSignature(KeyStore ks,String tokenProvider,byte[] dataToSign,String alias,char[] password){

        ArrayList certList = new ArrayList();
        CertStore certs = null;
        PrivateKey privateKey= null;
        String signature = null;
        try {
            privateKey = (PrivateKey) ks.getKey(alias,password);
            X509Certificate myPubCert = (X509Certificate) ks.getCertificate(alias);
            CMSSignedDataGenerator sgen = new CMSSignedDataGenerator();
            Provider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            sgen.addSigner(privateKey, myPubCert, CMSSignedDataGenerator.DIGEST_SHA1);
            certList.add(myPubCert);
            certs = (CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC"));
            sgen.addCertificatesAndCRLs(certs);
            CMSSignedData csd = sgen.generate(new CMSProcessableByteArray(dataToSign),true, tokenProvider);

            byte[] signedData = csd.getEncoded();
            byte[] signedData64 = Base64.encode(signedData);
            signature = new String(signedData64);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertStoreException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        }
        finally {
            Security.removeProvider("BC");
        }
        return  signature;
    }

    public void init() {
        try {
            HttpConnectionManagerParams params = new HttpConnectionManagerParams();
            HttpConnectionManager connectionManager = new MultiThreadedHttpConnectionManager();

            params.setDefaultMaxConnectionsPerHost(10);
            params.setMaxConnectionsPerHost(HostConfiguration.ANY_HOST_CONFIGURATION, 10);
            params.setConnectionTimeout(5000);
            params.setSoTimeout(5000);
            params.setMaxTotalConnections(10);
            params.setTcpNoDelay(true);
            params.setStaleCheckingEnabled(true);
            params.setLinger(-1);

            connectionManager.setParams(params);

            httpClient = new HttpClient();
            httpClient.setHttpConnectionManager(connectionManager);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String panInquiry(String input, String signature) throws Exception {
        init();
        String urlParameters = "data=" + URLEncoder.encode(input, "UTF-8") + "&signature=" + URLEncoder.encode(signature, "UTF-8");

        HttpMethod method = new PostMethod("https://59.163.46.2/TIN/PanInquiryBackEnd");
        method.setQueryString(urlParameters);

        httpClient.executeMethod(method);
        return method.getResponseBodyAsString();
    }

}

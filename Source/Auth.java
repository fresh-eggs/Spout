import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.text.BadLocationException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;


public class Auth 
{
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private TheGUI theGUI = null;
	private String userName;
	private boolean newClient;
	private ObjectOutputStream outToServer;
	private ObjectInputStream inFromServer;
	private static boolean pinSet = false;
	private static String pin;
	private static boolean readyForPin = false;//used by GUI
	private static KeyPair keyPair;
	private static SecretKeySpec privateSymKey;

	
	public Auth(TheGUI p1_gui, String p2_username, boolean p3_isNewClient, 
			ObjectOutputStream p4_outToServer, ObjectInputStream p5_inFromServer)
	{
		theGUI = p1_gui;
		userName = p2_username;
		newClient = p3_isNewClient;
		outToServer = p4_outToServer;
		inFromServer = p5_inFromServer;
	}



	//These are the variables we use to reference the clients public/private keys.
	//They are set below for both cases. (Client is new or returning)
	PrivateKey privateKeyForStorage = null; //RSA Private key
	PublicKey publicKeyForStorage = null;



	//========================================
	//        SETUP NEW/RETURNING USERS
	//========================================
	/*
	 * Loop until a username is entered into the chat window. GUI sets isUsernameSet == true
	 */

	public void SetupKeys() throws Exception
	{
		//This is where we setup new clients.
		if(newClient)
		{
			//In here we are creating the username hash to be used for identification and other things.
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
			String usernameHash = new String(Hex.encodeHex(sha1.digest((userName).getBytes())));
			System.out.println(usernameHash);
			outToServer.writeObject(usernameHash); //send over the user name hash

			//In order to give the user his set of keys.
			GenerateRSAKeys();

			//We call these in order to create and store the user's public private keypair.
			publicKeyForStorage = setupNewUserPublicKey(usernameHash);
			privateKeyForStorage = setupNewUserPrivateKey(usernameHash);

			//We do this to take in the secret for the HMAC.
			readyForPin = true;
			theGUI.appendString("[System]: Please input the PIN\n");
			
			//wait for PIN to be entered
			while(pinSet == false){Thread.sleep(1000);}
			String thePin = pin;
			pin = null;
			System.gc();//*Note: we call the GC to hope we wash away the bytes of "pin" from memory.

			//Encode the publicKey in order to keep it safe from corruption during the send.
			byte[] encodedPublic = publicKeyForStorage.getEncoded();
			String encodedPublicString = new String(Base64.encodeBase64(encodedPublic));

			//Calcualte HMAC on public key to send to server for validation of data.
			String HMAC = calculateHMAC(encodedPublicString, thePin);
			outToServer.writeObject(HMAC);
			outToServer.writeObject(encodedPublicString);

			exchangeSecret(thePin, inFromServer, privateKeyForStorage);
		}
		//This is where we validate old clients, this is where we would check database for the keys.
		else
		{
			boolean couldNotFindUsername = false;
			do
			{
				//Create the hash for the given username in order to compare it.
				MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
				String usernameHash = new String(Hex.encodeHex(sha1.digest((userName).getBytes())));
				System.out.println(usernameHash);

				//Setup a key factory in order to fabricate our keys from their
				//stored bytes.
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");


				try
				{
					//path to the public key bytes
					Path path = Paths.get("C:\\Users\\Public\\Documents\\"+usernameHash+".txt");

					//Read all the bytes for the public key and load it into our publicKeySpec.
					byte[] encodedPublic = Files.readAllBytes(path);
					EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
					publicKeyForStorage = keyFactory.generatePublic(publicKeySpec);


					//Gather the private key
					Path path2 = Paths.get("C:\\Users\\Public\\Documents\\"+usernameHash+"_.txt");

					//Load up the private key, this is the section where we would need passwords and to create
					//something to have it decrypt with the password, also go get the salt.
					byte[] encodedPrivate = Files.readAllBytes(path2);
					EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivate);
					privateKeyForStorage = keyFactory.generatePrivate(privateKeySpec);
					

				}
				catch(NoSuchFileException e7){
					theGUI.appendString("[System]: Could not find username, please try again.\n");
					couldNotFindUsername = true;
				}
				
				

				if(!couldNotFindUsername)
				{
					outToServer.writeObject(usernameHash); //send over the user name hash

					//Authentication
					//Wait for the server to send us randomly generated string
					String theEncryptedSecret = (String)inFromServer.readObject();

					//Decrypt
					String theSecret = DecryptRSA(theEncryptedSecret, privateKeyForStorage); 

					//Recieve the shared secret for the seshion.
					exchangeSecret(theSecret, inFromServer, privateKeyForStorage);	
				}
			
			}while(couldNotFindUsername == false);
		}
	}
	
	
	
	private static void GenerateRSAKeys() throws Exception
	{
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		keyPair = keygen.generateKeyPair();
	}
	
	
	
	//=======================================
	//
	// 			     NEW USER
	//
	//=======================================
	public PublicKey setupNewUserPublicKey(String usernameHash) throws BadLocationException, InterruptedException, IOException
	{
		/*This sets the variables for the users RSA keys. These RSA keys are only used for the digital signature.
		These are the bytes that are going to be stored by the database for every computer, the server will keep
		a list of the username hashes and public keys while the client will store the password cipher, the salt 
		for the passwords as well as the private and public keys associated to the username hash.*/
	    PublicKey publicKeyForStorage = keyPair.getPublic();
		
	    
		//This is where you would tack on the pin somewhere in the RSA key.
	    //Get the encoded bytes for the RSA public key in order to have the server store it for authentication and data validation.
	    byte[] encodedPublic = publicKeyForStorage.getEncoded();
		FileOutputStream keyfos2 = new FileOutputStream("C:/Users/Public/Documents/"+usernameHash+".txt");
		keyfos2.write(encodedPublic);
		keyfos2.close();
		
		return publicKeyForStorage;
	}
	
	
	
	public PrivateKey setupNewUserPrivateKey(String usernameHash) throws IOException
	{
		/*This sets the variables for the users RSA keys. These RSA keys are only used for the digital signature.
		These are the bytes that are going to be stored by the database for every computer, the server will keep
		a list of the username hashes and public keys while the client will store the password cipher, the salt 
		for the passwords as well as the private and public keys associated to the username hash.*/
	    PrivateKey privateKeyForStorage = keyPair.getPrivate();
		
		
		//Store the private key in a file named usernamehash_
	    byte[] encodedPrivate = privateKeyForStorage.getEncoded();
		FileOutputStream keyfos = new FileOutputStream("C:/Users/Public/Documents/"+usernameHash+"_.txt");
		keyfos.write(encodedPrivate);
		keyfos.close();
		
		return privateKeyForStorage;
	}
	
	
	
	//=======================================
	//
	// 		 EXCHANGING SHARED SECRET
	//
	//=======================================
	public void exchangeSecret(String theSecret, ObjectInputStream inFromServer, PrivateKey privateKeyForStorage) throws Exception
	{
		theGUI.appendString("[System]: waiting for server to input secret..."+"\n");

		String HMACfromserver = (String) inFromServer.readObject();
		String tempEncrypted = (String) inFromServer.readObject();

		String HMAC = calculateHMAC(tempEncrypted, theSecret);
		if(!(HMAC.equals(HMACfromserver)))
		{
			theGUI.appendString("[System]: The HMAC calculated on the secret does not match what was sent.\n");
			theGUI.appendString("[System]: The system can't garuntee that this connection is secure.\n");
		}
		else
		{
			//Decrypt
			String tempDecrypted = DecryptRSA(tempEncrypted, privateKeyForStorage);
			byte[] sharedBytes = tempDecrypted.getBytes();

			//Cleanup
			tempDecrypted = null;
			privateSymKey = new SecretKeySpec(sharedBytes, "AES"); //create privateSymKey object with byte[]
			sharedBytes = null;
			theGUI.appendString("[System]: You are now connected to the network\n");
			System.gc();
		}
	}
	
	
	
	
	//=======================================
	//
	// 			 RFC Compliant HMAC 
	//
	//=======================================
	public static String calculateHMAC(String data, String key)
			throws java.security.SignatureException
	{
		String result;
		
		try {

			// get an hmac_sha1 key from the raw key bytes
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);

			// get an hmac_sha1 Mac instance and initialize with the signing key
			Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
			mac.init(signingKey);

			// compute the hmac on input data bytes
			byte[] rawHmac = mac.doFinal(data.getBytes());
			
			// base64-encode the hmac
			result = new String(Base64.encodeBase64(rawHmac));

		} catch (Exception e) {
			throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
		}
	
		return result;
	}
	
	

	
	
	
	//=======================================
	//
	// 				RSA DECRYPT
	//
	//=======================================
	
	private String DecryptRSA(String cipherText, PrivateKey privateKey)  throws Exception
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		
		//decode Result and put it in a byte array
		byte[] decodedEncryptedBytes = Base64.decodeBase64(cipherText.getBytes());

		//Work Cipher magic
		String decryptedString = new String(cipher.doFinal(decodedEncryptedBytes));
		
		return decryptedString;
	}
	
	
	//==========================
	//==================
	//==========
	//OTHER
	
	
	protected SecretKeySpec GetToken(){
		return privateSymKey;
	}
	
	
	protected static boolean readyForPin(){
		return readyForPin;
	}
	
	
	protected static void setPin(String thePin){
		pin = thePin;
		pinSet = true;
	}
}



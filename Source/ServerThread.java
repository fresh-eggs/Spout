import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Random;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;


public class ServerThread implements Runnable
{
	//I/O variables 
	protected ObjectInputStream inFromClient;
	protected ObjectOutputStream outToClient;
	protected Socket threadSock;
	protected Thread listener;
	private Random rnd = new Random();
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	
	//List of threads
	Vector<ServerThread> serverThreadList = TCPServer.getThreadList();
	
	//Used to suspend all regular chat functions while there is a client connecting as to free up tunnels for RSA exchange.
	private boolean suspendAll;
	
	//RSA key exchange stuff
	private String sharedBitString;

	
	public ServerThread(Socket socket, String shared) throws IOException
	{
		sharedBitString = shared;//Take in the shared bits entered earlier.
		threadSock = socket;//assign socket created by server.
		suspendAll = true;//turn off all pipes to client
	}
	
	
	/*
	 * This is the start method. This method is responsible for starting execution of the thread,
	 * Once we start it, the run method begins. In here we also assign the i/o variables
	 */
	public void start()
	{
		try 
		{
			inFromClient = new ObjectInputStream(threadSock.getInputStream());
			outToClient = new ObjectOutputStream(threadSock.getOutputStream());
		}
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		
	    listener = new Thread(this);
		listener.start();
		serverThreadList.addElement(this);//add this element to the list of server threads.
	}
	

	/*

	 */
	public void run() 
	{


		try {

			//NEW USER
			//Gather up the username hash
			String usernameHash;
			usernameHash = (String) inFromClient.readObject();
			System.out.println(usernameHash);

			//In here we are checking our hash database to see if 
			//the client is new or returning.
			boolean isReturning = false;
			File dir = new File("C:/Users/Public/Documents/srv/");
			File[] directoryListing = dir.listFiles();
			String usernameHashFile = new String(usernameHash+".txt");

			//Try to find a hash that matches=
			if (directoryListing != null) 
			{
				for (File child : directoryListing) 
				{
					String filename = child.getName();
					if(usernameHashFile.equals(filename))
					{
						isReturning = true;
					}
				}
			} 



			if(isReturning)
			{
				System.out.println("we found a returing user");
				System.out.println("begin reuturning user process");
				//OLD USER
				Path path = Paths.get("C:\\Users\\Public\\Documents\\srv\\"+usernameHash+".txt");

				//Create public key from encoded bytes,
				byte[] encodedPublic = Files.readAllBytes(path);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
				PublicKey publicKeyForStorage = keyFactory.generatePublic(publicKeySpec);

				//AUTHENTICATION
				//Create the random mess used to sign.
				SecureRandom rnd = new SecureRandom();
				byte[] randomBytes = new byte[16];
				rnd.nextBytes(randomBytes);
				
				//the temp secret we will share with the client
				String HMACsecret = new String(Hex.encodeHex(randomBytes));
				
				//Encrypt and encode it then send it.
				String encryptedHMACsecret =  EncryptRSA(HMACsecret, publicKeyForStorage); 
				outToClient.writeObject(encryptedHMACsecret);

				sharedSecretSwapReturning(publicKeyForStorage, HMACsecret);
			}
			else
			{
				System.out.println("Start some new client junk");

				//Generate a temporary PIN to be used during the authentication of a new client.
				int PIN = 100000 + rnd.nextInt(900000);
				String PINstring = Integer.toString(PIN);
				System.out.println("This is the PIN for the new client:" +PIN);

				//Receive new user's HMAC for the public key they entended to send.
				String clientHMAC = (String) inFromClient.readObject();
				
				//Receive new user's public key 
				String encodedPublicKey = (String) inFromClient.readObject();

				//Calculate an HMAC on the encoded public key bytes to see if we have a match. 
				//If we do than we can be sure we received what the client intended to send.
				String HMAC = calculateHMAC(encodedPublicKey, PINstring);
				
				//Compare the one we calculated with the one the client sent.
				//if they are not the same, kick the client off and remove them from list.
				if(!HMAC.equals(clientHMAC))
				{
					try 
					{
						threadSock.close();
					}
					catch (IOException e) 
					{
						e.printStackTrace();
					}
					serverThreadList.removeElement(this);
					
					System.out.println("The HMAC we calculated did not match the one the client sent. Someone is being the NSA...");
				}
				else
				{
					//if they do match, continue on with the storage.
					System.out.println("The HMAC we calculated did match the one the client sent. MEOW");
					
					//Decode the public key bytes
					byte[] decodedPublicKey = Base64.decodeBase64(encodedPublicKey.getBytes());
					
					//Create public key from decoded bytes,
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
					PublicKey publicKeyForStorage = keyFactory.generatePublic(publicKeySpec);

					//Create a directory to store the user's public keys.
					File directory = new File("C:/Users/Public/Documents/srv/");
					directory.mkdir();
					
					//Store the bytes for the public key.
					//This public key is now associated to that username
					FileOutputStream keyfos2 = new FileOutputStream("C:/Users/Public/Documents/srv/"+usernameHash+".txt");
					keyfos2.write(decodedPublicKey);
					keyfos2.close();  

					//Send over the shared secret to the client that the network shares.
					sharedSecretSwapNewUser(publicKeyForStorage, PINstring);
				}

			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}


		
		//only thing we want run() to do is spam send to all.
		//When an I/O exception is caught, means client is no
		//longer connected so we close the socket and remove that
		//client from the global list.
		suspendAll = false;
		boolean clientConnected = true;
		System.out.println("Entering main thread loop.");
		while(clientConnected)
		{
			try 
			{
				sendToAll((String) inFromClient.readObject());
			} 
			catch (IOException e1) 
			{
				e1.printStackTrace();
				try 
				{
					threadSock.close();
				}
				catch (IOException e) 
				{
					e.printStackTrace();
				}
				clientConnected = false;
				serverThreadList.removeElement(this);
			} 
			catch (ClassNotFoundException e) {
				e.printStackTrace();
			} 
		}
	}
 
	
	/*
	 * This method sort of explains itself. It takes in the encrypted string it would recieve from its client, then 
	 * it goes down the array, sending this message to all clients currently active on the server. So long as suspendAll
	 * is not set. It is set whilst new clients are connecting.
	 */
	protected void sendToAll(String encryptedString)
	{
		if(!suspendAll)
		{
			synchronized(serverThreadList)//Locks up the serverthread list for the time being.
			{
				Enumeration<ServerThread> enumerator = serverThreadList.elements();
				while(enumerator.hasMoreElements())
				{
					ServerThread srvThread = (ServerThread)enumerator.nextElement();
					try
					{
						TCPServer.getGUI().getChatDisplay().append(encryptedString + "\n");
						srvThread.outToClient.writeObject(encryptedString);
					}
					catch (IOException e1) 
					{
						e1.printStackTrace();
					}
				}
			}	
		}
	}
	
	

	synchronized private void sharedSecretSwapNewUser(PublicKey value, String HMACsecret) throws IOException, 
	InterruptedException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, 
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException
	{
		String encryptedSharedBytes = null;
		try 
		{
			encryptedSharedBytes = EncryptRSA(sharedBitString, value);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		
		String HMAC = calculateHMAC(encryptedSharedBytes, HMACsecret);
		
		outToClient.writeObject(HMAC);
		outToClient.writeObject(encryptedSharedBytes);
		System.out.println("Sent Encrypted private secret to client");
	}
	
	
	
	synchronized private void sharedSecretSwapReturning(PublicKey pubKey, String HMACsecret) throws IOException, 
	InterruptedException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, 
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException
	{
		String encryptedSharedBytes = null;
		try 
		{
			encryptedSharedBytes = EncryptRSA(sharedBitString, pubKey);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		
		String HMAC = calculateHMAC(encryptedSharedBytes, HMACsecret);
		
		outToClient.writeObject(HMAC);
		outToClient.writeObject(encryptedSharedBytes);
		System.out.println("Sent Encrypted private secret to client");
	}
	
	
	
	private static String EncryptRSA(String plainText, PublicKey pubKey)  throws Exception
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);

		String encodedEncryptedString = new String(Base64.encodeBase64(cipher.doFinal(plainText.getBytes())));
		return encodedEncryptedString;
	}

						
	protected ObjectOutputStream getOutToClient() {
		return outToClient;
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

		} 
		catch (Exception e) 
		{
			throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
		}
	
		return result;
	}

}

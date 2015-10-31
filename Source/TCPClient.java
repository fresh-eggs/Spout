import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.swing.JOptionPane;
import javax.swing.text.BadLocationException;
import org.apache.commons.codec.binary.Base64;



public class TCPClient
{
	//========================
	//     IO variables
	//========================
	private static ObjectOutputStream outToServer;
	private static SecretKeySpec privateSymKey; 
	private static boolean isSrvSet = false;
	private static boolean suspendAll = false;
	private static String srvIP = null;
	private static SecureRandom rnd = new SecureRandom();
	private static boolean isNewClient = false;
	private static boolean isNewSet = false;


	//=========================
	//     Chat Variables
	//=========================
	private static String userName = null;
	private static boolean isUsernameSet = false;
	private static String password = null;
	private static boolean isPasswordSet = false;
	//meowmeowmeowmeowqmeowmeowmeowmeomwoemwomeowmeomwoemow

	//============================
	//    IP Check variables
	//============================
	private static Pattern VALID_IPV4_PATTERN = null;
	private static Pattern VALID_IPV6_PATTERN = null;
	private static final String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
	private static final String ipv6Pattern = "([0-9a-f]{1,4}:){7}([0-9a-f]){1,4}";

	//==========================
	//			OTHER
	//==========================
	private static byte[] iv = null;
	private static IvParameterSpec ivSpec;
	private static TheGUI theGUI; //instance of the client GUI
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	
	static {
		VALID_IPV4_PATTERN = Pattern.compile(ipv4Pattern, Pattern.CASE_INSENSITIVE);
		VALID_IPV6_PATTERN = Pattern.compile(ipv6Pattern, Pattern.CASE_INSENSITIVE);
	}

	
	
	
	
	
	
	
	public static void main(String argv[]) throws Exception
	{
		//GUI Stuff
		suspendAll = true;
		theGUI = new TheGUI();
		

		//============================
		//       Get ServerIP
		//============================
		Socket clientSocket = gatherServerIP();
		

		
		//===============================================
		//                  Setup I/O
		//===============================================
		outToServer = new ObjectOutputStream(clientSocket.getOutputStream()); //output to server
		ObjectInputStream inFromServer = new ObjectInputStream(clientSocket.getInputStream()); //buffered reader in from server
		theGUI.appendString("[System]: You are connected to: " + srvIP + "\n" + "\n");
		
		
		
		
		//===============================
		//        New Or Returning
		//===============================
		theGUI.appendString("[System]: Are you a new client on this server: ["+srvIP+"]\n");
		theGUI.appendString("[System]: y or n?\n");

		while(!isNewSet){
			Thread.sleep(500);
		}
		
		
		
		
		//=================================
		//        Gather Credentials
		//=================================
		
		if(isNewClient)//We must tell the GUI class that we are ready for the username.
		{
			theGUI.setReadyForUsername(true);
			isUsernameSet = false;
			theGUI.appendString("[System]: Please input your desired username..\n");
			while(isUsernameSet == false){
				Thread.sleep(1000);
			}
			
		}
		else
		{
			theGUI.appendString("[System]: Please enter your username..\n");
			while(isUsernameSet == false){
				Thread.sleep(1000);
			}	
		}

		
		
		
		//====================================
		//        Authentication Module
		//====================================
		//Creating the module that will handle authentication. 
		//We need this in order to have something that handles our user authentication.
		Auth authSequence = new Auth(theGUI, userName, isNewClient, outToServer, inFromServer);
		
		//Begin with the sequence that will set/fetch keys.
		authSequence.SetupKeys();
		
		//Key setup sequence is done, we need to gather our key.
		privateSymKey = authSequence.GetToken();
		
		
		

		
		//===============================================
		//               Create first IV
		//===============================================
		/*
		 * This is the first IV that we create to use in our CBC mode.
		 * After this one is used, the new IV comes from the random crap 
		 * at the beginning of every message sent over the server. It works 
		 * because everyone gets the same message so they all know the random 
		 * IV generated and sent with every message.
		 */
		suspendAll = false;
		byte[] randomBytes = new byte[16];
		rnd.nextBytes(randomBytes);
		ivSpec = new IvParameterSpec(randomBytes);
		
		while(randomBytes.length != 16)
		{
			rnd.nextBytes(randomBytes);
			ivSpec = new IvParameterSpec(randomBytes);
		}
		
	
		
		
		//==========================================
		//          Enter the Main loop.
		//==========================================
		/*
		 * Pretty self explanatory part here. We sit in this loop 99% of the time. Client reads the line,
		 * decrypts the contents then appends them to the GUI as they come in from the server.
		 * 
		 * At this point we have setup our AES tunnel with the shared secret we received from the server earlier.
		 */
		
		boolean closeSocket = false;
		while(!closeSocket)
		{
			try
			{
				boolean hmacMatch = false;
				
				//Receive both the HMAC and the encrypted/encoded mess sent from someone on the the network...
				String hmacReceived = (String) inFromServer.readObject();
				String cipherTxtFromServer = (String) inFromServer.readObject();


				if(cipherTxtFromServer != null)
				{
					//Calculate your own HMAC on the bytes you got.
					String hmacCalcualted = calculateHMAC(cipherTxtFromServer, privateSymKey.toString());

					//Compare our HMACs
					if(hmacCalcualted.equals(hmacReceived)){
						hmacMatch = true;
					}	
					else
						SetChatDisplay("The HMAC calculated did not match the one sent. Bytes received have been rejected.");

					
					
					if(hmacMatch)
					{
						//Call AESdecrypt on the message.
						String plainTxtFromServer = Decrypt(cipherTxtFromServer, privateSymKey);

						//Check the first byte header to determine contents.
						String header = plainTxtFromServer.substring(0,1);
						
						//Header == 0 denotes a simple message.
						if(header.equals("0"))
						{
							//Split the header off of the message
							String array[] = plainTxtFromServer.split("[0]", 2);
							String message = array[1];
							
							//Set the display
							SetChatDisplay(message);
						}
						
						//Set the iv to the first 16 bytes from the message.
						iv = (cipherTxtFromServer.substring(1, 17)).getBytes();
					}
				}
				
				//We set the IV with every received message, we use the random header that is attached to each message
				ivSpec = new IvParameterSpec(iv);	


			} catch (javax.crypto.BadPaddingException e) {
				JOptionPane.showMessageDialog(theGUI.getPanel(),"The shared secret you were given: "+" (Hash: "+privateSymKey.hashCode()+")  Does not match that of the other clients connected to "+srvIP+".\nPlease contact your server admi or try to connect again.","Bad Private Key", JOptionPane.ERROR_MESSAGE);
				e.printStackTrace();
			}

			if(closeSocket)//Kill client and exit main.
			{
				clientSocket.close();
				break;
			}
		}
	}

	
	
	
	//========== END OF MAIN ===========

	
	
	
	/*
	 * This method is used with the GUI. When the user presses enter, the GUI grabs the
	 * text from the userTextField, encrypts the contents and then fires it into the buffer
	 * reader on the server thread side.
	 */
	protected static void SendMessage(String userInput) throws InvalidKeyException, IllegalBlockSizeException,
	BadPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException,
	NoSuchAlgorithmException, NoSuchPaddingException, IOException, SignatureException, BadLocationException
	{
		String encryptedUserString;
		String symbol = "_";
		DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
		Calendar cal;
		cal = Calendar.getInstance();
		
		//Generate our random padding to be used as an IV by all clients receiving the message.
		int seed = rnd.nextInt(32 - 5 + 1) + 5; //make rand number between 5 - 32
		byte[] randomBytes = new byte[seed];
		rnd.nextBytes(randomBytes);
		String randomHeader = new String(randomBytes);
		
		//Check the random padding for "_" and replace with replacement. 
		//This character is used by us to denote where the random header ends.
		int temp = rnd.nextInt();
		String replacement = Integer.toString(temp);
		randomHeader = randomHeader.replace("_", replacement);
		
	
		//Encrypt and send out to socket. This takes random2, sticks it on the front of the string
		//Then it uses the current date\time and username followed by the message. This is where we use _ in 
		//order to break up the random crap at the start from the date and time.
		if(!suspendAll)
		{	
			//Encrypt the string we are to send.
			encryptedUserString = Encrypt("0"+randomHeader+symbol+"[" + dateFormat.format(cal.getTime())+" | " + userName+"]: "+userInput, privateSymKey);
			
			//Calculate HMAC and sign with users private key.
			String HMAC = calculateHMAC(encryptedUserString, privateSymKey.toString());
					
			//Write things out
			outToServer.writeObject(HMAC);
			outToServer.writeObject(encryptedUserString); 
		}
	}


	/*
	 * Uses some filters to be able to split our string into the important pieces (date/time, username, message) 
	 * in order to allow us to make each a different color. 
	 */
	private static void SetChatDisplay(String plainText) throws BadLocationException
	{
		String second = "";
		System.out.println(plainText);
		if(plainText != null)
		{
			try 
			{
				String[] strArray1 = plainText.split("_");//split off the random crap header used for IV

				second = strArray1[1];

				String[] strArray2 = second.split("]");//Split the string at the ] in order to make text and time different colors.
				String userNameAndInfo = strArray2[0];//place to throw second half of string.
				String text = strArray2[1];

				theGUI.appendInformation(userNameAndInfo+"]");
				theGUI.appendUserText(text + "\n");
				theGUI.getChatDisplay().setCaretPosition(theGUI.getChatDisplay().getDocument().getLength());

				plainText = "";
				text = "";
				second = "";
			} catch (ArrayIndexOutOfBoundsException e) {
				e.printStackTrace();
			}
		}
	}
	
	
	
	//=======================================
	//
	// 			     GET THE IP
	//
	//=======================================
	public static Socket gatherServerIP() throws BadLocationException, InterruptedException, UnknownHostException, IOException
	{
		theGUI.appendString("[System]: Please input the server address and press enter...\n");

		/*
		 * Just loop until a valid IP is entered in terms of string structure.
		 * Then we will look for a timeout exception.
		 */
		
		srvIP = null;
		Socket clientSocket = null; 
		while(isSrvSet == false)
		{	
			Thread.sleep(1000);
			
			if(srvIP != null)
			{
				theGUI.appendString("[System]: Attempting to connect to: "+"'"+srvIP+"'"+" please wait...\n");

				if(!isIpAddress(srvIP))
				{
					JOptionPane.showMessageDialog(theGUI.getPanel(), "The IP address: "+"'"+srvIP+"'"+" is not valid.\n"+"Please try again.","Invalid IP", JOptionPane.ERROR_MESSAGE);
					theGUI.appendString("[System]: Please input the server address and press enter...\n");
					srvIP = null;
				}

				if(srvIP != null && isIpAddress(srvIP))
				{
					isSrvSet = true;

					//Create client socket if we have a valid IP entered.
					try {
						clientSocket = new Socket(srvIP, 6874);
					} catch (ConnectException e1) {//catch the timeout exception and restart the process.
						JOptionPane.showMessageDialog(theGUI.getPanel(), "Connection timed out when attempting to connect to: "+"'"+srvIP+"'"+"\n"+"Please try again.","Timed Out", JOptionPane.ERROR_MESSAGE);
						isSrvSet = false;
						srvIP = null;
						e1.printStackTrace();
					}
				}
			}
		}
		
		return clientSocket;
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
	// 		   AES ENCRYPT/DECRYPT
	//
	//=======================================
	
	private static String Encrypt(String userInput, SecretKeySpec privateSymKey)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, InvalidParameterSpecException,
			NoSuchAlgorithmException, NoSuchPaddingException
	{
		//Initiate cipher class
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.ENCRYPT_MODE, privateSymKey, ivSpec);//where we use the IV and the shared secret.

		//Encode and encrypt
		String encodedEncryptedString = new String(Base64.encodeBase64(c.doFinal(userInput.getBytes())));
		return encodedEncryptedString;
	}


	
	private static String Decrypt(String encryptedUserInput, SecretKeySpec privateSymKey)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException,
			NoSuchAlgorithmException, NoSuchPaddingException
    {
		//Initiate Cipher
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.DECRYPT_MODE, privateSymKey, ivSpec);

		//decode Result and put it in a byte array
		byte[] decodedEncryptedBytes = Base64.decodeBase64(encryptedUserInput.getBytes());

		//Work Cipher magic
		String decryptedString = new String(c.doFinal(decodedEncryptedBytes));
		return decryptedString;
	}


	
	protected static void setUserName(String userName) throws BadLocationException 
	{
		if(userName.length() > 16)
		{
			JOptionPane.showMessageDialog(theGUI.getPanel(), "Usernames must be no greater than 16 characters.\n"+"Please try again.","Invalid Username", JOptionPane.ERROR_MESSAGE);
			theGUI.appendString("[System]: Please input your desired username..\n");
		}
		else
		{
			TCPClient.userName = userName;
			System.out.println(userName);
			isUsernameSet = true;
		}
		
		srvIP = null;
	}
	
	
	
	
	protected static void setPassword(String newPassword) throws BadLocationException 
	{
		if(newPassword.length() > 16)
		{
			JOptionPane.showMessageDialog(theGUI.getPanel(), "Password must be at least 10 characters long.\n"+"Please try again.","Invalid password", JOptionPane.ERROR_MESSAGE);
			theGUI.appendString("[System]: Please input your password..\n");
		}
		else
		{
			password = newPassword;
			isPasswordSet = true;
		}
	}
	
	
	
	
	protected static boolean isIpAddress(String ipAddress)
	{
		java.util.regex.Matcher m1 = VALID_IPV4_PATTERN.matcher(ipAddress);
		if (m1.matches()) {
			return true;
		}
		java.util.regex.Matcher m2 = VALID_IPV6_PATTERN.matcher(ipAddress);
		return m2.matches();
	}

	
	

	protected static void SetSrvIP(String getUserInput) {
		srvIP = getUserInput;
	}


	protected static boolean getIsSrvSet() {
		return isSrvSet;
	}


	protected static void setIsSrvSet(boolean value) {
		isSrvSet = value;
	}

	protected static void setSuspendAll(boolean setter) {
		suspendAll = setter;
	}

	protected static boolean isSuspendAll()
	{
		return suspendAll;
	}


	protected static boolean isUsernameSet() {
		return isUsernameSet;
	}

	protected static void setIsClientNew(boolean value)
	{
		isNewClient = value;
	}
	
	protected static void setIsNewSet(boolean value)
	{
		isNewSet = value;
	}

	protected static void setUsernameSet(boolean value) 
	{
		isUsernameSet = value;
	}

	protected static String getUserName() {
		return userName;
	}
}

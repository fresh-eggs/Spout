import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JOptionPane;

public class TCPServer 
{
	private static ArrayList<ServerThread> threadList = new ArrayList<ServerThread>();//array of server threads for concurrency
	private String sharedString;//placeholder for the secret bits sent to each instance of server thread.
	private static boolean bitsEntered = false;//to make loop wait for bits entered.
	final static TheGUIServer theGui = new TheGUIServer();//the servers GUI
	private static TheGUISrvThread theGuiSrvThread;//little msg box asking for secret.

	public TCPServer(Socket socket)	{
	}

	

	public static void main(String[] args) throws IOException, InvalidKeyException,
		IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException, NoSuchProviderException
	{
		final ServerSocket serverSocket = new ServerSocket(6874);
	
		theGui.setChatDisplay("Waiting for clients......");
		
		
		boolean acceptMore = true;
		while(acceptMore)
		{
			Thread.sleep(500);
			
			Socket client = serverSocket.accept();//wait until tcp handshake happens on port 6874
			theGui.setChatDisplay("Client Connected: " + client.getInetAddress() + "\n");
			
			theGuiSrvThread = new TheGUISrvThread();//create msg box to get shared bits
			String sharedString = theGuiSrvThread.getUserInput();//try to get them
			
			//If we dont get em, loop until server admin puts it in.
			while(sharedString == null)
			{
				Thread.sleep(2000);
				sharedString = theGuiSrvThread.getUserInput();
				System.out.println(sharedString);
				
				if(sharedString != null && sharedString.length() != 16)
				{
					sharedString = null;
					theGuiSrvThread.setUserInput(null);
					JOptionPane.showMessageDialog(theGui.getPanel(), "String entered is not 16Bytes long."+"\n"+"Please enter a valid private key.","Error", JOptionPane.ERROR_MESSAGE);
				}
			}
			theGuiSrvThread.setUserInput("1");//to ack that we have them
			
			ServerThread srvThread = new ServerThread(client, sharedString, theGuiSrvThread);//create new thread of server for every client.
			srvThread.start();
		}
	}
	
	
	protected static void createGUI()
	{
		theGuiSrvThread = new TheGUISrvThread();
	}

	protected static boolean areBitsEntered()
	{
		return bitsEntered;
	}
	
	protected void setBitsEntered(boolean bits)
	{
		bitsEntered = bits;
	}
	
	protected void setSharedString(String temp)
	{
		sharedString = temp;
	}
	
	protected String getSharedString()
	{
		return sharedString;
	}
	
	protected static TheGUIServer getGUI(){
		return theGui;
	}
}
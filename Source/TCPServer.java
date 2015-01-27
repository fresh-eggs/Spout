
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Vector;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TCPServer 
{
	private static boolean bitsEntered = false;//to make loop wait for bits entered.
	final static TheGUIServer theGui = new TheGUIServer();//the servers GUI
	private static SecureRandom secureRnd = new SecureRandom();
	
	//List of all server threads active.
	protected static Vector<ServerThread> serverThreadList = new Vector<ServerThread>();

	

	public static void main(String[] args) throws IOException, InvalidKeyException,
		IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException, NoSuchProviderException
	{
		final ServerSocket serverSocket = new ServerSocket(6874);
		final int AES_KEY_SIZE = 16;
		
		
		byte[] temp = new byte[AES_KEY_SIZE];
		secureRnd.nextBytes(temp);
		String sharedString = new String(temp);
		theGui.setChatDisplay(sharedString + "\n");
		theGui.setChatDisplay(sharedString.length() + "\n");
		theGui.setChatDisplay("Waiting for clients......" + "\n");
		
		
		//In order to start our nested while, accept more is set to false but has the check
		//before every pass of the inner acceptMore in order to see if the size is ok for 
		//our serverThread list.
		boolean acceptMore = false;	
		while(!acceptMore)
		{
			if(serverThreadList.size() < 15)
				acceptMore = true;
			
			while(acceptMore)
			{
				Socket client = serverSocket.accept();//wait until tcp handshake happens on port 6874
				theGui.setChatDisplay("Client Connected: " + client.getInetAddress() + "\n");
				
				if(serverThreadList.size() >= 15)
				{
					theGui.setChatDisplay("Client: "+client.getInetAddress()+
							" was rejected. Too many clients already connected." + "\n");

					acceptMore = false;
					client.close();
				}
				else
				{	
					ServerThread srvThread = new ServerThread(client, sharedString);//create new thread of server for every client.
					srvThread.start();
				}
			}
		}
	}
	
	protected static Vector<ServerThread> getThreadList()
	{
		return serverThreadList;
	}
	
	protected static boolean areBitsEntered()
	{
		return bitsEntered;
	}
	
	protected void setBitsEntered(boolean bits)
	{
		bitsEntered = bits;
	}
	
	protected static TheGUIServer getGUI(){
		return theGui;
	}
}





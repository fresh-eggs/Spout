import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JFrame;

public class TheGUISrvThread extends Frame implements ActionListener
{
	private Label theLabel;
	private TextField userTextField;
	public static JButton submitButton;
	private static JFrame f;
	private String theBits = null;
	
	Action accept = new AbstractAction("accept")
	{
		public void actionPerformed(ActionEvent arg0) 
		{
			theBits = userTextField.getText();//get the bits from the little box and store them temporarily 
			
			if(theBits.length() == 16)
				f.dispose();
		}
	};
	
	
	@SuppressWarnings("deprecation")
	public TheGUISrvThread()
	{
		//General Settings
		setLayout(new BorderLayout());
		
		f = new JFrame("Shout - v0.9");
		f.setVisible(true);
		f.setPreferredSize(new Dimension(350, 100));
	
		f.getContentPane().add(theLabel = new Label("Enter Random Bits: "), BorderLayout.NORTH);
		f.getContentPane().add(userTextField = new TextField(), BorderLayout.CENTER);
		f.getContentPane().add(submitButton = new JButton(accept), BorderLayout.LINE_START);
		f.getRootPane().setDefaultButton(submitButton);
		submitButton.setVisible(false);
		f.pack();
		userTextField.requestFocus();
		setSize(600, 400);
		setTitle("");

	}

	
	protected String getUserInput(){
		return theBits;
	}
	
	
	protected void setUserInput(String bits){
		theBits = bits;
	}
	
	
	public void actionPerformed(ActionEvent arg0) {
		// TODO Auto-generated method stub
		
	}
}







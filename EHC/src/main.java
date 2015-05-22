import java.awt.EventQueue;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JComboBox;
import javax.swing.JSpinner;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import java.awt.Font;

import javax.swing.JCheckBox;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.JPopupMenu;

import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;





public class main {
	
	public String stringHashFile = "";
	public String stringOutputFile = "";
	public String stringWordlist1 = "";
	public String stringWordlist2 = "";
	public String stringWordlist3 = "";
	public String stringRule1 = "";
	public String stringRule2 = "";
	public String stringRule3 = "";
	public String stringRule4 = "";
	public String stringSeparator = "";
	public String stringmode = "";
	public String stringOutputFormat = "";
	public String stringpassmax = "";
	public String stringpassmin = "";
	public String stringCommand = "";
	public String stringHashType = "";
	public String stringIncrementMode	= "";
	public boolean icm = false;
	public String stringMask = "";
	public String stringcli = "";

	private JFrame frmEhcV;
	private JTextField hashFile;
	private JTextField separatorField;
	private JTextField wordlist1;
	private JTextField lengthmin;
	private JTextField lengthmax;
	private JTextField wordlist2;
	private JTextField wordlist3;
	private JTextField rule1;
	private JTextField rule2;
	private JTextField rule3;
	private JTextField rule4;
	private JTextField outputhFile;
	private JTextField commandOut;
	private JTextField mask;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					main window = new main();
					window.frmEhcV.setVisible(true);
					UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public main() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (ClassNotFoundException | InstantiationException
				| IllegalAccessException | UnsupportedLookAndFeelException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		frmEhcV = new JFrame();
		frmEhcV.setTitle("EHC V0.1 (c) Tim 2015");
		frmEhcV.setBounds(100, 100, 800, 700);
		frmEhcV.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmEhcV.getContentPane().setLayout(null);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setBounds(10, 10, 764, 641);
		frmEhcV.getContentPane().add(tabbedPane);
		
		JPanel hashcat = new JPanel();
		tabbedPane.addTab("HashCat", null, hashcat, null);
		hashcat.setLayout(null);
		
		JLabel lblLength = new JLabel("Length:");
		lblLength.setBounds(454, 108, 37, 22);
		hashcat.add(lblLength);
		
		JLabel lblHashFile = new JLabel("Hash File:");
		lblHashFile.setBounds(10, 11, 47, 22);
		hashcat.add(lblHashFile);
		
		hashFile = new JTextField();
		hashFile.setBounds(67, 11, 478, 22);
		hashcat.add(hashFile);
		hashFile.setColumns(10);
		
		JButton InputFileBrowse = new JButton("Browse");
		InputFileBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          hashFile.setText((selectedFilePath.getPath()));
		        }
			}
		});
		InputFileBrowse.setBounds(555, 11, 71, 23);
		hashcat.add(InputFileBrowse);
		
		JLabel lblSeperator = new JLabel("Separator:");
		lblSeperator.setBounds(5, 44, 52, 22);
		hashcat.add(lblSeperator);
		
		separatorField = new JTextField();
		separatorField.setBounds(67, 44, 68, 22);
		hashcat.add(separatorField);
		separatorField.setColumns(10);
		
		JLabel lblMode = new JLabel("Mode:");
		lblMode.setBounds(145, 44, 47, 22);
		hashcat.add(lblMode);
		
		JComboBox mode = new JComboBox();
		mode.setModel(new DefaultComboBoxModel(new String[] {"Dictionary", "Masked"}));
		mode.setBounds(177, 45, 138, 20);
		hashcat.add(mode);
		
		JLabel lblHashType = new JLabel("Hash Type:");
		lblHashType.setBounds(325, 44, 60, 22);
		hashcat.add(lblHashType);
		
		JComboBox hashType = new JComboBox();
		hashType.setMaximumRowCount(40);
		hashType.setModel(new DefaultComboBoxModel(new String[] {"MD5", "md5($pass.$salt)", "md5($salt.$pass)", "md5(unicode($pass).$salt)", "md5($salt.unicode($pass))", "HMAC-MD5 (key = $pass)", "HMAC-MD5 (key = $salt)", "SHA1", "sha1($pass.$salt)", "sha1($salt.$pass)", "sha1(unicode($pass).$salt)", "sha1($salt.unicode($pass))", "HMAC-SHA1 (key = $pass)", "HMAC-SHA1 (key = $salt)", "MySQL", "MySQL4.1/MySQL5", "phpass, MD5(WordPress), MD5(phpBB3)", "md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5", "SHA-1(Django)", "MD4", "NTLM", "Domain Cached Credentials, mscash", "SHA256", "sha256($pass.$salt)", "sha256($salt.$pass)", "sha256(unicode($pass).$salt)", "sha256($salt.unicode($pass))", "HMAC-SHA256 (key = $pass)", "HMAC-SHA256 (key = $salt)", "md5apr1, MD5(APR), Apache MD5", "SHA512", "sha512($pass.$salt)", "sha512($salt.$pass)", "sha512(unicode($pass).$salt)", "sha512($salt.unicode($pass))", "HMAC-SHA512 (key = $pass)", "HMAC-SHA512 (key = $salt)", "SHA-512(Unix)", "Cisco-PIX MD5", "WPA/WPA2", "Double MD5", "bcrypt, Blowfish(OpenBSD)", "MD5(Sun)", "md5(md5(md5($pass)))", "md5(md5($salt).$pass)", "md5($salt.md5($pass))", "md5($pass.md5($salt))", "md5($salt.$pass.$salt)", "md5(md5($pass).md5($salt))", "md5($salt.md5($salt.$pass))", "md5($salt.md5($pass.$salt))", "md5($username.0.$pass)", "md5(strtoupper(md5($pass)))", "md5(sha1($pass))", "sha1(sha1($pass))", "sha1(sha1(sha1($pass)))", "sha1(md5($pass))", "MD5(Chap)", "SHA-3(Keccak)", "Half MD5", "Password Safe SHA-256", "IKE-PSK MD5", "IKE-PSK SHA1", "NetNTLMv1-VANILLA / NetNTLMv1-ESS", "NetNTLMv2", "Cisco-IOS SHA256", "Samsung Android Password/PIN", "AIX {smd5}", "AIX {ssha256}", "AIX {ssha512}", "AIX {ssha1}", "GOST, GOST R 34.11-94", "Fortigate (FortiOS)", "OS X v10.8", "GRUB 2", "IPMI2 RAKP HMAC-SHA1", "sha256crypt, SHA256(Unix)", "Plaintext", "Joomla", "osCommerce, xt:Commerce", "nsldap, SHA-1(Base64), Netscape LDAP SHA", "nsldaps, SSHA-1(Base64), Netscape LDAP SSHA", "Oracle 11g", "SMF > v1.1", "OS X v10.4, v10.5, v10.6", "EPi", "MSSQL(2000)", "MSSQL(2005)", "EPiServer 6.x < v4", "EPiServer 6.x > v4", "SSHA-512(Base64), LDAP {SSHA512}", "OS X v10.7", "MSSQL(2012)", "vBulletin < v3.8.5", "vBulletin > v3.8.5", "IPB2+, MyBB1.2+", "WebEdition CMS", "Redmine Project Management Web App"}));
		hashType.setBounds(382, 45, 347, 20);
		hashcat.add(hashType);
		
		JSeparator separator = new JSeparator();
		separator.setBounds(106, 96, 356, 12);
		hashcat.add(separator);
		
		JLabel lblWordlist = new JLabel("Wordlist 1:");
		lblWordlist.setBounds(5, 114, 52, 22);
		hashcat.add(lblWordlist);
		
		wordlist1 = new JTextField();
		wordlist1.setBounds(67, 114, 248, 22);
		hashcat.add(wordlist1);
		wordlist1.setColumns(10);
		
		JButton wordlist1Browse = new JButton("Browse");
		wordlist1Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          wordlist1.setText((selectedFilePath.getPath()));
		        }
				
			}
		});
		wordlist1Browse.setBounds(325, 114, 89, 23);
		hashcat.add(wordlist1Browse);
		
		JSeparator separator_2 = new JSeparator();
		separator_2.setBounds(424, 168, 38, 12);
		hashcat.add(separator_2);
		
		lengthmin = new JTextField();
		lengthmin.setBounds(521, 108, 47, 23);
		hashcat.add(lengthmin);
		lengthmin.setColumns(10);
		
		JLabel label = new JLabel("-");
		label.setFont(new Font("Tahoma", Font.PLAIN, 34));
		label.setBounds(580, 113, 17, 12);
		hashcat.add(label);
		
		lengthmax = new JTextField();
		lengthmax.setColumns(10);
		lengthmax.setBounds(607, 108, 47, 23);
		hashcat.add(lengthmax);
		
		JCheckBox incrementMode = new JCheckBox("Increment mode");
		incrementMode.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent arg0) {
				
				icm = true;
				
			}
		});
		incrementMode.setBounds(454, 137, 129, 20);
		hashcat.add(incrementMode);
		
		JLabel lblWordlist_1 = new JLabel("Wordlist 2:");
		lblWordlist_1.setBounds(5, 147, 52, 22);
		hashcat.add(lblWordlist_1);
		
		wordlist2 = new JTextField();
		wordlist2.setColumns(10);
		wordlist2.setBounds(67, 147, 248, 22);
		hashcat.add(wordlist2);
		
		JButton wordlist2Browse = new JButton("Browse");
		wordlist2Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          wordlist2.setText((selectedFilePath.getPath()));
		        }
			}
		});
		wordlist2Browse.setBounds(325, 147, 89, 23);
		hashcat.add(wordlist2Browse);
		
		JLabel lblWordlist_2 = new JLabel("Wordlist 3:");
		lblWordlist_2.setBounds(5, 179, 52, 22);
		hashcat.add(lblWordlist_2);
		
		wordlist3 = new JTextField();
		wordlist3.setColumns(10);
		wordlist3.setBounds(67, 179, 248, 22);
		hashcat.add(wordlist3);
		
		JButton wordlist3Browse = new JButton("Browse");
		wordlist3Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          wordlist3.setText((selectedFilePath.getPath()));
		        }
			}
		});
		wordlist3Browse.setBounds(325, 179, 89, 23);
		hashcat.add(wordlist3Browse);
		
		JLabel lblWordlists = new JLabel("Wordlists");
		lblWordlists.setBounds(59, 86, 47, 22);
		hashcat.add(lblWordlists);
		
		JSeparator separator_4 = new JSeparator();
		separator_4.setBounds(0, 96, 57, 12);
		hashcat.add(separator_4);
		
		JLabel lblLength_1 = new JLabel("Length");
		lblLength_1.setBounds(467, 86, 37, 22);
		hashcat.add(lblLength_1);
		
		JSeparator separator_5 = new JSeparator();
		separator_5.setBounds(502, 96, 257, 12);
		hashcat.add(separator_5);
		
		JSeparator separator_6 = new JSeparator();
		separator_6.setBounds(88, 223, 335, 12);
		hashcat.add(separator_6);
		
		JLabel lblRules = new JLabel("Rules");
		lblRules.setBounds(59, 213, 47, 22);
		hashcat.add(lblRules);
		
		JSeparator separator_7 = new JSeparator();
		separator_7.setBounds(0, 223, 57, 12);
		hashcat.add(separator_7);
		
		JLabel lblRule = new JLabel("Rule 1:");
		lblRule.setBounds(5, 240, 52, 22);
		hashcat.add(lblRule);
		
		rule1 = new JTextField();
		rule1.setBounds(67, 240, 248, 22);
		hashcat.add(rule1);
		rule1.setColumns(10);
		
		JButton rule1Browse = new JButton("Browse");
		rule1Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          rule1.setText((selectedFilePath.getPath()));
		        }
			}
		});
		rule1Browse.setBounds(325, 240, 89, 23);
		hashcat.add(rule1Browse);
		
		JLabel lblRule_1 = new JLabel("Rule 2:");
		lblRule_1.setBounds(5, 271, 52, 22);
		hashcat.add(lblRule_1);
		
		rule2 = new JTextField();
		rule2.setColumns(10);
		rule2.setBounds(67, 271, 248, 22);
		hashcat.add(rule2);
		
		JButton rule2Browse = new JButton("Browse");
		rule2Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          rule2.setText((selectedFilePath.getPath()));
		        }
			}
		});
		rule2Browse.setBounds(325, 271, 89, 23);
		hashcat.add(rule2Browse);
		
		JLabel lblRule_2 = new JLabel("Rule 3:");
		lblRule_2.setBounds(5, 304, 52, 22);
		hashcat.add(lblRule_2);
		
		rule3 = new JTextField();
		rule3.setColumns(10);
		rule3.setBounds(67, 304, 248, 22);
		hashcat.add(rule3);
		
		JButton rule3Browse = new JButton("Browse");
		rule3Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          rule3.setText((selectedFilePath.getPath()));
		        }
			}
		});
		rule3Browse.setBounds(325, 304, 89, 23);
		hashcat.add(rule3Browse);
		
		JLabel lblRule_3 = new JLabel("Rule 4:");
		lblRule_3.setBounds(5, 337, 52, 22);
		hashcat.add(lblRule_3);
		
		rule4 = new JTextField();
		rule4.setColumns(10);
		rule4.setBounds(67, 337, 248, 22);
		hashcat.add(rule4);
		
		JButton rule4Browse = new JButton("Browse");
		rule4Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          rule4.setText((selectedFilePath.getPath()));
		        }
			}
		});
		rule4Browse.setBounds(325, 337, 89, 23);
		hashcat.add(rule4Browse);
		
		JSeparator separator_10 = new JSeparator();
		separator_10.setBounds(424, 271, 335, 12);
		hashcat.add(separator_10);
		
		JLabel lblMask = new JLabel("Mask");
		lblMask.setBounds(464, 158, 37, 22);
		hashcat.add(lblMask);
		
		JSeparator separator_11 = new JSeparator();
		separator_11.setBounds(488, 168, 271, 12);
		hashcat.add(separator_11);
		
		mask = new JTextField();
		mask.setBounds(434, 240, 271, 22);
		hashcat.add(mask);
		mask.setColumns(10);
		
		JLabel lblEnterACustom = new JLabel("<html>Enter a custom mask here. If no max <br> length is specified above, this mask's<br>lentgh will be adapted. You may also<br> choose a .hcmask file by browsing.</html>");
		lblEnterACustom.setBounds(434, 179, 200, 56);
		hashcat.add(lblEnterACustom);
		
		JButton btnCheatSheet = new JButton("Cheat Sheet");
		btnCheatSheet.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				JOptionPane.showMessageDialog(null, "<html>?l = abcdefghijklmnopqrstuvwxyz<br>?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ<br>?d = 0123456789<br>?s = !#$%&'()*+,-./:;<=>?@[]^_`{|}~<br>?a = ?l?u?d?</html>");
				
			}
		});
		btnCheatSheet.setBounds(644, 179, 105, 23);
		hashcat.add(btnCheatSheet);
				
		JSeparator separator_3 = new JSeparator();
		separator_3.setBounds(0, 379, 421, 12);
		hashcat.add(separator_3);
		
		JSeparator separator_1 = new JSeparator();
		separator_1.setOrientation(SwingConstants.VERTICAL);
		separator_1.setBounds(423, 96, 10, 284);
		hashcat.add(separator_1);
		
		JLabel lblOutputFile = new JLabel("Output File:");
		lblOutputFile.setBounds(5, 402, 60, 22);
		hashcat.add(lblOutputFile);
		
		outputhFile = new JTextField();
		outputhFile.setBounds(67, 402, 460, 22);
		hashcat.add(outputhFile);
		outputhFile.setColumns(10);
		
		JButton outputFileBrowse = new JButton("Browse");
		outputFileBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          outputhFile.setText((selectedFilePath.getPath()));
		        }
			}
		});
		outputFileBrowse.setBounds(537, 402, 89, 23);
		hashcat.add(outputFileBrowse);
		
		JLabel lblOutputFormat = new JLabel("Output Format:");
		lblOutputFormat.setBounds(434, 284, 75, 22);
		hashcat.add(lblOutputFormat);
		
		JSeparator separator_8 = new JSeparator();
		separator_8.setBounds(0, 455, 47, 12);
		hashcat.add(separator_8);
		
		JLabel lblCommand = new JLabel("Command:");
		lblCommand.setBounds(54, 445, 52, 22);
		hashcat.add(lblCommand);
		
		JSeparator separator_9 = new JSeparator();
		separator_9.setBounds(115, 455, 644, 12);
		hashcat.add(separator_9);
						
		JButton btna = new JButton("8a");
		btna.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {				
				mask.setText("?a?a?a?a?a?a?a?a");				
			}
		});
		btna.setBounds(620, 213, 47, 23);
		hashcat.add(btna);
		
		JButton btn45 = new JButton("8l");
		btn45.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				mask.setText("?l?l?l?l?l?l?l?l");
			}
		});
		btn45.setBounds(677, 212, 47, 23);
		hashcat.add(btn45);
		
		JButton button = new JButton("...");
		button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          mask.setText((selectedFilePath.getPath()));
		        }
			}
		});
		button.setBounds(715, 240, 34, 23);
		hashcat.add(button);
		
		JComboBox cli = new JComboBox();
		cli.setModel(new DefaultComboBoxModel(new String[] {"cli64", "cli32"}));
		cli.setBounds(674, 12, 75, 20);
		hashcat.add(cli);
		
		commandOut = new JTextField();
		commandOut.setFont(new Font("Tahoma", Font.PLAIN, 11));
		commandOut.setBounds(10, 504, 739, 33);
		hashcat.add(commandOut);
		commandOut.setColumns(10);
		
		JButton CopyToClipboard = new JButton("Copy To Clipboard");
		CopyToClipboard.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				
				
				
				
				
			}
		});
		CopyToClipboard.setBounds(10, 554, 161, 23);
		hashcat.add(CopyToClipboard);
		
		JCheckBox chckbxNoIncrementMode = new JCheckBox("no Increment mode");
		chckbxNoIncrementMode.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				
				icm = false;
				
			}
		});
		chckbxNoIncrementMode.setBounds(580, 137, 129, 20);
		hashcat.add(chckbxNoIncrementMode);
		
		JPanel oclhashcat = new JPanel();
		tabbedPane.addTab("oclHashCat", null, oclhashcat, null);
		oclhashcat.setLayout(null);
		
		JComboBox outputFormat = new JComboBox();
		outputFormat.setMaximumRowCount(12);
		outputFormat.setModel(new DefaultComboBoxModel(new String[] {"plain", "hash[:salt]", "hash[:salt]:plain", "hex_plain", "hash[:salt]:hex_plain", "plain:hex_plain", "hash[:salt]:plain:hex_plain", "crackpos", "hash[:salt]:crackpos", "plain:crackpos", "hash[:salt]:plain:crackpos", "hex_plain:crackpos", "hash[:salt]:hex_plain:crackpos", "plain:hex_plain:crackpos", "hash[:salt]:plain:hex_plain:crackpos"}));
		outputFormat.setBounds(521, 286, 188, 20);
		hashcat.add(outputFormat);
		
		JButton engineer = new JButton("Reverse Engineer");
		engineer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				
				String hashcode = "";
				String attackmode = "";
				String client = "";
				
				stringHashFile = hashFile.getText();
				stringOutputFile = outputhFile.getText();
				stringWordlist1 = wordlist1.getText();
				stringWordlist2 = wordlist2.getText();
				stringWordlist3 = wordlist3.getText();
				stringRule1 = rule1.getText();
				stringRule2 = rule2.getText();
				stringRule3 = rule3.getText();
				stringRule4 = rule4.getText();
				stringSeparator = separatorField.getText();
				stringmode = mode.getSelectedItem().toString();
				stringOutputFormat = outputFormat.getSelectedItem().toString();
				stringHashType = hashType.getSelectedItem().toString();
				stringpassmax = lengthmax.getText();
				stringpassmin = lengthmin.getText();
				stringcli = cli.getSelectedItem().toString();
				stringOutputFile = outputhFile.getText();
				stringMask = mask.getText();
				
				//Sets attack mode
				if(stringmode == "Dictionary"){
					attackmode = "0";
				}
				
				else if(stringmode == "Masked"){
					attackmode = "3";
				}
				
				
				
				
				//Sets client type
				if(stringcli == "cli64"){
					client = "cli64	";
				}
				
				else if(stringcli == "cli32"){
					client = "cli32";
				}
				
				
				
				
				//sets increment flag
				if(icm = true){
					stringIncrementMode = "--increment";
				}
				
				
				
				
				//sets hash type
				if(stringHashType == "MD5"){
					hashcode = "0";
				}
				
				else if (stringHashType == "md5($pass.$salt)"){
					hashcode = "10";
				}
				
				else if (stringHashType == "md5($salt.$pass)"){
					hashcode = "20";
				}
				
				else if (stringHashType == "md5(unicode($pass).$salt)"){
					hashcode = "30";
				}
				
				else if (stringHashType == "md5($salt.unicode($pass))"){
					hashcode = "40";
				}
				
				else if (stringHashType == "HMAC-MD5 (key = $pass)"){
					hashcode = "50";
				}
				
				else if (stringHashType == "HMAC-MD5 (key = $salt)"){
					hashcode = "60";
				}
				
				else if (stringHashType == "SHA1"){
					hashcode = "100";
				}
				
				else if (stringHashType == "sha1($pass.$salt)"){
					hashcode = "110";
				}
				
				else if (stringHashType == "sha1($salt.$pass)"){
					hashcode = "120";
				}
				
				else if (stringHashType == "sha1(unicode($pass).$salt)"){
					hashcode = "130";
				}
				
				else if (stringHashType == "sha1($salt.unicode($pass))"){
					hashcode = "140";
				}
				
				else if (stringHashType == "HMAC-SHA1 (key = $pass)"){
					hashcode = "150";
				}
				
				else if (stringHashType == "HMAC-SHA1 (key = $salt)"){
					hashcode = "160";
				}
				
				else if (stringHashType == "MySQL"){
					hashcode = "200";
				}
				
				else if (stringHashType == "MySQL4.1/MySQL5"){
					hashcode = "300";
				}
				
				else if (stringHashType == "phpass, MD5(WordPress), MD5(phpBB3)"){
					hashcode = "400";
				}
				
				else if (stringHashType == "md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5"){
					hashcode = "500";
				}
				
				else if (stringHashType == "SHA-1(Django)"){
					hashcode = "800";
				}
				
				else if (stringHashType == "MD4"){
					hashcode = "900";
				}
				
				else if (stringHashType == "NTLM"){
					hashcode = "1000";
				}
				
				else if (stringHashType == "Domain Cached Credentials, mscash"){
					hashcode = "1100";
				}
				
				else if (stringHashType == "SHA256"){
					hashcode = "1400";
				}
				
				else if (stringHashType == "sha256($pass.$salt)"){
					hashcode = "1410";
				}
				
				else if (stringHashType == "sha256($salt.$pass)"){
					hashcode = "1420";
				}
				
				else if (stringHashType == "sha256(unicode($pass).$salt)"){
					hashcode = "1430";
				}
				
				else if (stringHashType == "sha256($salt.unicode($pass))"){
					hashcode = "1440";
				}
				
				else if (stringHashType == "HMAC-SHA256 (key = $pass)"){
					hashcode = "1450";
				}
				
				else if (stringHashType == "HMAC-SHA256 (key = $salt)"){
					hashcode = "1460";
				}
				
				else if (stringHashType == "md5apr1, MD5(APR), Apache MD5"){
					hashcode = "1600";
				}
				
				else if (stringHashType == "SHA512"){
					hashcode = "1700";
				}
				
				else if (stringHashType == "sha512($pass.$salt)"){
					hashcode = "1710";
				}
				
				else if (stringHashType == "sha512($salt.$pass)"){
					hashcode = "1720";
				}
				
				else if (stringHashType == "sha512(unicode($pass).$salt)"){
					hashcode = "1730";
				}
				
				else if (stringHashType == "sha512($salt.unicode($pass))"){
					hashcode = "1740";
				}
				
				else if (stringHashType == "HMAC-SHA512 (key = $pass)"){
					hashcode = "1750";
				}
				
				else if (stringHashType == "HMAC-SHA512 (key = $salt)"){
					hashcode = "1760";
				}
				
				else if (stringHashType == "SHA-512(Unix)"){
					hashcode = "1800";
				}
				
				else if (stringHashType == "Cisco-PIX MD5"){
					hashcode = "2400";
				}
				
				else if (stringHashType == "WPA/WPA2"){
					hashcode = "2500";
				}
				
				else if (stringHashType == "Double MD5"){
					hashcode = "2600";
				}
				
				else if (stringHashType == "bcrypt, Blowfish(OpenBSD)"){
					hashcode = "3200";
				}
				
				else if (stringHashType == "MD5(Sun)"){
					hashcode = "3300";
				}
				
				else if (stringHashType == "md5(md5(md5($pass)))"){
					hashcode = "3500";
				}
				
				else if (stringHashType == "md5(md5($salt).$pass)"){
					hashcode = "3610";
				}
				
				else if (stringHashType == "md5($salt.md5($pass))"){
					hashcode = "3710";
				}
				
				else if (stringHashType == "md5($pass.md5($salt))"){
					hashcode = "3720";
				}
				
				else if (stringHashType == "md5($salt.$pass.$salt)"){
					hashcode = "3810";
				}
				
				else if (stringHashType == "md5(md5($pass).md5($salt))"){
					hashcode = "3910";
				}
				
				else if (stringHashType == "md5($salt.md5($salt.$pass))"){
					hashcode = "4010";
				}
				
				else if (stringHashType == "md5($salt.md5($pass.$salt))"){
					hashcode = "4110";
				}
				
				else if (stringHashType == "md5($username.0.$pass)"){
					hashcode = "4210";
				}
				
				else if (stringHashType == "md5(strtoupper(md5($pass)))"){
					hashcode = "4300";
				}
				
				else if (stringHashType == "md5(sha1($pass))"){
					hashcode = "4400";
				}
				
				else if (stringHashType == "sha1(sha1($pass))"){
					hashcode = "4500";
				}
				
				else if (stringHashType == "sha1(sha1(sha1($pass)))"){
					hashcode = "4600";
				}
				
				else if (stringHashType == "sha1(md5($pass))"){
					hashcode = "4700";
				}
				
				else if (stringHashType == "MD5(Chap)"){
					hashcode = "4800";
				}
				
				else if (stringHashType == "SHA-3(Keccak)"){
					hashcode = "5000";
				}
				
				else if (stringHashType == "Half MD5"){
					hashcode = "5100";
				}
				
				else if (stringHashType == "Password Safe SHA-256"){
					hashcode = "5200";
				}
				
				else if (stringHashType == "IKE-PSK MD5"){
					hashcode = "5300";
				}
				
				else if (stringHashType == "IKE-PSK SHA1"){
					hashcode = "5400";
				}
				
				else if (stringHashType == "NetNTLMv1-VANILLA / NetNTLMv1-ESS"){
					hashcode = "5500";
				}
				
				else if (stringHashType == "NetNTLMv2"){
					hashcode = "5600";
				}
				
				else if (stringHashType == "Cisco-IOS SHA256"){
					hashcode = "5700";
				}
				
				else if (stringHashType == "Samsung Android Password/PIN"){
					hashcode = "5800";
				}
				
				else if (stringHashType == "AIX {smd5}"){
					hashcode = "6300";
				}
				
				else if (stringHashType == "AIX {ssha256}"){
					hashcode = "6400";
				}
				
				else if (stringHashType == "AIX {ssha512}"){
					hashcode = "6500";
				}
				
				else if (stringHashType == "AIX {ssha1}"){
					hashcode = "6700";
				}
				
				else if (stringHashType == "GOST, GOST R 34.11-94"){
					hashcode = "6900";
				}
				
				else if (stringHashType == "Fortigate (FortiOS)"){
					hashcode = "7000";
				}
				
				else if (stringHashType == "OS X v10.8"){
					hashcode = "7100";
				}
				
				else if (stringHashType == "GRUB 2"){
					hashcode = "7200";
				}
				
				else if (stringHashType == "IPMI2 RAKP HMAC-SHA1"){
					hashcode = "7300";
				}
				
				else if (stringHashType == "sha256crypt, SHA256(Unix)"){
					hashcode = "7400";
				}
				
				else if (stringHashType == "Plaintext"){
					hashcode = "9999";
				}
				
				//Application Hashes
				else if (stringHashType == "Joomla"){
					hashcode = "11";
				}
				
				else if (stringHashType == "osCommerce, xt:Commerce"){
					hashcode = "21";
				}
				
				else if (stringHashType == "nsldap, SHA-1(Base64), Netscape LDAP SHA"){
					hashcode = "101";
				}
				
				else if (stringHashType == "nsldaps, SSHA-1(Base64), Netscape LDAP SSHA"){
					hashcode = "111";
				}
				
				else if (stringHashType == "Oracle 11g"){
					hashcode = "112";
				}
				
				else if (stringHashType == "SMF > v1.1"){
					hashcode = "121";
				}
				
				else if (stringHashType == "OS X v10.4, v10.5, v10.6"){
					hashcode = "122";
				}
				
				else if (stringHashType == "EPi"){
					hashcode = "123";
				}
				
				else if (stringHashType == "MSSQL(2000)"){
					hashcode = "131";
				}
				
				else if (stringHashType == "MSSQL(2005)"){
					hashcode = "132";
				}
				
				else if (stringHashType == "EPiServer 6.x < v4"){
					hashcode = "141";
				}
				
				else if (stringHashType == "EPiServer 6.x > v4"){
					hashcode = "1441";
				}
				
				else if (stringHashType == "SSHA-512(Base64), LDAP {SSHA512}"){
					hashcode = "1711";
				}
				
				else if (stringHashType == "OS X v10.7"){
					hashcode = "1722";
				}
				
				else if (stringHashType == "MSSQL(2012)"){
					hashcode = "1731";
				}
				
				else if (stringHashType == "vBulletin < v3.8.5"){
					hashcode = "2611";
				}
				
				else if (stringHashType == "vBulletin > v3.8.5"){
					hashcode = "2711";
				}
				
				else if (stringHashType == "IPB2+, MyBB1.2+"){
					hashcode = "2811";
				}
				
				else if (stringHashType == "WebEdition CMS"){
					hashcode = "3721";
				}
				
				else if (stringHashType == "Redmine Project Management Web App"){
					hashcode = "7600";
				}
				
				else {
					JOptionPane.showMessageDialog(null, "Please Select a Hash Type!");
				}


			
				
				
				
				
				
				
				
				
				
				
				
				if(attackmode == "0"){
					stringCommand = "hashcat-" + client + " " + "--hash" + " " + hashcode + " " + "--attack-mode" + " " + attackmode + " " + "--outfile" + " " + stringOutputFile + " " + stringHashFile + " " + stringWordlist1 + " " + stringWordlist2 + " " + stringWordlist3;
				}
				
				if(attackmode == "3"){
					stringCommand = "hashcat-" + client + " " + "--hash" + " " + hashcode + " " + "--attack-mode" + " "  + attackmode + " " + "--outfile" + " " + stringOutputFile + " " + stringHashFile + " " + stringMask;
				}
				
				
				commandOut.setText(stringCommand);
				
				
				//TODO WORK THIS OUT!!!
				//Should get Runtime, Creates command array and executes cmd, passing command array "commands" as argument to cmd
				Runtime rt = Runtime.getRuntime();
				
				//String[] commands = new String[]{"cmd.exe /c start \""  + stringCommand + "\"cmd.exe /c start"};
				
				try {
					rt.exec("cmd.exe /c start cmd.exe /k \""+stringCommand+"\"");
				} catch (IOException e) {
					JOptionPane.showMessageDialog(null, e);
					e.printStackTrace();
				}
				
				
				
				
				
			}
		});
		engineer.setBounds(443, 317, 286, 63);
		hashcat.add(engineer);
						
		JLabel lblClient = new JLabel("Client:");
		lblClient.setBounds(633, 15, 46, 14);
		hashcat.add(lblClient);
		
		
		
		
		
		}
}

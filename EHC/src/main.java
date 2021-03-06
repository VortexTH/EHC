import java.awt.EventQueue;
import java.awt.Toolkit;

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

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
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
import java.awt.Color;





public class main {
	
	public String stringHashFile = "";
	public String stringOutputFile = "";
	public String stringWordlist1 = "";
	public String stringWordlist2 = "";
	public String stringWordlist3 = "";
	public String stringWordlist4 = "";
	public String stringWordlist5 = "";
	public String stringRule1 = "";
	public String stringRule2 = "";	
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
	public String stringThreads = "";
	public String stringSegmentSize = "";
	public String stringHashcatType = "";
	public String stringGpuTempAbort = "";
	public String stringGpuAccel = "";

	private JFrame frmEhcV;
	private JTextField hashFile;
	private JTextField threadsfield;
	private JTextField wordlist1;
	private JTextField wordlist2;
	private JTextField wordlist3;
	private JTextField rule1;
	private JTextField rule2;
	private JTextField outputhFile;
	private JTextField mask;
	private JTextField wordlist4;
	private JTextField wordlist5;
	private JTextField segmentsizefield;
	private JTextField gputempfield;

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
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          hashFile.setText((selectedFilePath.getPath()));
		        }
			}
		});
		InputFileBrowse.setBounds(555, 11, 71, 23);
		hashcat.add(InputFileBrowse);
		
		JLabel lblSeperator = new JLabel("Threads:");
		lblSeperator.setBounds(434, 114, 52, 22);
		hashcat.add(lblSeperator);
		
		threadsfield = new JTextField();
		threadsfield.setBounds(512, 114, 68, 22);
		hashcat.add(threadsfield);
		threadsfield.setColumns(10);
		
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
		separator.setBounds(106, 96, 353, 12);
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
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
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
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
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
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
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
		
		JLabel Performance = new JLabel("Performance");
		Performance.setBounds(463, 86, 64, 22);
		hashcat.add(Performance);
		
		JSeparator separator_5 = new JSeparator();
		separator_5.setBounds(528, 96, 231, 12);
		hashcat.add(separator_5);
		
		JSeparator separator_6 = new JSeparator();
		separator_6.setBounds(88, 281, 335, 12);
		hashcat.add(separator_6);
		
		JLabel lblRules = new JLabel("Rules");
		lblRules.setBounds(59, 271, 47, 22);
		hashcat.add(lblRules);
		
		JSeparator separator_7 = new JSeparator();
		separator_7.setBounds(0, 281, 57, 12);
		hashcat.add(separator_7);
		
		JLabel lblRule_2 = new JLabel("Rule 1:");
		lblRule_2.setBounds(5, 304, 52, 22);
		hashcat.add(lblRule_2);
		
		rule1 = new JTextField();
		rule1.setColumns(10);
		rule1.setBounds(67, 304, 248, 22);
		hashcat.add(rule1);
		
		JButton rule3Browse = new JButton("Browse");
		rule3Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          rule1.setText((selectedFilePath.getPath()));
		        }
			}
		});
		rule3Browse.setBounds(325, 304, 89, 23);
		hashcat.add(rule3Browse);
		
		JLabel lblRule_3 = new JLabel("Rule 2:");
		lblRule_3.setBounds(5, 337, 52, 22);
		hashcat.add(lblRule_3);
		
		rule2 = new JTextField();
		rule2.setColumns(10);
		rule2.setBounds(67, 337, 248, 22);
		hashcat.add(rule2);
		
		JButton rule4Browse = new JButton("Browse");
		rule4Browse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser();
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
		        int returnValue = fileChooser.showOpenDialog(null);
		        if (returnValue == JFileChooser.APPROVE_OPTION) {
		          File selectedFilePath = fileChooser.getSelectedFile();
		          rule2.setText((selectedFilePath.getPath()));
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
		btnCheatSheet.setBounds(620, 179, 104, 23);
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
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
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
				File loc = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
				fileChooser.setCurrentDirectory(loc);
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
		
		JLabel commandOut = new JLabel("");
		commandOut.setBounds(10, 503, 739, 40);
		hashcat.add(commandOut);
		
		JButton CopyToClipboard = new JButton("Copy To Clipboard");
		CopyToClipboard.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
								
				StringSelection copied = new StringSelection(commandOut.getText());
			    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			    clipboard.setContents (copied, copied);
								
			}
		});
		CopyToClipboard.setBounds(10, 554, 161, 23);
		hashcat.add(CopyToClipboard);
		
		JPanel oclhashcat = new JPanel();
		tabbedPane.addTab("oclHashcat Advanced Options", null, oclhashcat, null);
		oclhashcat.setLayout(null);
		
		JLabel lblGpuAcceleration = new JLabel("GPU Acceleration:");
		lblGpuAcceleration.setBounds(10, 11, 86, 14);
		oclhashcat.add(lblGpuAcceleration);
		
		JComboBox gpuaccelerationbox = new JComboBox();
		gpuaccelerationbox.setModel(new DefaultComboBoxModel(new String[] {"(none)", "1", "8", "40", "80", "160"}));
		gpuaccelerationbox.setBounds(106, 8, 63, 20);
		oclhashcat.add(gpuaccelerationbox);
		
		JLabel lblNewLabel = new JLabel("Gpu, Fanspeed, Temp warnings & triggers:");
		lblNewLabel.setBounds(207, 11, 212, 14);
		oclhashcat.add(lblNewLabel);
		
		JComboBox comboBox_1 = new JComboBox();
		comboBox_1.setModel(new DefaultComboBoxModel(new String[] {"On", "Off"}));
		comboBox_1.setBounds(429, 8, 91, 20);
		oclhashcat.add(comboBox_1);
		
		JLabel lblGpuTemperatureAbort = new JLabel("GPU Temperature abort at:");
		lblGpuTemperatureAbort.setBounds(10, 84, 131, 14);
		oclhashcat.add(lblGpuTemperatureAbort);
		
		gputempfield = new JTextField();
		gputempfield.setBounds(145, 81, 86, 20);
		oclhashcat.add(gputempfield);
		gputempfield.setColumns(10);
		
		JLabel lblc = new JLabel("\u00B0C");
		lblc.setBounds(235, 84, 46, 14);
		oclhashcat.add(lblc);
		
		JLabel lblClient = new JLabel("Client:");
		lblClient.setBounds(633, 15, 46, 14);
		hashcat.add(lblClient);
		
		JLabel lblWordlist_3 = new JLabel("Wordlist 4:");
		lblWordlist_3.setBounds(5, 212, 52, 22);
		hashcat.add(lblWordlist_3);
		
		wordlist4 = new JTextField();
		wordlist4.setColumns(10);
		wordlist4.setBounds(67, 212, 248, 22);
		hashcat.add(wordlist4);
		
		JButton button_1 = new JButton("Browse");
		button_1.setBounds(325, 212, 89, 23);
		hashcat.add(button_1);
		
		JLabel lblWordlist_4 = new JLabel("Wordlist 5:");
		lblWordlist_4.setBounds(5, 245, 52, 22);
		hashcat.add(lblWordlist_4);
		
		wordlist5 = new JTextField();
		wordlist5.setColumns(10);
		wordlist5.setBounds(67, 245, 248, 22);
		hashcat.add(wordlist5);
		
		JButton button_2 = new JButton("Browse");
		button_2.setBounds(325, 245, 89, 23);
		hashcat.add(button_2);		
		
		JLabel lblSegmentSize = new JLabel("Segment size:");
		lblSegmentSize.setBounds(434, 143, 67, 14);
		hashcat.add(lblSegmentSize);
		
		segmentsizefield = new JTextField();
		segmentsizefield.setBounds(512, 140, 68, 20);
		hashcat.add(segmentsizefield);
		segmentsizefield.setColumns(10);
		
		JLabel lblMb = new JLabel("MB");
		lblMb.setBounds(582, 143, 25, 14);
		hashcat.add(lblMb);
		
		JComboBox hashcattypechooser = new JComboBox();
		hashcattypechooser.setBackground(Color.WHITE);
		hashcattypechooser.setForeground(Color.RED);
		hashcattypechooser.setModel(new DefaultComboBoxModel(new String[] {"Hashcat", "oclHashcat"}));
		hashcattypechooser.setBounds(10, 45, 125, 21);
		hashcat.add(hashcattypechooser);		
		
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
				String threads = "";
				String segments = "";
				String gpuAcceleration = "";
				String gpuAbortTemp = "";
				String oclClient = "";
				
				stringHashFile = " " + hashFile.getText();
				stringOutputFile = " " + outputhFile.getText();
				
				//Gets wordlist DIRs
				if(wordlist1.getText().length() > 0){
				stringWordlist1 = " " + wordlist1.getText();
				}
				if(wordlist2.getText().length() > 0){
				stringWordlist2 = " " + wordlist2.getText();
				}
				if(wordlist3.getText().length() > 0){
				stringWordlist3 = " " + wordlist3.getText();
				}
				if(wordlist4.getText().length() > 0){
				stringWordlist4 = " " + wordlist4.getText();
				}
				if(wordlist5.getText().length() > 0){
				stringWordlist5 = " " + wordlist5.getText();
				}
				
				
				stringRule1 = " " + rule1.getText();
				stringRule2 = " " + rule2.getText();
				stringSeparator = threadsfield.getText();
				stringmode = mode.getSelectedItem().toString();
				stringOutputFormat = outputFormat.getSelectedItem().toString();
				stringHashType = hashType.getSelectedItem().toString();
				stringcli = cli.getSelectedItem().toString();
				stringOutputFile = outputhFile.getText();
				stringMask = mask.getText();
				stringThreads = threadsfield.getText();
				stringSegmentSize = segmentsizefield.getText();
				stringGpuTempAbort = gputempfield.getText();
				stringGpuAccel = gpuaccelerationbox.getSelectedItem().toString();
				
				//distinguishes between oclhashcat and CPU-based hashcat
				stringHashcatType = hashcattypechooser.getSelectedItem().toString();		
				
				
				//Sets GPU abort Temp for oclHashcat
				if(gputempfield.getText().length() > 0){
					gpuAbortTemp = " --gpu-temp-abort=" + stringGpuTempAbort;
				}
				
				
				//Sets GPU tuning options
				if(gpuaccelerationbox.getSelectedItem().toString() != "(none)"){
				    gpuAcceleration = " --gpu-accel=" + stringGpuAccel;
				}
				
				
				//Sets size of segment to cache from wordfile
				if(segmentsizefield.getText().length() > 0){
					segments = " --segment-size=" + stringSegmentSize;
				}
				
				
				//Sets number of concurrent threads
				if(threadsfield.getText().length() > 0){
					threads = " --threads=" + stringThreads;
				}				
				
				
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
					oclClient = "64";
				}
				
				else if(stringcli == "cli32"){
					client = "cli32";
					oclClient = "32";
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
				
				
				//-o argument strings
				String dirmod0 = " -o" + stringOutputFile + stringHashFile + stringWordlist1 + stringWordlist2 + stringWordlist3 + stringWordlist4 + stringWordlist5; 
				String dirmod3 = " -o" + stringOutputFile + " " + stringHashFile + " " + stringMask;
				
				
				//Rules
				if(rule1.getText().length() > 0 || rule2.getText().length() > 0){
					dirmod0 = dirmod0 + " -r" + stringRule1 +stringRule2;
				}
							
				
				
				//determines hashcat release in this case Hashcat CPU-based
				if (stringHashcatType == "Hashcat"){
				
				//Creates and sets command string
				if(attackmode == "0"){
					stringCommand = "hashcat-" + client + " -m " + hashcode + " -a " + attackmode + threads + segments + dirmod0;
				}
				
				if(attackmode == "3"){
					stringCommand = "hashcat-" + client + " -m " + hashcode + " -a " + attackmode + threads + segments + dirmod3;
				}				
				
			}
				
				
				
				//determines Hashcat release in this case oclHashcat
				else if (stringHashcatType == "oclHashcat"){
					
					//Creates and sets command string
					if(attackmode == "0"){
						stringCommand = "cudahashcat" + oclClient + " -m " + hashcode + " -a " + attackmode + threads + segments + gpuAcceleration + gpuAbortTemp + dirmod0;
					}
					
					if(attackmode == "3"){
						stringCommand = "cudahashcat" + oclClient + " -m " + hashcode + " -a " + attackmode + threads + segments + gpuAcceleration + gpuAbortTemp + dirmod3;
					}				
					
					
				}
				
				
				
				
				//Gets Runtime, executes cmd, passing "stringCommand" to the process.
				Runtime rt = Runtime.getRuntime();
				
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
						
		
		}
	}

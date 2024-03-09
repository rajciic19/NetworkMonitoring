package ru210540d;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.net.SocketException;

import org.snmp4j.CommunityTarget;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.SnmpConstants;

import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;

import org.snmp4j.transport.DefaultUdpTransportMapping;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import org.snmp4j.smi.*;
import org.snmp4j.util.*;


import java.util.List;

public class V4 extends JFrame{

	OID[] oid_array = new OID[9];
	
	public static String comm="si2019";
	
	public static String r1="192.168.10.1";
	public static String r2="192.168.20.1";
	public static String r3="192.168.30.1";
	
	public static int port = 161;
	public static int l_port = 1620;
	
	OID bgpOID = new OID("1.3.6.1.2.1.15");
	
	Object[][] data = new Object[2][9]; 
	
	Snmp snmp=null;
	CommunityTarget target = new CommunityTarget();
	
	private JTextArea textArea;
	
	public V4(JFrame frame) throws IOException {
	    refreshData(frame);
	    show_frame(frame);
	    
	}
	
	private void show_frame(JFrame frame) {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	    setLayout(new BorderLayout());

	    String[] columnNames = {"ID", "STATE", "VERSION", "IP_ADDRESS", "AS", "RECEIVED", "SENT", "KEEPALIVE", "ELAPSED"};
		JTable table = new JTable(data, columnNames);
	    table.setBackground(Color.BLACK);
	    table.setForeground(Color.WHITE);
	    table.setPreferredScrollableViewportSize(new Dimension(800, 30));
	    table.setFillsViewportHeight(true);

	    textArea = new JTextArea(20, 20);
	    textArea.setEditable(false);
	    textArea.setBackground(Color.BLACK);
	    textArea.setForeground(Color.WHITE);
	    textArea.setAlignmentX(Component.CENTER_ALIGNMENT);

	    JPanel containerPanel = new JPanel();
	    containerPanel.setLayout(new BoxLayout(containerPanel, BoxLayout.Y_AXIS));
	    containerPanel.setBackground(Color.BLACK);

	    JScrollPane scrollPane = new JScrollPane(table);
	    scrollPane.setAlignmentX(Component.CENTER_ALIGNMENT);
	    scrollPane.getViewport().setBackground(Color.BLACK);
	    containerPanel.add(scrollPane);

	    //containerPanel.add(Box.createVerticalStrut(50));
	    containerPanel.add(textArea);

	    add(containerPanel, BorderLayout.NORTH);

	    pack();
	    setLocationRelativeTo(null);
	    setVisible(true);


	}
	 
	public static void main(String[] args) {
	     
	 }

 	public void refreshData(JFrame frame) throws IOException {
		oid_array[0] = new OID(".1.3.6.1.2.1.15.3.1.1"); //bgpPeerIdentifier
		oid_array[1] = new OID(".1.3.6.1.2.1.15.3.1.2"); //bgpPeerState
		oid_array[2] = new OID(".1.3.6.1.2.1.15.3.1.4"); //bgpPeerNegotiatedVersion, 4
		oid_array[3] = new OID(".1.3.6.1.2.1.15.3.1.7"); //bgpPeerRemoteAddr
		//oid_array[4] = new OID(".1.3.6.1.2.1.15.3.1.8"); //bgpPeerRemotePort
		oid_array[4] = new OID(".1.3.6.1.2.1.15.3.1.9"); //bgpPeerRemoteAs
		oid_array[5] = new OID(".1.3.6.1.2.1.15.3.1.10"); //bgpPeerInUpdates
		oid_array[6] = new OID(".1.3.6.1.2.1.15.3.1.11"); //bgpPeerOutUpdates
		oid_array[7] = new OID(".1.3.6.1.2.1.15.3.1.19"); //bgpPeerKeepAlive
		oid_array[8] = new OID(".1.3.6.1.2.1.15.3.1.24"); //bgpPeerInUpdateElapsedTime
		
		
		TransportMapping transport=null;
		try {
			transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
		} 
		catch (SocketException e) {
			e.printStackTrace();
		}
		
		target.setCommunity(new OctetString(comm));
		//target.setAddress(targetAddress);
		if(target.getAddress()==null) target.setAddress(GenericAddress.parse("udp:" + r2 + "/161"));
		target.setVersion(SnmpConstants.version1);
		target.setTimeout(1000);
		target.setRetries(3);
		
		transport.listen();
		
		int j=0;
		int k=0;
		for(int i=0;i<9;i++) {
			TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
	        List<TreeEvent> events = treeUtils.getSubtree(target, oid_array[i]);

	        if(events == null || events.size() == 0) {
	            System.out.println("Greska");
	            return;
	        }
	        for(TreeEvent event: events) {
	            VariableBinding[] varBindings = event.getVariableBindings();
	            if(varBindings != null && varBindings.length > 0) {
	                for (VariableBinding varBinding : varBindings) {
	                    if ((varBinding.getOid()).startsWith(oid_array[i])) {
	                    	
	                        String value = varBinding.getVariable().toString();
	                        System.out.println("Vrednost: " + value); 
	                        
	                        
	                        data[k++][j]=value;
	                        if(k==2) {
	                        	k=0;
	                        	j++;
	                        }
	                    }
	                }
	            }
	        }
		}
		show_frame(frame);
		
		
	}
}

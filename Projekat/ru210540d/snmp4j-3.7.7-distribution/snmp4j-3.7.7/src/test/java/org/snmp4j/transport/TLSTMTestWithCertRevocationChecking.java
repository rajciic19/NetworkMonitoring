/*_############################################################################
  _## 
  _##  SNMP4J - TLSTMTestWithCertRevocationChecking.java  
  _## 
  _##  Copyright (C) 2003-2022  Frank Fock (SNMP4J.org)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/
package org.snmp4j.transport;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.log.ConsoleLogAdapter;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.TSM;
import org.snmp4j.smi.*;
import org.snmp4j.transport.tls.DefaultTlsTmSecurityCallback;
import org.snmp4j.transport.tls.SecurityNameMapping;
import org.snmp4j.transport.tls.TLSTMUtil;

import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.cert.PKIXRevocationChecker;
import java.util.*;

import static org.junit.Assert.*;

/**
 * Test TLSTM with real networking and certificate revocation checking activated.
 * @author Frank Fock
 */
public class TLSTMTestWithCertRevocationChecking {

    static {
        LogFactory.setLogFactory(new ConsoleLogFactory());
        ConsoleLogAdapter.setWarnEnabled(true);
    }

    private static final int TIMEOUT = 5000;

    private TLSTM tlstmCR;
    private TLSTM tlstmCS;
    private static final String SEC_NAME = "localhost";
    private static final String CA_DN = "CN=ca,OU=snmp4j-unit-test,O=AGENTPP,L=Stuttgart,ST=Baden-Wuerttemberg,C=DE";
    private static final String UNKNOWN_ISSUER_DN = "CN=www.snmp4j.org, OU=Unit-Test, O=AGENTPP, L=Stuttgart, ST=Baden-Wuerttemberg, C=DE";
    private static final OctetString SERVER_FINGER_PRINT =
             OctetString.fromHexString("72:b2:ab:da:db:47:79:d3:47:78:36:d8:e2:4f:6d:3c:52:e1:c6:b9:bc:2a:19:93:b8:c3:43:ab:e9:0e:1a:c7:1c:cf:a0:af:9a:55:1b:19:2e:aa:89:6c:90:7e:7f:98");
    private static final OctetString CLIENT_FINGER_PRINT =
        OctetString.fromHexString("0d:0b:d7:a1:e5:79:f8:a3:4a:de:8d:11:25:df:87:38:74:69:4a:d8:6e:fd:41:23:d1:09:af:11:fa:32:d2:52:41:95:85:0e:5c:94:d4:2d:e8:01:6b:eb:14:95:06:b2");
    private static final byte[] MESSAGE = new byte[] { 0,1,2,3,4,5,6,7,8,9,10 };
    private static final byte[] MESSAGE_SCOPED_PDU =
            OctetString.fromHexString("02 01 00 02 01"
                    +" 00 30 46 30 17 06 0F 2B 06 01 04 01 A6 70 0A 01 01 04 01 01 02 00 42 04 05 75 8A 24 30 2B 06 09"
                    +" 2B 06 01 06 03 12 01 04 00 04 1E 70 65 57 61 64 66 6E 61 67 6E 65 72 67 72 44 46 41 41 48 41 72"
                    +" C3 A4 C3 B6 C3 9F 33 39 34", ' ').getValue();

    @Before
    public void setUp() throws Exception {
        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        tlstmCS = new TLSTM();
        tlstmCS.setServerEnabled(false);
        tlstmCR = new TLSTM(new TlsAddress("127.0.0.1/0"));
        tlstmCR.setX09CertificateRevocationListURI(getClass().getResource("tls/crl_server.pem").toURI().toString());
        tlstmCS.setX09CertificateRevocationListURI(getClass().getResource("tls/crl_server.pem").toURI().toString());
        tlstmCR.setServerEnabled(true);
        //URL keystoreUrl = getClass().getResource("dtls-cert.ks");
        URL keystoreUrlServer = getClass().getResource("tls/agent-keystore.jks");
        URL truststoreUrlServer = getClass().getResource("tls/agent-truststore.jks");
        URL keystoreUrlClient = getClass().getResource("tls/client-keystore.jks");
        URL truststoreUrlClient = getClass().getResource("tls/client-truststore.jks");
        String password = "snmp4j";
        tlstmCS.setKeyStore(keystoreUrlClient.getFile());
        tlstmCS.setKeyStorePassword(password);
        tlstmCR.setKeyStore(keystoreUrlServer.getFile());
        tlstmCR.setKeyStorePassword(password);
        tlstmCS.setTrustStore(truststoreUrlClient.getFile());
        tlstmCS.setTrustStorePassword(password);
        tlstmCR.setTrustStore(truststoreUrlServer.getFile());
        tlstmCR.setTrustStorePassword(password);

        tlstmCR.setProtocolVersions(new String[]{"TLSv1.2"});
        tlstmCS.setProtocolVersions(new String[]{"TLSv1.2"});
    }

    @After
    public void tearDown() throws Exception {
         tlstmCR.close();
         tlstmCS.close();
    }

    @Test
    public void sendMessageWithPDUDnsCertPathVerification() throws Exception {
        // The below property cannot be set to false during runtime (will not have any effect if called after first
        // trust manager initialization:
        //System.setProperty("com.sun.net.ssl.checkRevocation", "false");
        tlstmCS.setX09CertificateRevocationListURI(null);
        tlstmCR.listen();
        final boolean[] messageReceived = { false, false, false };
        CertifiedTarget<TlsAddress> certifiedTarget = new CertifiedTarget<>(new TlsAddress(tlstmCR.getListenAddress()),
                new OctetString("localhost"), SERVER_FINGER_PRINT, new OctetString());
        certifiedTarget.setTimeout(3000);
        certifiedTarget.setRetries(0);
        final CommandResponder commandResponder = new CommandResponder() {

            public synchronized <A extends Address> void processPdu(CommandResponderEvent<A> event) {
                messageReceived[event.getPDU().getVariableBindings().size()-2] = true;
                if (messageReceived[2]) {
                    notify();
                }
                event.setProcessed(true);
            }

        };
        DefaultTlsTmSecurityCallback securityCallback = new DefaultTlsTmSecurityCallback();
        securityCallback.addAcceptedIssuerDN(CA_DN);
        securityCallback.addSecurityNameMapping(
                new OctetString(),
                SecurityNameMapping.CertMappingType.SANDNSName,
                new OctetString("localhost"), new OctetString("localhost"));
        tlstmCR.setSecurityCallback(securityCallback);
        Snmp snmpAgent = new Snmp(tlstmCR);
        snmpAgent.addCommandResponder(commandResponder);
        ScopedPDU scopedPDU = new ScopedPDU();
        UnsignedInteger32 value1 = new UnsignedInteger32(91589156l);
        OctetString value2 = new OctetString("peWadfnagnergrDFAAHAräöß394");
        scopedPDU.add(new VariableBinding(SnmpConstants.snmp4jStatsRequestRetries, value1));
        scopedPDU.add(new VariableBinding(SnmpConstants.snmpTrapCommunity, value2));
        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
        Snmp snmp = new Snmp(tlstmCS);
        ((MPv3)snmp.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM()));
        ((MPv3)snmpAgent.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM(localEngineID, false)));
        scopedPDU.setContextEngineID(localEngineID);
        snmp.listen();
        snmpAgent.setLocalEngine(localEngineID.getValue(), 1, 1);
        snmpAgent.listen();
        synchronized (commandResponder) {
            snmp.send(scopedPDU, certifiedTarget);
            ScopedPDU scopedPDU1 = (ScopedPDU) scopedPDU.clone();
            scopedPDU1.add(new VariableBinding(SnmpConstants.sysServices, new Integer32(42)));
            snmp.send(scopedPDU1, certifiedTarget);
            ScopedPDU scopedPDU2 = (ScopedPDU) scopedPDU.clone();
            scopedPDU1.add(new VariableBinding(SnmpConstants.sysContact, new OctetString("me")));
            snmp.send(scopedPDU2, certifiedTarget);
            commandResponder.wait(3000);
        }
        assertTrue(messageReceived[0]);
        snmp.close();
        snmpAgent.close();
    }


    @Test
    public void sendMessageWithRevokedServerCertificate() throws Exception {
        final boolean[] messageReceived = { false };
        CertifiedTarget<TlsAddress> certifiedTarget = new CertifiedTarget<>(new TlsAddress(tlstmCR.getListenAddress()),
                // accept server fingerprint and let client be accepted by cert path validation
                new OctetString(SEC_NAME), new OctetString(), new OctetString());
        TransportStateReference tmStateReference =
                new TransportStateReference(tlstmCS,
                        tlstmCR.getListenAddress(),
                        new OctetString(SEC_NAME),
                        SecurityLevel.authPriv,
                        SecurityLevel.undefined,
                        false, null, certifiedTarget);
        final TransportListener transportListener = new TransportListener() {
            public synchronized <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport,
                                                                        A incomingAddress, ByteBuffer wholeMessage,
                                                                        TransportStateReference tmStateReference) {
                byte[] message = new byte[wholeMessage.limit()];
                System.arraycopy(wholeMessage.array(), 0, message, 0, message.length);
                assertArrayEquals(MESSAGE, message);
                messageReceived[0] = true;
                notify();
            }
        };
        tlstmCR.addTransportListener(transportListener);
        tlstmCR.listen();
        tlstmCS.listen();
        synchronized (transportListener) {
            tlstmCS.sendMessage(tlstmCR.getListenAddress(), MESSAGE, tmStateReference, 3000, 0);
            transportListener.wait(3200);
        }
        assertFalse(messageReceived[0]);
    }

    @Test
    public void sendMessageWithRevokedServerCertificateWithCustomRevocationChecker() throws Exception {
        tlstmCR.setX09CertificateRevocationListURI(null);
        tlstmCS.setX09CertificateRevocationListURI(null);
        PKIXRevocationChecker certPathChecker = TLSTMUtil.createDefaultPKIXRevocationChecker();
        certPathChecker.setOptions(EnumSet.of(
                PKIXRevocationChecker.Option.ONLY_END_ENTITY));
        certPathChecker.setOcspResponses(Collections.emptyMap());
        tlstmCR.setPKIXRevocationChecker(certPathChecker);
        tlstmCS.setPKIXRevocationChecker(certPathChecker);
        final boolean[] messageReceived = { false };
        CertifiedTarget<TlsAddress> certifiedTarget = new CertifiedTarget<>(new TlsAddress(tlstmCR.getListenAddress()),
                // accept server fingerprint and let client be accepted by cert path validation
                new OctetString(SEC_NAME), new OctetString(), new OctetString());
        TransportStateReference tmStateReference =
                new TransportStateReference(tlstmCS,
                        tlstmCR.getListenAddress(),
                        new OctetString(SEC_NAME),
                        SecurityLevel.authPriv,
                        SecurityLevel.undefined,
                        false, null, certifiedTarget);
        final TransportListener transportListener = new TransportListener() {
            public synchronized <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport,
                                                                        A incomingAddress, ByteBuffer wholeMessage,
                                                                        TransportStateReference tmStateReference) {
                byte[] message = new byte[wholeMessage.limit()];
                System.arraycopy(wholeMessage.array(), 0, message, 0, message.length);
                assertArrayEquals(MESSAGE, message);
                messageReceived[0] = true;
                notify();
            }
        };
        tlstmCR.addTransportListener(transportListener);
        tlstmCR.listen();
        tlstmCS.listen();
        synchronized (transportListener) {
            tlstmCS.sendMessage(tlstmCR.getListenAddress(), MESSAGE, tmStateReference, 3000, 0);
            transportListener.wait(3200);
        }
        assertFalse(messageReceived[0]);
    }


    @Test
    public void sendMessageWithUntrustedCertificate() throws Exception {
        TLSTM tlstmCS = new TLSTM() {
            @Override
            void writeNetBuffer(SocketEntry entry, SocketChannel sc) throws IOException {
                entry.getOutNetBuffer().flip();
                // Send SSL/TLS encoded data to peer
                ByteBuffer outNet = entry.getOutNetBuffer().slice();
                while (outNet.hasRemaining()) {
                    for (int start = outNet.position(), end = outNet.limit(),
                         packetLength = 500; start < end; start = outNet.limit()) {
                        int num = sc.write(outNet.position(start).limit(start + Math.min(end - start, packetLength)));
                        try {
                            Thread.sleep(100);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        if (num == -1) {
                            throw new IOException("TLS connection closed");
                        }
                    }
                }
                entry.getOutNetBuffer().clear();
            }
        };
        tlstmCS.setServerEnabled(false);
        URL keystoreUrl = getClass().getResource("dtls-cert.ks");
        String password = "snmp4j";
        tlstmCS.setKeyStore(keystoreUrl.getFile());
        tlstmCS.setKeyStorePassword(password);
        tlstmCS.setTrustStore(keystoreUrl.getFile());
        tlstmCS.setTrustStorePassword(password);
        tlstmCS.setProtocolVersions(new String[]{"TLSv1.2"});
        tlstmCS.setMaxInboundMessageSize(32768);
        tlstmCR.setMaxInboundMessageSize(32768);
        tlstmCR.listen();
        final boolean[] messageReceived = { false };
        CertifiedTarget<TlsAddress> certifiedTarget = new CertifiedTarget<>(new TlsAddress(tlstmCR.getListenAddress()),
                new OctetString(SEC_NAME), SERVER_FINGER_PRINT, CLIENT_FINGER_PRINT);
        certifiedTarget.setTimeout(10000);
        certifiedTarget.setRetries(0);
        final CommandResponder commandResponder = new CommandResponder() {

            @Override
            public synchronized <A extends Address> void processPdu(CommandResponderEvent<A> event) {
                messageReceived[0] = true;
                notify();
                event.setProcessed(true);
            }

        };
        DefaultTlsTmSecurityCallback securityCallback = new DefaultTlsTmSecurityCallback();
        securityCallback.addAcceptedIssuerDN("CN=www.snmp4j.org, OU=Unit-Test, O=AGENTPP, L=Stuttgart, ST=Baden-Wuerttemberg, C=DE");
        securityCallback.addSecurityNameMapping(
                OctetString.fromHexString("4a:48:60:20:35:10:97:92:de:62:79:ae:85:b9:49:65:e9:03:6d:5a:f8:f3:70:41:9d:db:50:5a:76:3c:de:b5"),
                SecurityNameMapping.CertMappingType.SANIpAddress,
                new OctetString("127.0.0.1"), new OctetString("localhost"));
        tlstmCR.setSecurityCallback(securityCallback);
        Snmp snmpAgent = new Snmp(tlstmCR);
        snmpAgent.addCommandResponder(commandResponder);
        ScopedPDU scopedPDU = new ScopedPDU();
        //scopedPDU.setType(PDU.INFORM);
        UnsignedInteger32 value1 = new UnsignedInteger32(91589156l);
        OctetString value2 = new OctetString("peWadfnagnergrDFAAHAräöß394");
        scopedPDU.add(new VariableBinding(SnmpConstants.snmp4jStatsRequestRetries, value1));
        scopedPDU.add(new VariableBinding(SnmpConstants.snmpTrapCommunity, value2));
        scopedPDU.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString(ByteBuffer.allocate(1000).array())));
        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
        Snmp snmp = new Snmp(tlstmCS);
        ((MPv3)snmp.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM()));
        ((MPv3)snmpAgent.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM(localEngineID, false)));
        scopedPDU.setContextEngineID(localEngineID);
        snmp.listen();
        snmpAgent.setLocalEngine(localEngineID.getValue(), 1, 1);
        snmpAgent.listen();
        final ResponseListener responseListener = new ResponseListener() {
            @Override
            public synchronized <A extends Address> void onResponse(ResponseEvent<A> event) {
            }
        };
        synchronized (commandResponder) {
            snmp.send(scopedPDU, certifiedTarget, null, responseListener);
            commandResponder.wait(5000);
        }
        assertFalse("PDU received by command responder although client certificate should not be trusted", messageReceived[0]);
        snmp.close();
        snmpAgent.close();
    }
}

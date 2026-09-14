package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 7: ACK records travel in their own content type, are delivered to the handshake rather than to
 * the application, and a malformed ACK is discarded rather than failing the connection.
 */
public class DTLSAckTransportTest
    extends TestCase
{
    static class RecordingAckListener
        implements DTLSAckListener
    {
        final Vector received = new Vector();

        public void receivedAck(Vector recordNumbers) throws IOException
        {
            received.addElement(recordNumbers);
        }
    }

    public void testAckRoundTripsBetweenTwoRecordLayers() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(2, 0));
        recordNumbers.addElement(new DTLSRecordNumber(2, 3));

        DTLSRecordNumber sent = support.client.recordLayer.sendAck(recordNumbers);
        assertNotNull("the ACK must report its own record number", sent);

        // the ACK is not application data: receive must not surface it, but the listener must see it
        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals(1, listener.received.size());
        Vector got = (Vector)listener.received.elementAt(0);
        assertEquals(2, got.size());
        assertEquals(new DTLSRecordNumber(2, 0), got.elementAt(0));
        assertEquals(new DTLSRecordNumber(2, 3), got.elementAt(1));
    }

    public void testEmptyAckIsDelivered() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        support.client.recordLayer.sendAck(new Vector());

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals(1, listener.received.size());
        assertEquals(0, ((Vector)listener.received.elementAt(0)).size());
    }

    public void testAckWithNoListenerIsDiscarded() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        support.client.recordLayer.sendAck(new Vector());

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        // and the connection still works
        byte[] data = new byte[]{ 1, 2, 3 };
        support.client.recordLayer.send(data, 0, data.length);
        int n = support.server.recordLayer.receive(buf, 0, buf.length, 1000);
        assertEquals(3, n);
        assertTrue(Arrays.areEqual(data, Arrays.copyOf(buf, 3)));
    }

    public void testMalformedAckBodyIsDiscarded() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        // a body whose declared length does not match its contents
        byte[] bad = new byte[]{ 0, 32, 0, 0 };
        support.client.recordLayer.sendRecordForTest(ContentType.ack, bad, 0, bad.length);

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals("a malformed ACK must be discarded, not delivered", 0, listener.received.size());

        byte[] data = new byte[]{ 9 };
        support.client.recordLayer.send(data, 0, data.length);
        assertEquals(1, support.server.recordLayer.receive(buf, 0, buf.length, 1000));
    }

    /**
     * RFC 9147 7. "During the handshake, ACK records MUST be sent with an epoch which is equal to or higher
     * than the record which is being acknowledged", so during the handshake a record number naming a higher
     * epoch than the ACK that carried it is discarded on receipt.
     * <p>
     * Epoch 0 is unauthenticated and DTLS sequence numbers are predictable, so without this an off-path
     * attacker who can spoof the peer's address could forge a plaintext ACK naming the protected epochs,
     * retire fragments that were never delivered and stall the handshake.
     * </p>
     */
    public void testAckRecordNumbersAboveTheAckEpochAreDiscardedDuringTheHandshake() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        // The rule under test is a handshake-time one; the harness has otherwise completed the handshake
        support.server.recordLayer.inHandshake = true;

        int ackEpoch = support.server.recordLayer.getReadEpoch();

        // one record number at the ACK's own epoch, one above it
        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(ackEpoch, 7));
        recordNumbers.addElement(new DTLSRecordNumber(ackEpoch + 1, 0));

        byte[] body = DTLSAck.encode(recordNumbers);
        support.client.recordLayer.sendRecordForTest(ContentType.ack, body, 0, body.length);

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals("the ACK is still delivered", 1, listener.received.size());

        Vector got = (Vector)listener.received.elementAt(0);
        assertEquals("only the record number at or below the ACK's epoch survives", 1, got.size());
        assertEquals(new DTLSRecordNumber(ackEpoch, 7), got.elementAt(0));
    }

    /**
     * RFC 9147 7. After the handshake there is no such floor - "implementations MUST use the highest
     * available sending epoch" is the whole rule - and a protected ACK from a peer whose own sending epoch is
     * below ours is exactly what a post-handshake KeyUpdate draws. Discarding those record numbers would
     * leave the KeyUpdate unretired and its sender retransmitting forever, so a protected ACK is taken as it
     * stands.
     * <p>
     * The epoch-0 defence is untouched: an unprotected ACK is still filtered, and it is the only epoch an
     * attacker can write at.
     * </p>
     */
    public void testAckRecordNumbersAboveTheAckEpochSurviveAfterTheHandshake() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        int ackEpoch = support.server.recordLayer.getReadEpoch();

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(ackEpoch, 7));
        recordNumbers.addElement(new DTLSRecordNumber(ackEpoch + 1, 0));

        byte[] body = DTLSAck.encode(recordNumbers);
        support.client.recordLayer.sendRecordForTest(ContentType.ack, body, 0, body.length);

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals(1, listener.received.size());

        Vector got = (Vector)listener.received.elementAt(0);
        assertEquals("a protected post-handshake ACK is delivered as it stands", 2, got.size());
        assertEquals(new DTLSRecordNumber(ackEpoch + 1, 0), got.elementAt(1));
    }

    /**
     * The same rule on the sending side, and it is likewise a handshake-time one: rather than emit an ACK
     * below the epoch of the records it covers, send none.
     */
    public void testAckIsNotSentBelowTheEpochOfTheRecordsItAcknowledgesDuringTheHandshake() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        support.client.recordLayer.inHandshake = true;

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(support.client.recordLayer.getReadEpoch() + 1, 0));

        assertNull("no ACK is sent below the epoch it covers",
            support.client.recordLayer.sendAck(recordNumbers));

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals("nothing reached the peer", 0, listener.received.size());
    }

    /**
     * RFC 9147 7. "After the handshake, implementations MUST use the highest available sending epoch", with
     * no floor set by the record being acknowledged. The two directions' epochs advance on their own key
     * updates, so a peer that has updated its sending keys while we have not must still be acknowledged -
     * from below its epoch, at the highest epoch we have.
     * <p>
     * Mutation this test is built to catch: apply the handshake-time floor unconditionally in
     * {@code sendAck} and no ACK is sent.
     * </p>
     */
    public void testAckIsSentAtTheHighestSendingEpochAfterTheHandshake() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        int writeEpoch = support.client.recordLayer.getWriteEpoch();

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(writeEpoch + 1, 0));

        DTLSRecordNumber sent = support.client.recordLayer.sendAck(recordNumbers);
        assertNotNull("an ACK must still be sent from below the epoch it covers", sent);
        assertEquals("at the highest epoch we have", writeEpoch, sent.getEpoch());

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals("and it reached the peer", 1, listener.received.size());
    }

    public void testSendAckRequiresDTLS13() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        DTLSRecordLayer layer = support.setUpLegacyLayer();

        try
        {
            layer.sendAck(new Vector());
            fail("expected internal_error for an ACK outside DTLS 1.3");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
    }

    /**
     * RFC 9147 4.1 lists ack(26) among the content types of a DTLSPlaintext record, and section 7 has a peer
     * with no protected epoch to send in yet - one that has received part of a fragmented ClientHello or
     * ServerHello - acknowledge it at epoch 0. A record layer that only recognises ACK inside a DTLSCiphertext
     * record drops every such acknowledgement unread and retransmits the whole flight on its timer instead.
     * <p>
     * The receiving side is a DTLS 1.3 record layer still reading at epoch 0, as a server is between its
     * ServerHello flight and the client's first protected record, and the ACK arrives as a plaintext record.
     * The epoch-0 filter still applies: a record number above the ACK's own epoch is discarded from it.
     * </p>
     */
    public void testPlaintextAckAtEpochZeroIsDelivered() throws Exception
    {
        TlsCrypto crypto = new BcTlsCrypto();
        DTLSRecordLayer13TestSupport.Queue c2s = new DTLSRecordLayer13TestSupport.Queue();
        DTLSRecordLayer13TestSupport.Queue s2c = new DTLSRecordLayer13TestSupport.Queue();
        AbstractTlsContext context = TlsAEADCipherDTLS13Test.createContext(crypto, true,
            CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, new byte[32], new byte[32]);
        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };
        DTLSRecordLayer serverLayer = new DTLSRecordLayer(context, peer,
            new DTLSRecordLayer13TestSupport.QueueTransport(c2s, s2c));
        serverLayer.setWriteVersion(ProtocolVersion.DTLSv12);
        serverLayer.setReadVersion(ProtocolVersion.DTLSv12);

        RecordingAckListener listener = new RecordingAckListener();
        serverLayer.setAckListener(listener);

        // Puts the record layer into DTLS 1.3 mode (dtls13 == true) without moving the read epoch off epoch 0.
        serverLayer.initPendingEpoch(TlsUtils.initCipher(context));
        assertEquals(0, serverLayer.getReadEpoch());

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(0, 7));
        // above the ACK's own epoch: discarded by the epoch-0 filter, not delivered
        recordNumbers.addElement(new DTLSRecordNumber(2, 1));
        byte[] body = DTLSAck.encode(recordNumbers);

        // RFC 9147 4. DTLSPlaintext: type, legacy_record_version, epoch, sequence_number, length
        byte[] record = new byte[13 + body.length];
        record[0] = (byte)ContentType.ack;
        TlsUtils.writeVersion(ProtocolVersion.DTLSv12, record, 1);
        TlsUtils.writeUint16(0, record, 3);
        TlsUtils.writeUint48(3, record, 5);
        TlsUtils.writeUint16(body.length, record, 11);
        System.arraycopy(body, 0, record, 13, body.length);
        c2s.put(record);

        byte[] buf = new byte[serverLayer.getReceiveLimit()];
        assertEquals("an ACK carries no application data", -1, serverLayer.receive(buf, 0, buf.length, 500));

        assertEquals("the plaintext ACK must be delivered to the listener", 1, listener.received.size());
        Vector delivered = (Vector)listener.received.elementAt(0);
        assertEquals("only the epoch-0 record number survives the epoch-0 filter", 1, delivered.size());
        assertEquals(new DTLSRecordNumber(0, 7), delivered.elementAt(0));
    }

    /**
     * The counterpart: before DTLS 1.3 has been selected nothing sends ACKs (RFC 9147 7, and
     * draft-ietf-tls-rfc9147bis makes the receiver ignore any that arrive), so a plaintext ACK reaching a
     * record layer that is not yet in DTLS 1.3 mode is discarded like any unknown content type.
     */
    public void testPlaintextAckBeforeDTLS13IsSelectedIsIgnored() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        DTLSRecordLayer legacyLayer = support.setUpLegacyLayer();

        RecordingAckListener listener = new RecordingAckListener();
        legacyLayer.setAckListener(listener);

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(0, 1));
        byte[] body = DTLSAck.encode(recordNumbers);

        byte[] record = new byte[13 + body.length];
        record[0] = (byte)ContentType.ack;
        TlsUtils.writeVersion(ProtocolVersion.DTLSv12, record, 1);
        TlsUtils.writeUint16(0, record, 3);
        TlsUtils.writeUint48(0, record, 5);
        TlsUtils.writeUint16(body.length, record, 11);
        System.arraycopy(body, 0, record, 13, body.length);

        support.deliverToLegacyLayer(record);

        byte[] buf = new byte[legacyLayer.getReceiveLimit()];
        assertEquals(-1, legacyLayer.receive(buf, 0, buf.length, 500));
        assertEquals("no ACK may be processed before DTLS 1.3 is selected", 0, listener.received.size());
    }
}

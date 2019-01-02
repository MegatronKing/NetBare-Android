/*  NetBare - An android network capture and injection library.
 *  Copyright (C) 2018-2019 Megatron King
 *  Copyright (C) 2018-2019 GuoShi
 *
 *  NetBare is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  NetBare is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE. See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with NetBare.
 *  If not, see <http://www.gnu.org/licenses/>.
 */
package com.github.megatronking.netbare.ssl;

import com.github.megatronking.netbare.NetBareLog;

import java.nio.ByteBuffer;

/**
 * A SSL utils class.
 *
 * @author Megatron King
 * @since 2018-11-14 11:38
 */
public final class SSLUtils {

    /**
     * Change cipher spec.
     */
    public static final int SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;

    /**
     * Alert.
     */
    public static final int SSL_CONTENT_TYPE_ALERT = 21;

    /**
     * Handshake.
     */
    public static final int SSL_CONTENT_TYPE_HANDSHAKE = 22;

    /**
     * Application data.
     */
    public static final int SSL_CONTENT_TYPE_APPLICATION_DATA = 23;

    /**
     * HeartBeat Extension.
     */
    public static final int SSL_CONTENT_TYPE_EXTENSION_HEARTBEAT = 24;

    /**
     * The length of the ssl record header (in bytes).
     */
    private static final int SSL_RECORD_HEADER_LENGTH = 5;

    /**
     * Packet length is not enough to determine.
     */
    public static final int PACKET_NOT_ENOUGH = 1;

    /**
     * It is a plaintext packet.
     */
    public static final int PACKET_NOT_ENCRYPTED = 2;

    /**
     * It is a valid SSL packet.
     */
    public static final int PACKET_SSL = 3;

    /**
     * Verify a packet to see whether it is a valid SSL packet.
     *
     * @param buffer Encrypted SSL packet.
     * @return Verification result, one of {@link #PACKET_NOT_ENOUGH}, {@link #PACKET_NOT_ENCRYPTED},
     * and {@link #PACKET_SSL}.
     */
    public static int verifyPacket(ByteBuffer buffer) {
        final int position = buffer.position();
        // Get the packet length and wait until we get a packets worth of data to unwrap.
        if (buffer.remaining() < SSL_RECORD_HEADER_LENGTH) {
            NetBareLog.w("No enough ssl/tls packet length: " + buffer.remaining());
            return PACKET_NOT_ENOUGH;
        }
        int packetLength = 0;
        // SSLv3 or TLS - Check ContentType
        boolean tls;
        switch (unsignedByte(buffer, position)) {
            case SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            case SSL_CONTENT_TYPE_ALERT:
            case SSL_CONTENT_TYPE_HANDSHAKE:
            case SSL_CONTENT_TYPE_APPLICATION_DATA:
            case SSL_CONTENT_TYPE_EXTENSION_HEARTBEAT:
                tls = true;
                break;
            default:
                // SSLv2 or bad data
                tls = false;
        }
        if (tls) {
            // SSLv3 or TLS - Check ProtocolVersion
            int majorVersion = unsignedByte(buffer, position + 1);
            if (majorVersion == 3) {
                // SSLv3 or TLS
                packetLength = unsignedShort(buffer, position + 3) + SSL_RECORD_HEADER_LENGTH;
                if (packetLength <= SSL_RECORD_HEADER_LENGTH) {
                    // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
                    tls = false;
                }
            } else {
                // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
                tls = false;
            }
        }
        if (!tls) {
            // SSLv2 or bad data - Check the version
            int headerLength = (unsignedByte(buffer, position) & 0x80) != 0 ? 2 : 3;
            int majorVersion = unsignedByte(buffer, position + headerLength + 1);
            if (majorVersion == 2 || majorVersion == 3) {
                // SSLv2
                packetLength = headerLength == 2 ?
                        (buffer.getShort(position) & 0x7FFF) + 2 : (buffer.getShort(position) & 0x3FFF) + 3;
                if (packetLength <= headerLength) {
                    NetBareLog.w("No enough ssl/tls packet length, packet: " + packetLength +
                            " header: " + headerLength);
                    // No enough data.
                    return PACKET_NOT_ENOUGH;
                }
            } else {
                // Not encrypted
                return PACKET_NOT_ENCRYPTED;
            }
        }
        // Decode SSL data.
        if (packetLength > buffer.remaining()) {
            NetBareLog.w("No enough ssl/tls packet length, packet: " + packetLength +
                    " actual: " + buffer.remaining());
            // Wait until the whole packet can be read.
            return PACKET_NOT_ENOUGH;
        }
        return PACKET_SSL;
    }

    private static int unsignedByte(ByteBuffer buffer, int index) {
        return buffer.get(index) & 0x0FF;
    }

    private static int unsignedShort(ByteBuffer buffer, int index) {
        return buffer.getShort(index) & 0x0FFFF;
    }

}

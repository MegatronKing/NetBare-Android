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
package com.github.megatronking.netbare.ip.header;

import java.nio.ByteBuffer;
import java.util.Locale;

/**
 * The UDP module  must be able to determine the source and destination internet addresses and
 * the protocol field from the internet header.
 *
 * UDP Header Format:
 *
 * 0      7 8     15 16    23 24    31
 * +--------+--------+--------+--------+
 * |     Source      |   Destination   |
 * |      Port       |      Port       |
 * +--------+--------+--------+--------+
 * |                 |                 |
 * |     Length      |    Checksum     |
 * +--------+--------+--------+--------+
 * |
 * |          data octets ...
 * +---------------- ...
 *
 * See https://tools.ietf.org/html/rfc768
 *
 * @author Megatron King
 * @since 2018-10-10 23:04
 */
public class UdpHeader extends Header {

    private static final short OFFSET_SRC_PORT = 0;
    private static final short OFFSET_DEST_PORT = 2;
    private static final short OFFSET_TOTAL_LENGTH = 4;
    private static final short OFFSET_CRC = 6;

    public UdpHeader(ByteBuffer packet, int offset) {
        super(packet, offset);
    }

    public short getSourcePort() {
        return getBuffer().getShort(offset + OFFSET_SRC_PORT);
    }

    public void setSourcePort(short port) {
        getBuffer().putShort(offset + OFFSET_SRC_PORT, port);
    }

    public short getDestinationPort() {
        return getBuffer().getShort(offset + OFFSET_DEST_PORT);
    }

    public void setDestinationPort(short port) {
        getBuffer().putShort(offset + OFFSET_DEST_PORT, port);
    }

    public short getCrc() {
        return getBuffer().getShort(offset + OFFSET_CRC);
    }

    public void setCrc(short crc) {
        getBuffer().putShort(offset + OFFSET_CRC, crc);
    }

    public char getHeaderLength() {
        return 8;
    }

    public short getTotalLength() {
        return getBuffer().getShort(offset + OFFSET_TOTAL_LENGTH);
    }

    public void setTotalLength(short length) {
        getBuffer().putShort(offset + OFFSET_TOTAL_LENGTH, length);
    }

    public void updateChecksum(IpHeader ipHeader) {
        setCrc((short) 0);
        setCrc(computeChecksum(ipHeader));
    }

    private short computeChecksum(IpHeader ipHeader) {
        // Sum = Ip Sum(Source Address + Destination Address) + Protocol + UDP Length
        // Checksum is the 16-bit one's complement of the one's complement sum of a
        // pseudo header of information from the IP header, the UDP header, and the
        // data,  padded  with zero octets  at the end (if  necessary)  to  make  a
        // multiple of two octets.
        short dataLength = ipHeader.getDataLength();
        long sum = ipHeader.getIpSum();
        sum += ipHeader.getProtocol() & 0xFF;
        sum += dataLength & 0xFFFF;
        sum += getSum(offset, dataLength);
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

    @Override
    public String toString() {
        return String.format(Locale.getDefault(), "%d -> %d", getSourcePort() & 0xFFFF,
                getDestinationPort() & 0xFFFF);
    }
}

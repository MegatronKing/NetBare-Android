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
 * TCP segments are sent as internet datagrams. The Internet Protocol header carries several
 * information fields, including the source and destination host addresses. A TCP header follows
 * the internet header, supplying information specific to the TCP protocol. This division allows
 * for the existence of host level protocols other than TCP.
 *
 * TCP Header Format:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * See https://tools.ietf.org/html/rfc793#section-3.1
 *
 * @author Megatron King
 * @since 2018-10-10 22:19
 */
public class TcpHeader extends Header {

    private static final int OFFSET_SRC_PORT = 0;
    private static final int OFFSET_DEST_PORT = 2;
    private static final int OFFSET_LENRES = 12;
    private static final int OFFSET_CRC = 16;
    private static final int OFFSET_FLAG = 13;
    private static final int OFFSET_SEQ = 4;
    private static final int OFFSET_ACK = 8;

    private static final int FIN = 1;
    private static final int SYN = 2;
    private static final int RST = 4;
    private static final int PSH = 8;
    private static final int ACK = 16;
    private static final int URG = 32;

    public TcpHeader(ByteBuffer packet, int offset) {
    	super(packet, offset);
	}

    public void setOffset(int offset) {
        this.offset = offset;
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

    public char getHeaderLength() {
        char length = getBuffer().getChar(offset + OFFSET_LENRES);
        return (char) (length >> 4 << 2);
    }

    public short getCrc() {
        return getBuffer().getShort(offset + OFFSET_CRC);
    }

    public void setCrc(short crc) {
        getBuffer().putShort(offset + OFFSET_CRC, crc);
    }

    public byte getFlag() {
        return getBuffer().get(OFFSET_FLAG);
    }

    public int getSeqID() {
        return getBuffer().getInt(offset + OFFSET_SEQ);
    }

    public int getAckID() {
        return getBuffer().getInt(offset + OFFSET_ACK);
    }

    public void updateChecksum(IpHeader ipHeader) {
        setCrc((short) 0);
        setCrc(computeChecksum(ipHeader));
    }

    private short computeChecksum(IpHeader ipHeader) {
        // Sum = Ip Sum(Source Address + Destination Address) + Protocol + TCP Length
        // The checksum field is the 16 bit one's complement of the one's complement sum of all 16
        // bit words in the header and text.
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
        return String.format(Locale.getDefault(), "%s%s%s%s%s%s %d -> %d %s:%s",
                (getFlag() & SYN) == SYN ? "SYN" : "",
                (getFlag() & ACK) == ACK ? "ACK" : "",
                (getFlag() & PSH) == PSH ? "PSH" : "",
                (getFlag() & RST) == RST ? "RST" : "",
                (getFlag() & FIN) == FIN ? "FIN" : "",
                (getFlag() & URG) == URG ? "URG" : "",
                getSourcePort() & 0xFFFF,
                getDestinationPort() & 0xFFFF,
                getSeqID(),
                getAckID());
    }

}

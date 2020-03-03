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

/**
 * ICMP messages are sent using the basic IP header. The first octet of the data portion of the
 * datagram is a ICMP type field; the value of this field determines the format of the remaining
 * data. Any field labeled "unused" is reserved for later extensions and must be zero when sent,
 * but receivers should not use these fields (except to include them in the checksum).
 * Unless otherwise noted under the individual format descriptions, the values of the internet
 * header fields are as follows:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              TBD                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            Optional                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * See https://tools.ietf.org/html/rfc792
 *
 * @author Megatron King
 * @since 2018-10-10 23:04
 */
public class IcmpHeader extends Header {

    private static final short OFFSET_TYPE = 0;
    private static final short OFFSET_CODE = 1;
    private static final short OFFSET_CRC = 2;

    private IpHeader mIpHeader;

    public IcmpHeader(IpHeader header, ByteBuffer packet, int offset) {
        super(packet, offset);
        mIpHeader = header;
    }

    public IpHeader getIpHeader() {
        return mIpHeader;
    }

    public byte getType() {
        return getBuffer().get(offset + OFFSET_TYPE);
    }

    public byte getCode() {
        return getBuffer().get(offset + OFFSET_CODE);
    }

    public short getCrc() {
        return getBuffer().getShort(offset + OFFSET_CRC);
    }

    public void setCrc(short crc) {
        getBuffer().putShort(offset + OFFSET_CRC, crc);
    }

    public void updateChecksum() {
        setCrc((short) 0);
        setCrc(computeChecksum());
    }

    private short computeChecksum() {
        short dataLength = mIpHeader.getDataLength();
        long sum = mIpHeader.getIpSum();
        sum += mIpHeader.getProtocol() & 0xFF;
        sum += dataLength & 0xFFFF;
        sum += getSum(offset, dataLength);
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

}

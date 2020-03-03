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
 * An abstract header object for ip protocol packets, provides some common apis.
 *
 * @author Megatron King
 * @since 2018-10-09 16:28
 */
/* package */ abstract class Header {

    private ByteBuffer buffer;
    int offset;

    public Header(ByteBuffer packet, int offset) {
        this.buffer = packet;
        this.offset = offset;
    }

    public long getSum(int offset, int len) {
        long sum = 0;
        while (len > 1) {
            sum += getBuffer().getShort(offset) & 0xFFFF;
            offset += 2;
            len -= 2;
        }

        if (len > 0) {
            sum += (getBuffer().get(offset) & 0xFF) << 8;
        }
        return sum;
    }

	public ByteBuffer getBuffer() {
		return buffer;
	}
}

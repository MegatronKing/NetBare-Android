package com.github.megatronking.netbare.ip.packet;

import com.github.megatronking.netbare.ip.header.IpHeader;
import com.github.megatronking.netbare.ip.header.UdpHeader;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class UdpPacket extends Packet{
	private IpHeader ipHeader;
	private UdpHeader udpHeader;

	public UdpPacket(ByteBuffer buffer) {
		super(buffer);
		ipHeader = new IpHeader(getBuffer(), 0);
		udpHeader = new UdpHeader(getBuffer(), ipHeader.getHeaderLength());
	}

	public IpHeader getIpHeader() {
		return ipHeader;
	}

	public UdpHeader getUdpHeader() {
		return udpHeader;
	}

	public ByteBuffer getData() {
		int size = ipHeader.getDataLength() & 0xFFFF - udpHeader.getHeaderLength();
		int dataOffset = ipHeader.getHeaderLength() + udpHeader.getHeaderLength();
		byte[] data = new byte[size];
		System.arraycopy(getBuffer().array(), dataOffset, data, 0, size);
		return ByteBuffer.wrap(data);
	}

	@Override
	public UdpPacket clone() {
		return new UdpPacket(ByteBuffer.wrap(Arrays.copyOf(getBuffer().array(), getBuffer().limit())));
	}

	public short getHeaderLength() {
		return (short) (getIpHeader().getHeaderLength() + getUdpHeader().getHeaderLength());
	}

	public void updateChecksum() {
		ipHeader.updateChecksum();
		udpHeader.updateChecksum(ipHeader);
	}
}

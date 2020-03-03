package com.github.megatronking.netbare.ip.packet;

import java.nio.ByteBuffer;

public class Packet {
	private ByteBuffer buffer;

	public Packet(ByteBuffer buffer) {
		this.buffer = buffer;
	}

	public ByteBuffer getBuffer() {
		return buffer;
	}
}

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
package com.github.megatronking.netbare.http2;

import android.support.annotation.NonNull;

import com.github.megatronking.netbare.NetBareXLog;
import com.github.megatronking.netbare.http.HttpId;
import com.github.megatronking.netbare.http.HttpPendingInterceptor;
import com.github.megatronking.netbare.http.HttpProtocol;
import com.github.megatronking.netbare.http.HttpRequest;
import com.github.megatronking.netbare.http.HttpRequestChain;
import com.github.megatronking.netbare.http.HttpResponse;
import com.github.megatronking.netbare.http.HttpResponseChain;
import com.github.megatronking.netbare.http.HttpZygoteRequest;
import com.github.megatronking.netbare.http.HttpZygoteResponse;
import com.github.megatronking.netbare.http.SSLRefluxCallback;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decodes HTTP2 request and response packets.
 *
 * @author Megatron King
 * @since 2019/1/5 14:19
 */
public final class Http2DecodeInterceptor extends HttpPendingInterceptor {

    private final SSLRefluxCallback mRefluxCallback;

    private final HttpZygoteRequest mZygoteRequest;
    private final HttpZygoteResponse mZygoteResponse;

    private final Map<Integer, HttpId> mHttpIds;

    private final Http2Stream mRequestStream;
    private final Http2Stream mResponseStream;

    private Hpack.Reader mHpackReader;

    public Http2DecodeInterceptor(SSLRefluxCallback refluxCallback, HttpZygoteRequest zygoteRequest,
                                  HttpZygoteResponse zygoteResponse) {
        this.mRefluxCallback = refluxCallback;

        this.mZygoteRequest = zygoteRequest;
        this.mZygoteResponse = zygoteResponse;

        this.mHttpIds = new ConcurrentHashMap<>();

        this.mRequestStream = new Http2Stream();
        this.mResponseStream = new Http2Stream();
    }

    private NetBareXLog mLog;

    @Override
    protected void intercept(@NonNull final HttpRequestChain chain, @NonNull ByteBuffer buffer,
                             int index) throws IOException {
        if (chain.request().httpProtocol() == HttpProtocol.HTTP_2) {
            if (mLog == null) {
                HttpRequest request = chain.request();
                mLog = new NetBareXLog(request.protocol(), request.ip(), request.port());
            }
            if (index == 0) {
                // Send connection preface to peer.
                ByteBuffer preface = ByteBuffer.allocate(Http2.CONNECTION_PREFACE.length);
                preface.put(Http2.CONNECTION_PREFACE);
                preface.flip();
                mRefluxCallback.onRequest(chain.request(), preface);
            }
            if (!buffer.hasRemaining()) {
                return;
            }
            decode(mergeRequestBuffer(buffer), new DecodeCallback() {

                @Override
                public void onPending(ByteBuffer buffer) {
                    pendRequestBuffer(buffer);
                }

                @Override
                public void onResult(ByteBuffer buffer) throws IOException {
                    int streamId = mRequestStream.id;
                    if (streamId >= 0) {
                        HttpId id = mHttpIds.get(streamId);
                        if (id == null) {
                            id = new HttpId(streamId);
                            mHttpIds.put(streamId, id);
                        }
                        mZygoteRequest.zygote(id);
                    }
                    chain.process(buffer);
                }

                @Override
                public void onSkip(ByteBuffer buffer) throws IOException {
                    mRefluxCallback.onRequest(chain.request(), buffer);
                }

            }, mRequestStream, mZygoteRequest);
        } else {
            chain.process(buffer);
        }
    }

    @Override
    protected void intercept(@NonNull final HttpResponseChain chain, @NonNull ByteBuffer buffer,
                             int index)
            throws IOException {
        if (chain.response().httpProtocol() == HttpProtocol.HTTP_2) {
            if (mLog == null) {
                HttpResponse response = chain.response();
                mLog = new NetBareXLog(response.protocol(), response.ip(), response.port());
            }
            if (!buffer.hasRemaining()) {
                return;
            }
            decode(mergeResponseBuffer(buffer), new DecodeCallback() {

                @Override
                public void onPending(ByteBuffer buffer) {
                    pendResponseBuffer(buffer);
                }

                @Override
                public void onResult(ByteBuffer buffer) throws IOException {
                    int streamId = mResponseStream.id;
                    if (streamId >= 0) {
                        HttpId id = mHttpIds.get(streamId);
                        if (id == null) {
                            id = new HttpId(streamId);
                            mHttpIds.put(streamId, id);
                        }
                        mZygoteResponse.zygote(id);
                    }
                    chain.process(buffer);
                }

                @Override
                public void onSkip(ByteBuffer buffer) throws IOException {
                    mRefluxCallback.onResponse(chain.response(), buffer);
                }

            }, mResponseStream, mZygoteResponse);
        } else {
            chain.process(buffer);
        }
    }

    private void decode(ByteBuffer buffer, DecodeCallback callback, Http2Stream stream,
                        Http2SettingsReceiver receiver)
            throws IOException {
        // HTTP2 frame structure
        //  0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                 Length (24)                   |
        // +---------------+---------------+---------------+
        // |   Type (8)    |   Flags (8)   |
        // +-+-+-----------+---------------+-------------------------------+
        // |R|                 Stream Identifier (31)                      |
        // +=+=============================================================+
        // |                   Frame Payload (0...)                      ...
        // +---------------------------------------------------------------+
        if (buffer.remaining() < Http2.FRAME_HEADER_LENGTH) {
            callback.onPending(buffer);
            return;
        }
        int length = readMedium(buffer);
        if (length < 0 || length > Http2.INITIAL_MAX_FRAME_SIZE) {
            // Values greater than 214 (16,384) MUST NOT be sent unless the receiver has set a
            // larger value for SETTINGS_MAX_FRAME_SIZE.
            throw new IOException("Http2 frame size error: " + length);
        }
        // Check payload length
        if (length + 6 > buffer.remaining()) {
            mLog.w("No enough http2 frame length, expect: %d actual: %d", length,
                    buffer.remaining() - 6);
            // Packet not enough for one frame, wait next packet.
            // Revert position.
            buffer.position(buffer.position() - 3);
            callback.onPending(buffer);
            return;
        } else if (length + 6 < buffer.remaining()) {
            mLog.w("Multi http2 frames in one buffer, first frame length : %d, buffer length: %d",
                    length + 9, buffer.remaining() + 3);
            // Separate multi-frames
            ByteBuffer newBuffer = ByteBuffer.allocate(length + 9);
            newBuffer.put(buffer.array(), buffer.position() - 3, newBuffer.capacity());
            newBuffer.flip();
            decode(newBuffer, callback, stream, receiver);
            // Process the left data
            buffer.position(buffer.position() + length + 6);
            decode(buffer, callback, stream, receiver);
            return;
        }

        byte type = (byte) (buffer.get() & 0xff);
        byte flags = (byte) (buffer.get() & 0xff);
        int streamId = buffer.getInt() & 0x7fffffff;
        FrameType frameType = FrameType.parse(type);
        if (frameType == null) {
            mLog.e("Unexpected http2 frame type: " + type);
            // Discard frames that have unknown or unsupported types.
            return;
        }
        if (stream.id != -1) {
            if (streamId != stream.id && frameType == FrameType.CONTINUATION) {
                throw new IOException("Http2 TYPE_CONTINUATION streamId changed!");
            }
        }
        mLog.i("Decode a http2 frame: " + frameType + " stream(" + streamId +
                ") length(" + length + ")");
        stream.id = streamId;
        switch (frameType) {
            case DATA:
                decodeData(buffer, length, flags, streamId, callback);
                break;
            case HEADERS:
            case CONTINUATION:
                decodeHeaders(buffer, length, flags, streamId, callback);
                break;
            case SETTINGS:
                decodeSettings(buffer, length, flags, streamId, receiver);
                // Do not break this.
            default:
                // Encrypt and send it to remote server directly.
                buffer.position(buffer.position() - Http2.FRAME_HEADER_LENGTH);
                callback.onSkip(buffer);
                break;
        }
    }

    private int readMedium(ByteBuffer buffer) {
        return (buffer.get() & 0xff) << 16
                | (buffer.get() & 0xff) << 8
                | (buffer.get() & 0xff);
    }

    private void decodeSettings(ByteBuffer buffer, int length, byte flags, int streamId,
                                Http2SettingsReceiver receiver)
            throws IOException {
        if (streamId != 0) {
            throw new IOException("Http2 TYPE_SETTINGS streamId != 0");
        }
        if ((flags & Http2.FLAG_ACK) != 0) {
            if (length != 0) {
                throw new IOException("Http2 FRAME_SIZE_ERROR ack frame should be empty!");
            }
            return;
        }
        if (length % 6 != 0) {
            throw new IOException("Http2 TYPE_SETTINGS length %% 6 != 0: " + length);
        }
        int initPosition = buffer.position();
        Http2Settings settings = new Http2Settings();
        for (int i = 0; i < length; i += 6) {
            int id = buffer.getShort() & 0xFFFF;
            int value = buffer.getInt();
            switch (id) {
                case 1: // SETTINGS_HEADER_TABLE_SIZE
                    break;
                case 2: // SETTINGS_ENABLE_PUSH
                    if (value != 0 && value != 1) {
                        throw new IOException("Http2 PROTOCOL_ERROR SETTINGS_ENABLE_PUSH != 0 or 1");
                    }
                    break;
                case 3: // SETTINGS_MAX_CONCURRENT_STREAMS
                    id = 4; // Renumbered in draft 10.
                    break;
                case 4: // SETTINGS_INITIAL_WINDOW_SIZE
                    id = 7; // Renumbered in draft 10.
                    if (value < 0) {
                        throw new IOException("Http2 PROTOCOL_ERROR SETTINGS_INITIAL_WINDOW_SIZE > 2^31 - 1");
                    }
                    break;
                case 5: // SETTINGS_MAX_FRAME_SIZE
                    if (value < Http2.INITIAL_MAX_FRAME_SIZE || value > 16777215) {
                        throw new IOException("Http2 PROTOCOL_ERROR SETTINGS_MAX_FRAME_SIZE: " + value);
                    }
                    break;
                case 6: // SETTINGS_MAX_HEADER_LIST_SIZE
                    break; // Advisory only, so ignored.
                default:
                    break; // Must ignore setting with unknown id.
            }
            settings.set(id, value);
        }
        // Reverse the position and sent to terminal.
        buffer.position(initPosition);
        receiver.onSettingsUpdate(settings);
    }

    private void decodeHeaders(ByteBuffer buffer, int length, byte flags, int streamId,
                               DecodeCallback callback) throws IOException {
        // +---------------+
        // |Pad Length? (8)|
        // +-+-------------+-----------------------------------------------+
        // |E|                 Stream Dependency? (31)                     |
        // +-+-------------+-----------------------------------------------+
        // |  Weight? (8)  |
        // +-+-------------+-----------------------------------------------+
        // |                   Header Block Fragment (*)                 ...
        // +---------------------------------------------------------------+
        // |                           Padding (*)                       ...
        // +---------------------------------------------------------------+
        if (streamId == 0) {
            throw new IOException("Http2 PROTOCOL_ERROR: TYPE_HEADERS streamId == 0");
        }
        short padding = (flags & Http2.FLAG_PADDED) != 0 ? (short) (buffer.get() & 0xff) : 0;
        if ((flags & Http2.FLAG_PRIORITY) != 0) {
            // Skip priority.
            buffer.position(buffer.position() + 5);
        }
        length = lengthWithoutPadding(length, flags, padding);
        if (length > 0) {
            decodeHeaderBlock(buffer, flags, callback);
        }
        if ((flags & Http2.FLAG_END_STREAM) != 0) {
            mLog.i("End the http2 stream with no body : " + streamId);
            // Use an empty data frame to end the stream.
            callback.onSkip(endStream(FrameType.DATA, streamId));
        }
    }

    private void decodeHeaderBlock(ByteBuffer buffer, byte flags,
                                   DecodeCallback callback) throws IOException {
        if (mHpackReader == null) {
            mHpackReader = new Hpack.Reader();
        }
        try {
            mHpackReader.readHeaders(buffer, (flags & Http2.FLAG_END_HEADERS) != 0, callback);
        } catch (IndexOutOfBoundsException e) {
            throw new IOException("Http2 decode header block failed.");
        }
    }

    private void decodeData(ByteBuffer buffer, int length, byte flags, int streamId,
                            DecodeCallback callback) throws IOException {
        if (streamId == 0) {
            throw new IOException("Http2 PROTOCOL_ERROR: TYPE_DATA streamId == 0");
        }
        boolean gzipped = (flags & Http2.FLAG_COMPRESSED) != 0;
        if (gzipped) {
            throw new IOException("Http2 PROTOCOL_ERROR: FLAG_COMPRESSED without SETTINGS_COMPRESS_DATA");
        }
        short padding = (flags & Http2.FLAG_PADDED) != 0 ? (short) (buffer.get() & 0xff) : 0;
        length = lengthWithoutPadding(length, flags, padding);
        if (length > 0) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(buffer.array(), buffer.position(), length);
            callback.onResult(ByteBuffer.wrap(os.toByteArray()));
        }
        if ((flags & Http2.FLAG_END_STREAM) != 0) {
            mLog.i("End the http2 stream : " + streamId);
            callback.onSkip(endStream(FrameType.DATA, streamId));
        }
    }

    private int lengthWithoutPadding(int length, byte flags, short padding) throws IOException {
        if ((flags & Http2.FLAG_PADDED) != 0) {
            length--; // Account for reading the padding length.
        }
        if (padding > length) {
            throw new IOException("Http2 PROTOCOL_ERROR padding " + padding + " > remaining length " + length);
        }
        return (short) (length - padding);
    }

    private ByteBuffer endStream(FrameType frameType, int streamId) {
        ByteBuffer endBuffer = ByteBuffer.allocate(Http2.FRAME_HEADER_LENGTH);
        endBuffer.put((byte) 0);
        endBuffer.put((byte) 0);
        endBuffer.put((byte) 0);
        endBuffer.put((byte) (frameType.get() & 0xff));
        endBuffer.put((byte) (Http2.FLAG_END_STREAM & 0xff));
        endBuffer.putInt(streamId & 0x7fffffff);
        endBuffer.flip();
        return endBuffer;
    }

}

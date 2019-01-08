package com.github.megatronking.netbare.http2;

import java.util.Arrays;

/**
 * Http/2 peer settings.
 *
 * @author Megatron King
 * @since 2019/1/6 23:14
 */
public final class Http2Settings {

    /**
     * From the HTTP/2 specs, the default initial window size for all streams is 64 KiB. (Chrome 25
     * uses 10 MiB).
     */
    private static final int DEFAULT_INITIAL_WINDOW_SIZE = 65535;

    /**
     * HTTP/2: Size in bytes of the table used to decode the sender's header blocks.
     */
    private static final int HEADER_TABLE_SIZE = 1;
    /**
     * HTTP/2: The peer must not send a PUSH_PROMISE frame when this is 0.
     */
    private static final int ENABLE_PUSH = 2;

    /**
     * Sender's maximum number of concurrent streams.
     */
    private static final int MAX_CONCURRENT_STREAMS = 4;

    /**
     * HTTP/2: Size in bytes of the largest frame payload the sender will accept.
     */
    private static final int MAX_FRAME_SIZE = 5;

    /**
     * HTTP/2: Advisory only. Size in bytes of the largest header list the sender will accept.
     */
    private static final int MAX_HEADER_LIST_SIZE = 6;

    /**
     * Window size in bytes.
     */
    private static final int INITIAL_WINDOW_SIZE = 7;

    /**
     * Total number of settings.
     */
    private static final int COUNT = 10;

    /**
     * Bitfield of which flags that values.
     */
    private int set;

    /**
     * Flag values.
     */
    private final int[] values = new int[COUNT];

    void clear() {
        set = 0;
        Arrays.fill(values, 0);
    }

    Http2Settings set(int id, int value) {
        if (id < 0 || id >= values.length) {
            return this; // Discard unknown settings.
        }

        int bit = 1 << id;
        set |= bit;
        values[id] = value;
        return this;
    }

    boolean isSet(int id) {
        int bit = 1 << id;
        return (set & bit) != 0;
    }

    int get(int id) {
        return values[id];
    }

    int size() {
        return Integer.bitCount(set);
    }

    int getHeaderTableSize() {
        int bit = 1 << HEADER_TABLE_SIZE;
        return (bit & set) != 0 ? values[HEADER_TABLE_SIZE] : -1;
    }

    boolean getEnablePush(boolean defaultValue) {
        int bit = 1 << ENABLE_PUSH;
        return ((bit & set) != 0 ? values[ENABLE_PUSH] : defaultValue ? 1 : 0) == 1;
    }

    int getMaxConcurrentStreams(int defaultValue) {
        int bit = 1 << MAX_CONCURRENT_STREAMS;
        return (bit & set) != 0 ? values[MAX_CONCURRENT_STREAMS] : defaultValue;
    }

    int getMaxFrameSize(int defaultValue) {
        int bit = 1 << MAX_FRAME_SIZE;
        return (bit & set) != 0 ? values[MAX_FRAME_SIZE] : defaultValue;
    }

    int getMaxHeaderListSize(int defaultValue) {
        int bit = 1 << MAX_HEADER_LIST_SIZE;
        return (bit & set) != 0 ? values[MAX_HEADER_LIST_SIZE] : defaultValue;
    }

    int getInitialWindowSize() {
        int bit = 1 << INITIAL_WINDOW_SIZE;
        return (bit & set) != 0 ? values[INITIAL_WINDOW_SIZE] : DEFAULT_INITIAL_WINDOW_SIZE;
    }

}

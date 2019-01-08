package com.github.megatronking.netbare.http2;

/**
 * A receiver observes HTTP2 settings update.
 *
 * @author Megatron King
 * @since 2019/1/6 23:23
 */
public interface Http2SettingsReceiver {

    void onSettingsUpdate(Http2Settings http2Settings);

}

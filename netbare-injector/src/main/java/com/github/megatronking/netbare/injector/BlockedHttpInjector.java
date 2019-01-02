package com.github.megatronking.netbare.injector;

import android.support.annotation.NonNull;

import com.github.megatronking.netbare.http.HttpBody;
import com.github.megatronking.netbare.http.HttpRequest;
import com.github.megatronking.netbare.http.HttpRequestHeaderPart;
import com.github.megatronking.netbare.http.HttpResponse;
import com.github.megatronking.netbare.http.HttpResponseHeaderPart;

/**
 * An injector can block http request and response. Add your custom rules in
 * {@link #sniffRequest(HttpRequest)} or {@link #sniffResponse(HttpResponse)} to filter the request.
 *
 * @author Megatron King
 * @since 2019/1/2 20:50
 */
public abstract class BlockedHttpInjector implements HttpInjector {

    @Override
    public final void onRequestInject(@NonNull HttpRequestHeaderPart header,
                                @NonNull InjectorCallback callback) {
    }

    @Override
    public final void onResponseInject(@NonNull HttpResponseHeaderPart header,
                                 @NonNull InjectorCallback callback) {
    }

    @Override
    public final void onRequestInject(@NonNull HttpRequest request, @NonNull HttpBody body,
                                @NonNull InjectorCallback callback) {
    }

    @Override
    public final void onResponseInject(@NonNull HttpResponse response, @NonNull HttpBody body,
                                 @NonNull InjectorCallback callback) {
    }

    @Override
    public void onRequestFinished(@NonNull HttpRequest request) {
    }

    @Override
    public void onResponseFinished(@NonNull HttpResponse response) {
    }

}

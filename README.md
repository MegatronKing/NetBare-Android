# NetBare
NetBare是一款网络包拦截和注入框架，可以实现抓包、屏蔽包、改包等各种强大功能。NetBare核心是基于VPN技术，将网络包转发到本地代理服务器，再通过虚拟网关（VirtualGateway）进行拦截分发。在设计上，虚拟网关层是完全对外开放的，开发者可以自由定义虚拟网关，也可以使用NetBare内部已实现的虚拟网关进行网络包的处理。

## NetBare初始化
1. 在Application中绑定
```kotlin
NetBare.get().attachApplication(application, BuildConfig.DEBUG)
```

2. 创建自签证书（SSL需要）
```kotlin
val jks = JKS(context, alias, password, commonName, organization,
        organizationalUnitName, certOrganization, certOrganizationalUnitName)
```

3. 安装自签证书（SSL需要）
```kotlin
// 判断证书是否安装
JKS.isInstalled(context, alias)
// 安装证书
JKS.install(context, name, alias)
```

4. 创建NetBare服务。由于NetBare具有危险性，所以在设计上会强制要求在通知栏提示用户服务正在运行，同时要在Manifest中配置Service。
```kotlin
// 继承NetBareService创建自己应用的Service
class AppService : NetBareService() {
        override fun notificationId(): Int {
            // 通知栏ID
        }
        override fun createNotification(): Notification {
            // 创建一个Notification
        }
}
```
```xml
<service android:name=".AppService"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
                <action android:name="com.github.megatronking.netbare.action.Start"/>
                <action android:name="com.github.megatronking.netbare.action.Stop"/>
            </intent-filter>
</service>
```

5. NetBare服务的启动和停止
```kotlin
// 通过NetBareConfig自由配置NetBare服务并启动
NetBare.get().start(NetBareConfig)
// 停止NetBare服务
NetBare.get().stop()
```

## NetBareConfig配置

NetBareConfig需要使用NetBareConfig.Builder进行构造，解释下以下几个重要的配置方法。
- setMtu 最大传输单元，必要，建议大于2048。
- setAddress 本地代理服务器IP地址，必要，建议用A类IP地址，防止冲突。
- addRoute 设置经过VPN的目标IP包，必要，建议使用0.0.0.0，所有IP全部经过VPN。
- dumpUid 是否dump网络包所属的uid，可选，耗电方法，建议false
- setVirtualGatewayFactory 配置虚拟网关，可选。

NetBare框架提供了默认的NetBareConfig来快速集成：
```kotlin
// 创建默认的NetBareConfig，作用于所有IP协议
val config = NetBareConfig.defaultConfig()
// 为Http协议创建默认的NetBareConfig
val config = NetBareConfig.defaultHttpConfig(jks, interceptors)
```

## NetBare虚拟网关

虚拟网关是对网络包进行拦截、解析、注入的核心，可以加载开发者自定义的拦截器，通过NetBareConfig.Builder来配置。NetBare框架提供了两个默认的虚拟网关对象。

#### DefaultVirtualGateway
默认虚拟网关，可以拦截到所有协议的网络包。默认虚拟网关无法直接构造，需要通过DefaultVirtualGatewayFactory来进行构造。开发者可以使用NetBareConfig.setVirtualGatewayFactory配置默认虚拟网关工厂。
```kotlin
// 配置自定义拦截器
val interceptors = listOf(...)
//  创建默认虚拟网关工厂
val defaultGatewayFactory = DefaultVirtualGatewayFactory(interceptors)
// 通过NetBareConfig.Builder来配置defaultGatewayFactory
...
```
虚拟网关拦截器，继承Interceptor。Interceptor使用工厂模式，由InterceptorFactory来构造。
```kotlin
class TestIntercepter : Interceptor {

    @Throws(IOException::class)
    override fun intercept(chain: RequestChain, buffer: ByteBuffer) {
        // 对请求包进行自定义处理
        ...
        // 将请求发射出去，交给下个拦截器或者发给服务器
        chain.process(buffer)
    }

    @Throws(IOException::class)
    override fun intercept(chain: ResponseChain, buffer: ByteBuffer) {
        // 对响应包进行处理
        ...
        // 将响应发射出去，交给下个拦截器或者发给客户端
        chain.process(buffer)
    }

    override fun onRequestFinished(request: Request) {
        // 请求包已全部发送完成
    }

    override fun onResponseFinished(response: Response) {
        // 响应包已全部发送完成
    }
}
```


#### HttpVirtualGateway
Http协议虚拟网关，可以拦截到所有Http协议的网络包。Http协议虚拟网关也无法直接构造，需要通过HttpVirtualGatewayFactory来进行构造。创建HttpVirtualGatewayFactory实例需要前面的JKS以及拦截器HttpInterceptor。
```kotlin
// 配置自定义HttpInterceptor
val interceptors = listOf(...)
//  创建Http虚拟网关工厂
val httpGatewayFactory = HttpVirtualGatewayFactory(jks, interceptors)
// 通过NetBareConfig.Builder来配置httpGatewayFactory
...
```
Http虚拟网关拦截器，继承HttpInterceptor。同样的HttpInterceptor也使用工厂模式，由HttpInterceptorFactory来构造。

```kotlin
class TestHttpIntercepter : HttpInterceptor() {

    override fun intercept(chain: HttpRequestChain, buffer: ByteBuffer) {
        // 对Http请求包进行自定义处理
        ...
        // 将Http请求发射出去，交给下个拦截器或者发给服务器
        chain.process(buffer)
    }

    override fun intercept(chain: HttpResponseChain, buffer: ByteBuffer) {
        // 对Http响应包进行自定义处理
        ...
        // 将Http响应发射出去，交给下个拦截器或者发给客户端
        chain.process(buffer)
    }

    override fun onRequestFinished(request: HttpRequest) {
        // Http请求包已全部发送完成
    }

    override fun onResponseFinished(response: HttpResponse) {
        // Http响应包已全部发送完成
    }

}
```
此外，NetBare框架内置了HttpIndexInterceptor等特殊拦截器方便开发者使用。

## 注入器Injector
NetBare提供了一套通用的injector框架来方便开发者注入请求和响应。Injector框架是基于虚拟网关的拦截器来运行的。目前只开发了针对Http协议的注入器，其它协议可以后续再扩展。

Http协议的注入是基于HttpInjectInterceptor拦截器来实现的，在配置HttpVirtualGatewayFactory的时候，需要配置此拦截器，每一个注入器对应一个拦截器实例。而所有注入器都必须实现HttpInjector接口。
```kotlin
class TestHttpInjector : HttpInjector {

    override fun sniffRequest(request: HttpRequest): Boolean {
        // 对request进行判定，是否需要注入。true表示需要注入。
        return false
    }

    override fun sniffResponse(response: HttpResponse): Boolean {
        // 对response进行判定，是否需要注入。true表示需要注入。
        return false
    }

    @Throws(IOException::class)
    override fun onRequestInject(header: HttpRequestHeaderPart,
                                 callback: InjectorCallback) {
        // 当sniffRequest返回true时，会走到此方法。
        // 对请求头部进行注入，包括method、url、headers都可以修改
        ...
        // 将注入完成后将新的数据发射出去
        callback.onFinished(header)
    }

    @Throws(IOException::class)
    override fun onResponseInject(header: HttpResponseHeaderPart,
                                  callback: InjectorCallback) {
        // 当sniffResponse返回true时，会走到此方法。
        // 对响应头部进行注入，包括code、message、headers都可以修改
        ...
        // 将注入完成后将新的数据发射出去
        callback.onFinished(header)
    }

    @Throws(IOException::class)
    override fun onRequestInject(request: HttpRequest, body: HttpBody,
                                 callback: InjectorCallback) {
        // 当sniffRequest返回true时，会走到此方法。
        // 对请求体进行注入，如果请求体数据较大，会多次走到此方法。
        ...
        // 将注入完成后将新的数据发射出去
        callback.onFinished(body)
    }

    @Throws(IOException::class)
    override fun onResponseInject(response: HttpResponse, body: HttpBody,
                                  callback: InjectorCallback) {
        // 当sniffResponse返回true时，会走到此方法。
        // 对响应体进行注入，如果请求体数据较大，会多次走到此方法。
        ...
        // 将注入完成后将新的数据发射出去
        callback.onFinished(body)
    }

    override fun onRequestFinished(request: HttpRequest) {
        // Http请求包已全部发送完成
    }

    override fun onResponseFinished(response: HttpResponse) {
        // Http响应包已全部发送完成
    }
```
将注入器绑定到拦截器，并装载到虚拟网关中：
```kotlin
// 配置自定义HttpInjectInterceptor
val interceptor1 = HttpInjectInterceptor.createFactory(injector1)
val interceptor2 = HttpInjectInterceptor.createFactory(injector2)
...
val interceptors = listOf(interceptor1, interceptor2 ...)
//  创建Http虚拟网关工厂
val httpGatewayFactory = HttpVirtualGatewayFactory(jks, interceptors)
// 通过NetBareConfig.Builder来配置httpGatewayFactory
...
```

## NetBare范例
NetBare的接入步骤就有些繁琐，所以提供了一个简单的Sample工程供大家参考。sample中包含三个比较有趣的东西：
- 拦截器1：打印所有Http请求的URL。
- 注入器1：将百度首页的logo图片修改成自定义的图片。
- 注入器2：将发朋友圈的定位地点修改到珠峰。

![](https://github.com/MegatronKing/NetBare/blob/master/assets/sample1.png)
![](https://github.com/MegatronKing/NetBare/blob/master/assets/sample2.png)

## 结语
NetBare框架尚未完全成熟，仍然有很多工作要做，包括ICMP、IGMP等IP协议的转发等等，后续会继续完善。

基于NetBare实现的一款抓包+注入工具，欢迎大家下载体验：https://play.google.com/store/apps/details?id=com.guoshi.httpcanary

**声明：DON'T BE EVIL！NetBare只可用于学习和调试，禁止用于网络恶意攻击和钓鱼等非法途径**

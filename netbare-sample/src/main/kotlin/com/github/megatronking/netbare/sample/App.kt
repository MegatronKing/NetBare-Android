package com.github.megatronking.netbare.sample

import android.app.Application
import com.github.megatronking.netbare.NetBare
import com.github.megatronking.netbare.ssl.JKS

class App : Application() {

    companion object {
        const val JSK_ALIAS = "NetBareSample"

        private lateinit var sInstance: App

        fun getInstance(): App {
            return sInstance
        }
    }

    private lateinit var mJKS : JKS
    private var rootCertificatePath: String? = null
    private var privateKeyPath: String? = null

    override fun onCreate() {
        super.onCreate()
        sInstance = this

        // Create default JKS
        createJKS()

        // 初始化NetBare
        NetBare.get().attachApplication(this, BuildConfig.DEBUG)
    }

    fun setRootCertificatePath(path: String) {
        rootCertificatePath = path
    }

    fun setPrivateKeyPath(path: String) {
        privateKeyPath = path
    }

    fun getJKS(): JKS {
        return mJKS
    }

    fun createJKS() {
        mJKS = if (rootCertificatePath == null && privateKeyPath == null) {
            JKS(this, JSK_ALIAS, JSK_ALIAS.toCharArray(), JSK_ALIAS, JSK_ALIAS,
                    JSK_ALIAS, JSK_ALIAS, JSK_ALIAS)
        } else {
            JKS(this, JSK_ALIAS, JSK_ALIAS.toCharArray(), JSK_ALIAS, JSK_ALIAS,
                    JSK_ALIAS, JSK_ALIAS, JSK_ALIAS, rootCertificatePath, privateKeyPath)
        }
    }
}
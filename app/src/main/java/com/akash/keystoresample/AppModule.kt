package com.akash.keystoresample

import android.os.Build
import org.koin.android.ext.koin.androidApplication
import org.koin.dsl.module.module
import org.vumc.mycap.core.KeyStoreUtilsApi21
import org.vumc.mycap.core.KeyStoreUtilsApi23


val dataSourceModule = module {

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        single { KeyStoreUtilsApi23(androidApplication()) as KeyStoreUtils }
    } else {
        single { KeyStoreUtilsApi21(androidApplication()) as KeyStoreUtils }
    }

    single { AppRealm(androidApplication(), get<KeyStoreUtils>()) }

}

package com.akash.keystoresample

import android.app.Application
import io.realm.Realm
import io.realm.RealmConfiguration
import org.koin.android.ext.android.startKoin

class KeyStoreApplication : Application() {



    override fun onCreate() {
        super.onCreate()

        startKoin(this, listOf(dataSourceModule))
    }
}
package com.akash.keystoresample

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import io.realm.Realm
import org.koin.android.ext.android.get
import timber.log.Timber

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val appRealm: AppRealm = get()
        //just a check to see if encryption works
        val realm = Realm.getDefaultInstance()

        Timber.d("Realm $realm")
    }
}

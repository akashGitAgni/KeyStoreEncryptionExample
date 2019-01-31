package com.akash.keystoresample

import android.app.Application
import io.realm.Realm
import io.realm.RealmConfiguration


class AppRealm(context: Application, keyStoreUtils: KeyStoreUtils) {
    companion object {
        const val SCHEMA_VERSION = 10L
    }

    init {
        Realm.init(context)
        Realm.setDefaultConfiguration(
            RealmConfiguration.Builder()
                .encryptionKey(keyStoreUtils.getOrCreateEncryptionKey())
                .name("core_module.realm")
                .schemaVersion(SCHEMA_VERSION)
                .deleteRealmIfMigrationNeeded()
                .initialData {
                    loadInitialData(it)
                }
                .build()!!
        )
    }


    private fun loadInitialData(realm: Realm) {
        var person = realm.createObject(Person::class.java)
        person.name = ("Makoto Yamazaki")
        person.age = 32

        person = realm.createObject(Person::class.java)
        person.name = ("Makoto Yamazaki")
        person.age = 32

        person = realm.createObject(Person::class.java)
        person.name = ("Makoto Yamazaki")
        person.age = 32

        person = realm.createObject(Person::class.java)
        person.name = ("Makoto Yamazaki")
        person.age = 32
    }
}
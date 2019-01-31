package com.akash.keystoresample

import io.realm.RealmObject
import io.realm.annotations.Index


open class Person : RealmObject() {
    @Index
    var name: String? = null

    var age: Int = 0
}
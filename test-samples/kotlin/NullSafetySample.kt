package com.example.vulnerable

class DataProcessor {

    // VULN: Excessive !! usage (3+ times)
    fun processUser(user: User?) {
        val name = user!!.name
        val email = user!!.email
        val age = user!!.age
        val address = user!!.address
        println("$name, $email, $age, $address")
    }

    // VULN: Single !! usage
    fun getName(user: User?): String {
        return user!!.name
    }

    // VULN: Unsafe cast
    fun convertData(obj: Any): String {
        val data = obj as String
        return data.uppercase()
    }

    // SAFE: Safe call and Elvis operator
    fun getNameSafe(user: User?): String {
        return user?.name ?: "Unknown"
    }

    // SAFE: Safe cast
    fun convertSafe(obj: Any): String? {
        val data = obj as? String
        return data?.uppercase()
    }
}

data class User(val name: String, val email: String, val age: Int, val address: String)

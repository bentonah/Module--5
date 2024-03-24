import java.security.*
import javax.crypto.*
import javax.crypto.spec.*

// Data class representing a user with username, hashed password, and credentials
data class User(val username: String, val hashedPassword: ByteArray, val credentials: MutableMap<String, ByteArray> = HashMap())

// Class managing user authentication, password encryption/decryption, and credential storage
class PasswordManager {
    private val users: MutableMap<String, User> = HashMap() // Map to store users
    private var isAuthenticated: Boolean = false // Flag to track user authentication status
    private val secretKey: SecretKey // Secret key for AES encryption/decryption

    // Initialization block to generate secret key for AES encryption/decryption
    init {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(128) // Using 128-bit key size
        secretKey = keyGenerator.generateKey()
    }

    // Function to add a new user
    fun addUser(username: String, password: String) {
        val hashedPassword = hashPassword(password) // Hash the user's password for secure storage
        val user = User(username, hashedPassword)
        users[username] = user // Store the user object in the users map
        println("User $username added successfully.")
    }

    // Function to authenticate a user
    fun authenticate(username: String, password: String): Boolean {
        val user = users[username] // Retrieve the user object
        if (user != null && MessageDigest.isEqual(user.hashedPassword, hashPassword(password))) {
            isAuthenticated = true // Set authentication flag to true if passwords match
            println("Authentication successful!")
            return true
        } else {
            isAuthenticated = false // Set authentication flag to false if passwords don't match
            println("Authentication failed. Invalid username or password.")
            return false
        }
    }

    // Function to add credentials for a website
    fun addCredentials(url: String, username: String, password: String) {
        if (isAuthenticated) {
            val domain = extractDomain(url)
            val encryptedPassword = encrypt(password) // Encrypt the password before storing
            users[username]?.let { it.credentials[domain] = encryptedPassword } // Store the encrypted password in the user's credentials map
            println("Credentials for $domain added successfully.")
        } else {
            println("Please authenticate first before adding credentials.")
        }
    }

    // Function to retrieve the decrypted password for a website
    fun getDecryptedPassword(username: String, url: String): String? {
        return if (isAuthenticated) {
            val domain = extractDomain(url)
            users[username]?.credentials?.get(domain)?.let { decrypt(it) } // Decrypt the password if it exists
        } else {
            println("Please authenticate first before retrieving passwords.")
            null
        }
    }

    // Function to encrypt a password using AES encryption
    private fun encrypt(password: String): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.doFinal(password.toByteArray())
    }

    // Function to decrypt an encrypted password using AES decryption
    private fun decrypt(encryptedPassword: ByteArray): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decryptedBytes = cipher.doFinal(encryptedPassword)
        return String(decryptedBytes)
    }

    // Function to hash a password using SHA-256
    private fun hashPassword(password: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(password.toByteArray())
    }

    // Function to extract domain from URL
    private fun extractDomain(url: String): String {
        val domainPattern = "(?<=://)[^/]+".toRegex()
        return domainPattern.find(url)?.value ?: ""
    }
}

fun main() {
    val passwordManager = PasswordManager()

    // Example usage:
    // Add a user
    passwordManager.addUser("user123", "password123")

    // Authenticate user
    passwordManager.authenticate("user123", "password123")

    // Add credentials
    passwordManager.addCredentials("https://example.com", "user123", "password123")
    passwordManager.addCredentials("https://example.net", "user123", "securePassword")

    // Retrieve and print decrypted password
    val decryptedPassword = passwordManager.getDecryptedPassword("user123", "https://example.com")
    decryptedPassword?.let { println("Decrypted password for example.com: $it") }

    // Example of handling non-existent website
    val nonExistentPassword = passwordManager.getDecryptedPassword("user123", "https://nonexistent.com")
    nonExistentPassword?.let { println("Decrypted password for nonexistent.com: $it") } ?: println("Website not found.")
}
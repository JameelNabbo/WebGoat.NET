// VulnerableApp.scala
// Intentionally vulnerable Scala code for SAST scanner testing

package com.example.vulnerable

import java.io._
import java.security.{MessageDigest, SecureRandom}
import java.sql.{Connection, DriverManager, ResultSet}
import javax.crypto.Cipher
import javax.script.ScriptEngineManager
import scala.util.Random
import scala.xml.XML
import scala.sys.process._

// ============ SQL Injection ============

object DatabaseService {
  val dbPassword = "SuperSecretDBPassword123!"
  val secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  val apiKey = "sk-live-abc123def456ghi789jkl012mno345"

  // JDBC SQL injection via string concatenation
  def findUser(conn: Connection, username: String): ResultSet = {
    val query = "SELECT * FROM users WHERE name = '" + username + "'"
    conn.createStatement().executeQuery(query)
  }

  // JDBC with interpolation
  def deleteUser(conn: Connection, userId: String): Int = {
    val stmt = conn.prepareStatement(s"DELETE FROM users WHERE id = $userId")
    stmt.executeUpdate(s"DELETE FROM users WHERE id = $userId")
  }

  // Slick #$ injection
  def searchSlick(tableName: String) = {
    // sql"SELECT * FROM #$tableName WHERE active = true"
    val q = sql"SELECT * FROM #$tableName"
    q
  }

  // Anorm injection
  def findAnorm(name: String) = {
    SQL(s"SELECT * FROM users WHERE name = '$name'")
  }

  // Spark SQL injection
  def sparkQuery(spark: Any, tableName: String) = {
    spark.sql(s"SELECT * FROM $tableName WHERE active = true")
  }
}

// ============ Command Injection ============

object CommandUtils {
  // scala.sys.process with string interpolation
  def runCommand(userInput: String): String = {
    val result = s"ls -la $userInput".!!
    result
  }

  // Process with dynamic input
  def executeProcess(cmd: String): Int = {
    Process(cmd).!
  }

  // String.! operator
  def quickExec(path: String): String = {
    s"cat $path".!!
  }

  // Runtime.exec
  def runtimeExec(command: String): Unit = {
    Runtime.getRuntime.exec(command)
  }
}

// ============ Code Injection ============

object CodeInjection {
  // Reflection with dynamic class name
  def loadClass(className: String): Any = {
    val clazz = Class.forName(className)
    clazz.getDeclaredMethod("execute").invoke(clazz.newInstance())
  }

  // ScriptEngine eval
  def evalScript(userCode: String): Any = {
    val engine = new ScriptEngineManager().getEngineByName("js")
    engine.eval(userCode)
  }
}

// ============ XSS ============

object WebController {
  // Play Html() with dynamic content
  def renderHtml(userInput: String) = {
    Html(s"<div>$userInput</div>")
  }

  // Raw HTML in template
  // @Html(userContent)
}

// ============ Path Traversal ============

object FileService {
  // Path traversal with user input
  def readFile(filename: String): String = {
    val file = new File(s"/data/uploads/$filename")
    scala.io.Source.fromFile(file).mkString
  }

  def readPath(path: String): String = {
    scala.io.Source.fromFile(path).mkString
  }
}

// ============ Insecure Deserialization ============

object DeserializationService {
  // Java ObjectInputStream
  def deserialize(data: Array[Byte]): Any = {
    val ois = new ObjectInputStream(new ByteArrayInputStream(data))
    ois.readObject()
  }

  // Kryo without registration
  def kryoDeserialize(data: Array[Byte]): Any = {
    val kryo = new Kryo()
    // Missing: kryo.setRegistrationRequired(true)
    kryo.readClassAndObject(new Input(data))
  }
}

// ============ XXE ============

object XmlService {
  // Unsafe XML parsing
  def parseXml(xmlString: String) = {
    val factory = javax.xml.parsers.SAXParserFactory.newInstance()
    // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    val parser = factory.newSAXParser()
    XML.loadString(xmlString)
  }

  def parseDocument(xmlInput: InputStream) = {
    val dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    // No safe configuration
    val builder = dbf.newDocumentBuilder()
    builder.parse(xmlInput)
  }
}

// ============ SSRF ============

object HttpService {
  // SSRF with user-controlled URL
  def fetchUrl(url: String) = {
    val ws = WS.url(url)
    ws.get()
  }

  def proxyRequest(target: String, endpoint: String) = {
    val fullUrl = s"$target/$endpoint"
    WS.url(fullUrl).get()
  }
}

// ============ Weak Cryptography ============

object CryptoService {
  // MD5 hashing
  def hashMd5(data: String): String = {
    val md = MessageDigest.getInstance("MD5")
    md.update(data.getBytes)
    md.digest().map("%02x".format(_)).mkString
  }

  // SHA-1 hashing
  def hashSha1(data: String): String = {
    val md = MessageDigest.getInstance("SHA1")
    md.update(data.getBytes)
    md.digest().map("%02x".format(_)).mkString
  }

  // DES encryption
  def encryptDes(data: Array[Byte], key: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
    cipher.doFinal(data)
  }

  // ECB mode
  def encryptEcb(data: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.doFinal(data)
  }
}

// ============ Insecure Random ============

object RandomService {
  // scala.util.Random (insecure)
  def generateToken(): String = {
    val rng = new Random()
    val bytes = new Array[Byte](32)
    rng.nextBytes(bytes)
    bytes.map("%02x".format(_)).mkString
  }

  def generateSessionId(): String = {
    Random.alphanumeric.take(32).mkString
  }
}

// ============ Play Framework Security ============

object PlayConfig {
  // CORS allow all
  val corsConfig = Map(
    "allowedOrigins" -> "*"
  )

  // CSRF disabled
  def unsafeAction = {
    nocheck {
      // Action body without CSRF
    }
  }

  // Session not secure
  val sessionConfig = Map(
    "play.http.session.secure" -> false
  )
}

// ============ Akka Security ============

object AkkaService {
  // Dynamic ActorSelection
  def getActor(path: String) = {
    val system = ActorSystem("mySystem")
    system.actorSelection(path)
  }

  // Akka remote config without TLS
  val config = """
    akka.remote {
      artery {
        canonical.hostname = "0.0.0.0"
        canonical.port = 2551
      }
    }
  """
}

// Mutable state in Actor
class UserActor extends Actor {
  var userCount = 0
  var sessionMap = Map.empty[String, String]

  def receive = {
    case msg: String =>
      userCount += 1
      println(s"Processing message for user, password=$msg")
  }
}

// ============ Pattern Matching ============

object MatchingService {
  sealed trait Status
  case object Active extends Status
  case object Inactive extends Status
  case object Suspended extends Status

  // Non-exhaustive match
  def handleStatus(status: Status): String = status match {
    case Active => "active"
    case Inactive => "inactive"
    // Missing: case Suspended
  }

  def processInput(input: Any): String = input match {
    case s: String => s.toUpperCase
    case i: Int => i.toString
    // No wildcard case
  }
}

// ============ Resource Leaks ============

object ResourceService {
  // FileInputStream not closed
  def readConfig(path: String): String = {
    val fis = new FileInputStream(path)
    val reader = new BufferedReader(new InputStreamReader(fis))
    reader.readLine()
  }

  // Connection not closed
  def queryDb(): ResultSet = {
    val conn = DriverManager.getConnection("jdbc:mysql://localhost/db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT 1")
  }

  // Source not closed
  def readLines(path: String): List[String] = {
    val source = scala.io.Source.fromFile(path)
    source.getLines().toList
  }
}

// ============ Implicit Conversion Security ============

object Conversions {
  // Dangerous implicit conversion from String to SQL
  implicit def stringToSql(s: String): SQL = SQL(s)

  // Implicit String to Html
  implicit def stringToHtml(s: String): Html = Html(s)
}

// ============ Unsafe Type Casting ============

object TypeService {
  def processData(data: Any): String = {
    val result = data.asInstanceOf[Map[String, Any]]
    result("key").asInstanceOf[String]
  }

  def castList(items: Any): List[Int] = {
    items.asInstanceOf[List[Int]]
  }
}

// ============ Information Disclosure ============

object LoggingService {
  def logAuth(username: String, password: String): Unit = {
    println(s"Auth attempt: user=$username, password=$password")
  }

  def logSecret(token: String): Unit = {
    printf("Token: %s\n", token)
  }

  // Stack trace in response
  def handleError(e: Exception) = {
    val stackTrace = e.getStackTrace.mkString("\n")
    InternalServerError(Json.obj("error" -> e.getMessage, "stack" -> stackTrace))
  }
}

// ============ Spark-Specific ============

object SparkService {
  def queryData(spark: Any, tableName: String) = {
    spark.sql("SELECT * FROM " + tableName + " WHERE active = true")
  }
}

// ============ Hardcoded Secrets (more) ============

object Config {
  val masterKey = "mk-1234567890abcdef"
  val authToken = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
  val encryptionKey = "0123456789abcdef0123456789abcdef"
  val clientSecret = "cs_live_abc123def456"
  val dbPassword = "postgres_secure_pass_2026"
}

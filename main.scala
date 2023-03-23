package sigtesting

def main(args: Array[String]): Unit = {
  val signed = signWithMastercard()
  verifyWithMastercard(signed)
}

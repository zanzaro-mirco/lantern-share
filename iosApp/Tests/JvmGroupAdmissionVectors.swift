import Foundation

/// Public, fixed JVM fixtures: Kotlin 2.1.21 codec/canonical bytes, JDK 17 ECDSA and
/// Bouncy Castle 1.83 X.509. Generated 2026-10-11; disposable private keys were not retained.
/// Self-signed certificates are valid 2026-01-01...2036-01-01. Tests use a fixed date.
/// No app identity, TLS credentials or trust are created from these vectors.
enum JvmGroupAdmissionVectors {
    static let verificationDate = Date(timeIntervalSince1970: 1_791_676_800) // 2026-10-11 UTC

    struct Vector {
        let founder: String
        let der: String
        let signature: String
        let canonicalBytes: String
    }

    static let p256 = Vector(
        founder: "96b9d5bb94fad13e0d9ab4df84af9b022237a011db15f27500b4b0328630136e",
        der: "MIIBRzCB76ADAgECAgEBMAoGCCqGSM49BAMCMC4xLDAqBgNVBAMMI0xhbnRlcm4gcHVibGljIEpWTSB0ZXN0IHZlY3RvciBwMjU2MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowLjEsMCoGA1UEAwwjTGFudGVybiBwdWJsaWMgSlZNIHRlc3QgdmVjdG9yIHAyNTYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQvK72lGXKW9poWhlH7BPxBGvUlSrioJvZs55rz9Aq2cRhT2aepGuCAoGq1pURYZsmDUyLlwd7A6VE6Z+pP3pXGMAoGCCqGSM49BAMCA0cAMEQCIAzPlvwV9o2jUaSbCeO0pytfFn7yA4FcQTqa9pdfjuv3AiAy7lsFdKeOyo52aS642eLSaRdfK6DmTQmLZHD0ujqBOg==",
        signature: "MEUCIQC7bb2DOJBG0+SQmxqCulQzvKoGOSazorbc/6bcbf0m5wIgWajAtv5MCW6CcI7q850SCcxT/v6oAtXu0nBwrxs4hU4=",
        canonicalBytes: "MjU6bGFudGVybi1ncm91cC1hZG1pc3Npb24tMTE6MTY0OmNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M2NDo5NmI5ZDViYjk0ZmFkMTNlMGQ5YWI0ZGY4NGFmOWIwMjIyMzdhMDExZGIxNWYyNzUwMGI0YjAzMjg2MzAxMzZlNjQ6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg=="
    )

    static let p384 = Vector(
        founder: "9ef503c0352a465acbd85e7984a675e6d3667175e51ff5f1ca3314e8d8cc2765",
        der: "MIIBhzCCAQygAwIBAgIBATAKBggqhkjOPQQDAjAuMSwwKgYDVQQDDCNMYW50ZXJuIHB1YmxpYyBKVk0gdGVzdCB2ZWN0b3IgcDM4NDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMC4xLDAqBgNVBAMMI0xhbnRlcm4gcHVibGljIEpWTSB0ZXN0IHZlY3RvciBwMzg0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE82pvCxYJ01gpqwmkAZj2qGM6CxLyz406T2HsaoJBExla8YhhftkMR+UH/i74b+BS4cVfX2z+UNkxlF2+ehlJVWj9BzsHBuQ9wGq4mZFCncwt1EVbT00IYb0NMSh0zxMgMAoGCCqGSM49BAMCA2kAMGYCMQD0vGQ/OiXKjBG6UVC6XlXs6H5P7qvh+68vKGXc6DNbG7bP200Uv4v2abNzfYIo6nQCMQC6buYPJbG5YMXXV6nfimuYOk3l+wy9dhuBPKYj/XtjM2IgV9f1/QC5Yy+B4DVt7pQ=",
        signature: "MGUCMQDPbOqsN3e3icIkfePkvn+XWHHQr0brCI/5tFiwNiUu6B1MBWJed5jNgItRRBL5n3wCMHHXhb+HzQTO+zxW3nkAoY83uo6ddjsWMOx4EQtHaS1pMJ4rAFe9PTqxgza62BkT+Q==",
        canonicalBytes: "MjU6bGFudGVybi1ncm91cC1hZG1pc3Npb24tMTE6MTY0OmNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M2NDo5ZWY1MDNjMDM1MmE0NjVhY2JkODVlNzk4NGE2NzVlNmQzNjY3MTc1ZTUxZmY1ZjFjYTMzMTRlOGQ4Y2MyNzY1NjQ6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg=="
    )

    static let sha384 = Vector(
        founder: "c1890683101c48fe2e978300380ca911734541ceca3ee98131f83a247ce81ec3",
        der: "MIIBSzCB86ADAgECAgEBMAoGCCqGSM49BAMDMDAxLjAsBgNVBAMMJUxhbnRlcm4gcHVibGljIEpWTSB0ZXN0IHZlY3RvciBzaGEzODQwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAwMS4wLAYDVQQDDCVMYW50ZXJuIHB1YmxpYyBKVk0gdGVzdCB2ZWN0b3Igc2hhMzg0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEidsikBnaEZE4nEgD5WKirdga4OwjKOQxQa9z7EfNFWRabLfBJJGwYD5wd+PV0JlbNKpcuFMgEf6XDUR6g3rBRjAKBggqhkjOPQQDAwNHADBEAiBBaNKgm5VYnfSigYQ6fSjfEgGhWuLAVJX0o8QUz5W8vAIgcGyCEdxTdomp++AExeLH3I4vLH6GJKxdycChYwjxWIo=",
        signature: "MEYCIQDus6pAJ2SkuqU0mOk8OVpWn6Lo86d9g+nHInp7/BAbnQIhALCQIgrHPRaFAFiasDJEifdiaftepSzGVUgNDeanBzy5",
        canonicalBytes: "MjU6bGFudGVybi1ncm91cC1hZG1pc3Npb24tMTE6MTY0OmNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M2NDpjMTg5MDY4MzEwMWM0OGZlMmU5NzgzMDAzODBjYTkxMTczNDU0MWNlY2EzZWU5ODEzMWY4M2EyNDdjZTgxZWMzNjQ6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg=="
    )
}

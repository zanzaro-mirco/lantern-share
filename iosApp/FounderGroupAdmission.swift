import Foundation
import Security
import LanternIdentity
import LanternUI

/// A future explicit admission request uses this on its owning queue, off the UI thread.
/// It must recheck connection liveness/cancellation before sending. No active service caller,
/// trust write, implicit remote root adoption or durable admission is introduced here.
enum FounderGroupAdmission {
    static func prepare(
        identity: AppleIdentity,
        persistence: IosPersistence,
        memberID: String
    ) throws -> IosGroupAdmissionEvidence {
        var signingFailure: Error?
        do {
            return try IosFounderGroupAdmission.shared.prepare(
                persistence: persistence, identityId: identity.id, memberId: memberID,
                certificateDer: (SecCertificateCopyData(identity.certificate) as Data).base64EncodedString(),
                sign: { bytes in
                    do { return try identity.sign(Self.data(bytes)) }
                    catch { signingFailure = error; return nil }
                },
                verifySignature: { bytes, signature in
                    KotlinBoolean(bool: ApplePublicCertificate.verifySignature(
                        certificate: identity.certificate, expectedID: identity.id,
                        message: Self.data(bytes), signature: signature
                    ))
                }
            )
        } catch {
            throw signingFailure ?? error
        }
    }

    private static func data(_ bytes: KotlinByteArray) -> Data {
        Data((0..<Int(bytes.size)).map { UInt8(bitPattern: bytes.get(index: Int32($0))) })
    }
}

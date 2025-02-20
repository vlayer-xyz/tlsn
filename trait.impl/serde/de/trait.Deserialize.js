(function() {
    var implementors = Object.fromEntries([["tlsn_core",[["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"tlsn_core/attestation/enum.FieldKind.html\" title=\"enum tlsn_core::attestation::FieldKind\">FieldKind</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"tlsn_core/connection/enum.HandshakeData.html\" title=\"enum tlsn_core::connection::HandshakeData\">HandshakeData</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"tlsn_core/connection/enum.KeyType.html\" title=\"enum tlsn_core::connection::KeyType\">KeyType</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"tlsn_core/connection/enum.SignatureScheme.html\" title=\"enum tlsn_core::connection::SignatureScheme\">SignatureScheme</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"tlsn_core/connection/enum.TlsVersion.html\" title=\"enum tlsn_core::connection::TlsVersion\">TlsVersion</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"tlsn_core/transcript/enum.Direction.html\" title=\"enum tlsn_core::transcript::Direction\">Direction</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"tlsn_core/transcript/enum.TranscriptCommitmentKind.html\" title=\"enum tlsn_core::transcript::TranscriptCommitmentKind\">TranscriptCommitmentKind</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.Attestation.html\" title=\"struct tlsn_core::attestation::Attestation\">Attestation</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.AttestationProof.html\" title=\"struct tlsn_core::attestation::AttestationProof\">AttestationProof</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.Body.html\" title=\"struct tlsn_core::attestation::Body\">Body</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.FieldId.html\" title=\"struct tlsn_core::attestation::FieldId\">FieldId</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.Header.html\" title=\"struct tlsn_core::attestation::Header\">Header</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.Uid.html\" title=\"struct tlsn_core::attestation::Uid\">Uid</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.Version.html\" title=\"struct tlsn_core::attestation::Version\">Version</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.Certificate.html\" title=\"struct tlsn_core::connection::Certificate\">Certificate</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ConnectionInfo.html\" title=\"struct tlsn_core::connection::ConnectionInfo\">ConnectionInfo</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.HandshakeDataV1_2.html\" title=\"struct tlsn_core::connection::HandshakeDataV1_2\">HandshakeDataV1_2</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ServerCertCommitment.html\" title=\"struct tlsn_core::connection::ServerCertCommitment\">ServerCertCommitment</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ServerCertData.html\" title=\"struct tlsn_core::connection::ServerCertData\">ServerCertData</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ServerCertOpening.html\" title=\"struct tlsn_core::connection::ServerCertOpening\">ServerCertOpening</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ServerEphemKey.html\" title=\"struct tlsn_core::connection::ServerEphemKey\">ServerEphemKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ServerIdentityProof.html\" title=\"struct tlsn_core::connection::ServerIdentityProof\">ServerIdentityProof</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ServerName.html\" title=\"struct tlsn_core::connection::ServerName\">ServerName</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.ServerSignature.html\" title=\"struct tlsn_core::connection::ServerSignature\">ServerSignature</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/connection/struct.TranscriptLength.html\" title=\"struct tlsn_core::connection::TranscriptLength\">TranscriptLength</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/hash/struct.Hash.html\" title=\"struct tlsn_core::hash::Hash\">Hash</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/hash/struct.HashAlgId.html\" title=\"struct tlsn_core::hash::HashAlgId\">HashAlgId</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/hash/struct.TypedHash.html\" title=\"struct tlsn_core::hash::TypedHash\">TypedHash</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/presentation/struct.Presentation.html\" title=\"struct tlsn_core::presentation::Presentation\">Presentation</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/request/struct.Request.html\" title=\"struct tlsn_core::request::Request\">Request</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/signing/struct.KeyAlgId.html\" title=\"struct tlsn_core::signing::KeyAlgId\">KeyAlgId</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/signing/struct.Signature.html\" title=\"struct tlsn_core::signing::Signature\">Signature</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/signing/struct.SignatureAlgId.html\" title=\"struct tlsn_core::signing::SignatureAlgId\">SignatureAlgId</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/signing/struct.VerifyingKey.html\" title=\"struct tlsn_core::signing::VerifyingKey\">VerifyingKey</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/struct.Secrets.html\" title=\"struct tlsn_core::Secrets\">Secrets</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/transcript/struct.CompressedPartialTranscript.html\" title=\"struct tlsn_core::transcript::CompressedPartialTranscript\">CompressedPartialTranscript</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/transcript/struct.Idx.html\" title=\"struct tlsn_core::transcript::Idx\">Idx</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/transcript/struct.PartialTranscript.html\" title=\"struct tlsn_core::transcript::PartialTranscript\">PartialTranscript</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/transcript/struct.Subsequence.html\" title=\"struct tlsn_core::transcript::Subsequence\">Subsequence</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/transcript/struct.Transcript.html\" title=\"struct tlsn_core::transcript::Transcript\">Transcript</a>"],["impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/transcript/struct.TranscriptProof.html\" title=\"struct tlsn_core::transcript::TranscriptProof\">TranscriptProof</a>"],["impl&lt;'de, T&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"tlsn_core/attestation/struct.Field.html\" title=\"struct tlsn_core::attestation::Field\">Field</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.218/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,</div>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[13714]}
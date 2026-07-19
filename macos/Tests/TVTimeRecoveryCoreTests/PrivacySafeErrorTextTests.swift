import Foundation
import Testing

@testable import TVTimeRecoveryCore

@Suite("Privacy-safe local errors")
struct PrivacySafeErrorTextTests {
  private struct SyntheticError: LocalizedError {
    let errorDescription: String?
  }

  @Test("Allows fixed guidance and suppresses private or deceptive text")
  func screensMessages() {
    let safe = "The selected item is not a safe regular directory."
    expectEqual(PrivacySafeErrorText.message(for: SyntheticError(errorDescription: safe)), safe)

    for unsafe in [
      "Could not read /Users/private/backup",
      "Credential token was rejected",
      "Contact private@example.test",
      "Hidden\u{202E}path",
      "file: local-output",
    ] {
      expectEqual(
        PrivacySafeErrorText.message(for: SyntheticError(errorDescription: unsafe)),
        "The operation could not be completed safely."
      )
    }
  }

  @Test("Suppresses non-localized and oversized errors")
  func suppressesUnknownErrors() {
    struct UnknownError: Error {}
    expectEqual(
      PrivacySafeErrorText.message(for: UnknownError()),
      "The operation could not be completed safely."
    )
    expectEqual(
      PrivacySafeErrorText.message(
        for: SyntheticError(errorDescription: String(repeating: "x", count: 501))
      ),
      "The operation could not be completed safely."
    )
  }
}
